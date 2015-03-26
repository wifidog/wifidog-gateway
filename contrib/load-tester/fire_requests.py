#!/usr/bin/env python2
# -*- coding: utf -*-


import socket
import fcntl
import struct

import uuid
import sys

from httplib import HTTPConnection

PORT = "2060"

def main(targetIF, prefix, maxI):
    target = get_ip_address(targetIF)
    for i in xrange(int(maxI)):
        source = get_ip_address(prefix + str(i))
        # source_address requires python 2.7
        # urllib2 does not nicely expose source_address, so use
        # lower-level API
        conn = HTTPConnection(target, PORT, timeout=10, source_address=(source, 0))
        conn.connect()
        conn.request("GET", "/")
        try:
            resp = conn.getresponse()
            resp.read()
        except:
            pass
        conn = HTTPConnection(target, PORT, timeout=10, source_address=(source, 0))
        conn.connect()
        conn.request("GET", "/wifidog/auth?token=" + str(uuid.uuid4()))
        try:
            resp = conn.getresponse()
            # this causes wifidog to ask our mock auth server if the token is
            # correct
            resp.read()
        except:
            pass


# http://code.activestate.com/recipes/439094-get-the-ip-address-associated-with-a-network-inter/
def get_ip_address(ifname):
    print "ifname: %s" % ifname
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    return socket.inet_ntoa(fcntl.ioctl(
        s.fileno(),
        0x8915,  # SIOCGIFADDR
        struct.pack('256s', ifname[:15])
        )[20:24])

if __name__ == "__main__":
    while True:
        main(sys.argv[1], sys.argv[2], sys.argv[3])
