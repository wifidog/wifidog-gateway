#!/usr/bin/env python2
# -*- coding: utf -*-


import socket
import fcntl
import struct

import uuid
import sys
import random

import argparse
import functools


from multiprocessing import Pool

from httplib import HTTPConnection
from httplib import BadStatusLine

PORT = "2060"


def main(targetIF, prefix, maxI):
    target = get_ip_address(targetIF)
    for i in xrange(int(maxI)):
        main_single(target, prefix, i)

def main_single(target, prefix, i):
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
            conn.close()
        except BadStatusLine as e:
            print "Got BadStatusLine for /: %s" % e
        conn = HTTPConnection(target, PORT, timeout=10, source_address=(source, 0))
        conn.connect()
        token = str(uuid.uuid4())
        conn.request("GET", "/wifidog/auth?token=" + token )
        try:
            resp = conn.getresponse()
            # this causes wifidog to ask our mock auth server if the token is
            # correct
            resp.read()
            conn.close()
        except BadStatusLine as e:
            print "Got BadStatusLine for login: %s" % e
        # log out sometimes
        if random.choice([True, False, False]):
            conn = HTTPConnection(target, PORT, timeout=10, source_address=(source, 0))
            conn.connect()
            conn.request("GET", "/wifidog/auth?logout=1&token=" + token)
            try:
                resp = conn.getresponse()
                resp.read()
                conn.close()
            except BadStatusLine as e:
                print "Got BadStatusLine for logout: %s" % e


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

    parser = argparse.ArgumentParser(description='Hammer a wifidog instance with requests')
    parser.add_argument('--target-interface', required=True,
                   help='Interface where Wifidog is listening')
    parser.add_argument('--source-interface-prefix', required=True,
                   help='Prefix of the virtual interfaces from which Wifidog is exercised.')
    parser.add_argument('--source-interface-count', required=True,
                   help='Number of virtual interfaces, where interface is prefix+index')
    parser.add_argument('--process-count', required=True,
                   help='How many processes to run')

    args = parser.parse_args()

    target = get_ip_address(args.target_interface)
    p = Pool(int(args.process_count))
    partial = functools.partial(main_single, target, args.source_interface_prefix)
    while True:
        p.map(partial, list(xrange(int(args.source_interface_count))))

