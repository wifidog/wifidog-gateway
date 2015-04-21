#!/usr/bin/env python2
# -*- coding: utf -*-


import uuid
import random

import functools

from multiprocessing import Pool

from httplib import HTTPConnection
from httplib import BadStatusLine

import common


PORT = "2060"


def main(targetIF, prefix, maxI):
    target = common.get_ip_address(targetIF)
    for i in xrange(int(maxI)):
        main_single(target, prefix, i)


def main_single(target, prefix, i):
    source = common.get_ip_address(prefix + str(i))
    # source_address requires python 2.7
    # urllib2 does not nicely expose source_address, so use
    # lower-level API
    conn = HTTPConnection(target, PORT, timeout=10,
                          source_address=(source, 0))
    conn.connect()
    conn.request("GET", "/")
    try:
        resp = conn.getresponse()
        resp.read()
        conn.close()
    except BadStatusLine as e:
        print "Got BadStatusLine for /: %s" % e
    conn = HTTPConnection(target, PORT, timeout=10,
                          source_address=(source, 0))
    conn.connect()
    token = str(uuid.uuid4())
    conn.request("GET", "/wifidog/auth?token=" + token)
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
        conn = HTTPConnection(target, PORT, timeout=10,
                              source_address=(source, 0))
        conn.connect()
        conn.request("GET", "/wifidog/auth?logout=1&token=" + token)
        try:
            resp = conn.getresponse()
            resp.read()
            conn.close()
        except BadStatusLine as e:
            print "Got BadStatusLine for logout: %s" % e


if __name__ == "__main__":

    parser = common.get_argparser()
    args = parser.parse_args()

    target = common.get_ip_address(args.target_interface)
    p = Pool(int(args.process_count))
    partial = functools.partial(
        main_single,
        target,
        args.source_interface_prefix)
    while True:
        p.map(partial, list(xrange(int(args.source_interface_count))))
