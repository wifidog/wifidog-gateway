#!/usr/bin/env python2
# -*- coding: utf -*-


import functools
from multiprocessing import Pool
import subprocess
import random


import common


def main_single(target, prefix, i):
    """
    Either calls 'wdctl status' or
    logs out the client specified by the interface prefix + i.
    """
    binary = "../../src/wdctl"
    ip = common.get_ip_address(prefix + str(i))
    mac = common.get_mac_address(prefix + str(i))
    args = [["status"], ["reset", ip], ["reset", mac]]
    call = [binary]
    call.extend(random.choice(args))
    ret = subprocess.call(call)
    print "fire_wdctl.py: Return code %s" % ret


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
