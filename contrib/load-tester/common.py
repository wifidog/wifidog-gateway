# -*- coding: utf-8 -*-

import socket
import fcntl
import struct

import argparse

# http://stackoverflow.com/questions/159137/getting-mac-address
def get_mac_address(ifname):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    info = fcntl.ioctl(s.fileno(), 0x8927,  struct.pack('256s', ifname[:15]))
    return ':'.join(['%02x' % ord(char) for char in info[18:24]])

# http://code.activestate.com/recipes/439094-get-the-ip-address-associated-with-a-network-inter/
def get_ip_address(ifname):
    print "ifname: %s" % ifname
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    return socket.inet_ntoa(fcntl.ioctl(
        s.fileno(),
        0x8915,  # SIOCGIFADDR
        struct.pack('256s', ifname[:15])
        )[20:24])

def get_argparser():
    parser = argparse.ArgumentParser(description='Hammer a wifidog'
                                     + ' instance with requests')
    parser.add_argument(
        '--target-interface',
        required=True,
        help='Interface where Wifidog is listening')
    parser.add_argument(
        '--source-interface-prefix',
        required=True,
        help='Prefix of the virtual interfaces from which Wifidog' +
        ' is exercised.')
    parser.add_argument(
        '--source-interface-count',
        required=True,
        help='Number of virtual interfaces, where interface is prefix+index')
    parser.add_argument(
        '--process-count',
        required=True,
        help='How many processes to run')
    return parser
