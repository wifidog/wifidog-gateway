/*
 * shell_command.h
 *
 *  Created on: Jul 9, 2015
 *      Author: GaomingPan
 */

#ifndef SRC_SHELL_COMMAND_H_
#define SRC_SHELL_COMMAND_H_

/* @breif get ap wireless ssid shell, depends on uci command.
 * */
#define CMD_GET_WIRELESS_SSID    "uci get wireless.@wifi-iface[0].ssid"
#define CMD_GET_WAN_IP           "uci -P/var/state get network.wan.ipaddr"
#define CMD_GET_CPU_USE          "top -n 1 | grep id"
#define CMD_GET_AP_MAC           "uci get network.lan.macaddr"
#define CMD_GET_WAN_IFNAME       "uci get network.wan.ifname"

//#define CMD_GET_CLIENT_LIST      "cat /var/dhcp.leases | awk \'{print $2,$3,$4}\'"
#define CMD_GET_CLIENT_LIST      "cat $(uci get dhcp.@dnsmasq[0].leasefile) | awk \'{print $2,$3,$4}\'"

/************
#define CMD_MAKE_SPEED_FILE      "UP_SPEED=\"/tmp/client.up.speed\"\n"      \
                                 "DOWN_SPEED=\"/tmp/client.down.speed\"\n"  \
                                 "MAC_IP=\"/tmp/mac-ip.client\"\n"          \
                                 "LAN_IPS=`uci get network.lan.ipaddr | awk -F '.' '{print $1}'` \n" \
                                 "cat /proc/net/arp | grep : | grep ^$LAN_IPS | grep -v 00:00:00:00:00:00| awk '{print $1}' > $MAC_IP \n" \
                                 "iptables -N UPLOAD \n" \
                                 "iptables -N DOWNLOAD \n" \
                                 "while read line;do iptables -I FORWARD 1 -s $line -j UPLOAD;done < $MAC_IP \n"    \
                                 "while read line;do iptables -I FORWARD 1 -d $line -j DOWNLOAD;done < $MAC_IP \n"  \
                                 "sleep 1 \n" \
                                 "iptables -nvx -L FORWARD | grep DOWNLOAD | awk '{print $9,$2}' | sort -n -r > $DOWN_SPEED \n"  \
                                 "iptables -nvx -L FORWARD | grep UPLOAD | awk '{print $8,$2}' | sort -n -r > $UP_SPEED \n"  \
                                 "while read line;do iptables -D FORWARD -s $line -j UPLOAD;done < $MAC_IP \n"    \
                                 "while read line;do iptables -D FORWARD -d $line -j DOWNLOAD;done < $MAC_IP \n"  \
                                 "iptables -X UPLOAD \n"  \
                                 "iptables -X DOWNLOAD \n"

/**
#define CMD_GET_CHAIN_NUM       "TARGET=/tmp/client.up.speed\n" \
                                "awk \'$1{++b[$1]}{c[NR]=$0;d[NR]=$1} END { for (i=1;i<=NR;i++) print b[d[i]]}\' $TARGET " \
                                "> /tmp/client.speed.chain.num"
**

#define CMD_GET_CHAIN_NUM       "TARGET_A=/tmp/client.up.speed\n" \
                                "TARGET_B=/tmp/client.down.speed\n" \
								"awk \'$1{++b[$1]}{c[NR]=$0;d[NR]=$1} END { for (i=1;i<=NR;i++) print b[d[i]]}\' $TARGET_A " \
                                "> /tmp/client.speed.chain.num\n" \
								"awk \'$1{++b[$1]}{c[NR]=$0;d[NR]=$1} END { for (i=1;i<=NR;i++) print b[d[i]]}\' $TARGET_B " \
								">> /tmp/client.speed.chain.num"


#define CMD_CLEAN_SPEED_CHAIN     "MAC_IP=\"/tmp/mac-ip.client\"\n" \
                                  "while read line;do iptables -D FORWARD -s $line -j UPLOAD;done < $MAC_IP \n" \
                                  "while read line;do iptables -D FORWARD -d $line -j DOWNLOAD;done < $MAC_IP \n" \
                                  "iptables -X UPLOAD \n " \
                                  "iptables -X DOWNLOAD "

******************/

#endif /* SRC_SHELL_COMMAND_H_ */
