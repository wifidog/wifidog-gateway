#!/bin/sh
######################################################################################################
#
# Description: get the rate of clients,run in openwrt open router.
# Author:      GaomingPan
# Version:     v1.0.0
# Lisence:     GPL
# Date:        2015-09-08
#
######################################################################################################

UP_SPEED=/tmp/client.up.speed      
DOWN_SPEED=/tmp/client.down.speed  
MAC_IP=/tmp/mac-ip.client
I_FACE=$(uci get wifidog_conf.single.gatewayInterface | awk '{print $2}')
CHECK_INTERVAL=$(uci get wifidog_conf.single.checkInterval | awk '{print $2}')

while [ true ]
  do
    cat /proc/net/arp | grep : | grep $I_FACE | grep -v 00:00:00:00:00:00| awk '{print $1}' > $MAC_IP  
    iptables -N UPLOAD  
    iptables -N DOWNLOAD  
    while read line;do iptables -I FORWARD 1 -s $line -j UPLOAD;done < $MAC_IP     
    while read line;do iptables -I FORWARD 1 -d $line -j DOWNLOAD;done < $MAC_IP   
    sleep 1  
    iptables -nvx -L FORWARD | grep DOWNLOAD | awk '{print $9,$2}' | sort -n -r > $DOWN_SPEED   
    iptables -nvx -L FORWARD | grep UPLOAD | awk '{print $8,$2}' | sort -n -r > $UP_SPEED   
    while read line;do iptables -D FORWARD -s $line -j UPLOAD;done < $MAC_IP     
    while read line;do iptables -D FORWARD -d $line -j DOWNLOAD;done < $MAC_IP   
    iptables -X UPLOAD   
    iptables -X DOWNLOAD
    sleep  $(($CHECK_INTERVAL - 2))
   done
 
