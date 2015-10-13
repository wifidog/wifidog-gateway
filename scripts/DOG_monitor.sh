#!/bin/sh
###########################################################
##
## Description: this scripts generate the interface traffic
##		count file and clients rate file for the 
##		wifidog daemon,and monitor the wifidog daemon,
##		if the wifidog was down,it will be start again.
##		This scripts based on UCI and iptables,run on
##		OpenWrt routers. 
## Author: GaomingPan
## Lisence: GPL
## Date: 2015-09-12
## Version: v1.2.1
##
############################################################

############################################################
##
## Function: iface_data_file_generator
## Description: generate the file that contains: interface
##		name,Receive bytes,Transmit bytes,Rx rate in
##		a second and Tx rate in a second.
## FileContentsFormat:
##         ifacename   RxBytes   TxBytes  dRx   dTx
##
############################################################
IFACE_DATA=/tmp/.iface-data
T_IFACE_DATA=/tmp/.t_iface-data
DEV_FILE=/proc/net/dev
TMP=/tmp/.ftmp
TMP_D=/tmp/.ftmpd

iface_data_file_generator()
{
  echo > $IFACE_DATA
  echo > $T_IFACE_DATA
  echo > $TMP 
  echo > $TMP_D 
  cat $DEV_FILE | sed 1d | sed 1d  > $TMP
  while read line
  do
    echo $line | awk '{print $1,$2,$10}' >> $T_IFACE_DATA
  done < $TMP
  sleep 1
  cat $DEV_FILE | sed 1d | sed 1d  > $TMP
  while read line
  do
    echo $line | awk '{print $1,$2,$10}' >> $IFACE_DATA
  done < $TMP
  sed '/^$/d' $T_IFACE_DATA > $TMP
  cat $TMP > $T_IFACE_DATA
  sed '/^$/d' $IFACE_DATA > $TMP
  cat $TMP >  $IFACE_DATA
  echo > $TMP
  i=$(awk 'END{print NR}' $IFACE_DATA)
  while [ $i -gt 0 ]
  do
     read line < $IFACE_DATA
     rx1=$(echo $line | awk '{print $2}')
     tx1=$(echo $line | awk '{print $3}')
     read line < $T_IFACE_DATA
     rx2=$(echo $line | awk '{print $2}')
     tx2=$(echo $line | awk '{print $3}')
     cat $IFACE_DATA|sed 1d > $TMP
     cat $TMP > $IFACE_DATA 
     cat $T_IFACE_DATA|sed 1d > $TMP
     cat $TMP > $T_IFACE_DATA
     drx=$(($rx1 - $rx2))
     dtx=$(($tx1 - $tx2))
     echo "$line $drx $dtx" >> $TMP_D
     i=$(($i - 1))
  done
  cat $TMP_D > $IFACE_DATA

}

##########################################################
##
## Function: clients_RxTxRate_generator
## Description: this function generator the client rate file.
##
###########################################################
UP_SPEED=/tmp/.client.up.speed      
DOWN_SPEED=/tmp/.client.down.speed  
MAC_IP=/tmp/.mac-ip.client
I_FACE=$(uci get wifidog_conf.single.gatewayInterface | awk '{print $2}')
CHECK_INTERVAL=$(uci get wifidog_conf.single.checkInterval | awk '{print $2}')

clients_RxTxRate_generator()
{
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
}

##################################################
##
## Function: dog_daemon_monitor
## Description: monitor the wifidog daemon,if it
##              was down,then start it.
##
#################################################
PID_NAME=wifidog
PS_FILE=/tmp/ps-info
dog_daemon_monitor()
{
   ps > $PS_FILE
   pid=$(cat $PS_FILE | grep $PID_NAME | awk '{print $1}')
  
   if [ -n "$pid" ]
     then
       return 1
   fi
  
   /usr/bin/wifidog-init stop > /dev/null
   sleep 2
   /usr/bin/wifidog-init start > /dev/null

   return 0
}


##################################################
##
## Function: hostname_file_generator
## Description: this function generate and refresh 
##		the hostname  file for wifidog.
##
##################################################
HOST_NAME_FILE=/tmp/.hostname.txt

hostname_file_generator()
{
   cat $(uci get dhcp.@dnsmasq[0].leasefile) | awk '{print $2,$3,$4}' > $HOST_NAME_FILE
}

##################################################
##
## Function: iface_conn_file_generator
## Description: this function generate and refresh 
##		the interface connection file for wifidog.
##
##################################################
IFACE_CONN_FILE=/tmp/.iface_conn
IFACE_LIST=/tmp/.iface_list.txt

iface_conn_file_generator()
{
  rm -f $IFACE_CONN_FILE
  cat /proc/net/arp | awk '{print $6}' | awk '!a[$1]++' | sed 1d > $IFACE_LIST
  while read line
    do
      echo "$line $(cat /proc/net/arp | grep -e "0x2" | grep -e $line | awk 'END{print NR}')" >> $IFACE_CONN_FILE
    done < $IFACE_LIST
}


##################################################
##
## Function: cpu_use_info_file_generator
## Description: this function generate and refresh 
##		the cpu use information file for wifidog.
##
##################################################
CPU_USE_INFO_FILE=/tmp/.cpu_use_info

cpu_use_info_file_generator()
{
    echo "$(top -n 1 | grep id | awk 'NR==2{print}')" > $CPU_USE_INFO_FILE
}


##################################################
##
## Function: wan_ipaddr_file_generator
## Description: this function generate and refresh 
##		the WAN ip address information file for wifidog.
##
##################################################
WAN_IPADDR_FILE=/tmp/.wan_ipaddr.txt

wan_ipaddr_file_generator()
{
    echo "$(ifconfig | grep $(uci get network.wan.ifname) -A 2 | grep addr | sed 1d | awk '{print $2}' | awk -F ":" '{print $2}')" > $WAN_IPADDR_FILE
}

##################################################
##
## Function: man_loop
## Description: this is the mian function,do above
##              things to refresh data.
##
#################################################
main_loop()
{
    sleep_time=$(($CHECK_INTERVAL - 4))
    
    while [ true ]
      do
#         iface_data_file_generator
#         clients_RxTxRate_generator
#         hostname_file_generator
#         iface_conn_file_generator
#         cpu_use_info_file_generator
#         wan_ipaddr_file_generator
         dog_daemon_monitor
         sleep  $sleep_time
      done
 }

#############################
##
## now,do the loop
##
#############################
main_loop

