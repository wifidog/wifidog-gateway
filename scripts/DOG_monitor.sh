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
## Version: v1.2.0
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
IFACE_DATA=/tmp/iface-data
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
UP_SPEED=/tmp/client.up.speed      
DOWN_SPEED=/tmp/client.down.speed  
MAC_IP=/tmp/mac-ip.client
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
dog_daemon_monitor()
{
   pid=$(ps | grep wifidog | cut -d "r" -f 1)
  
   if [ -n "$pid" ]
     then
       return 1
   fi
  
   /usr/bin/wdctl stop > /dev/null
   sleep 1
   /usr/bin/wifidog -d 1 &

   return 0
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
    while [ true ]
      do
         iface_data_file_generator
         clients_RxTxRate_generator
         dog_daemon_monitor
         sleep  $(($CHECK_INTERVAL - 3))
      done
 }

#############################
##
## now,do the loop
##
#############################
main_loop

