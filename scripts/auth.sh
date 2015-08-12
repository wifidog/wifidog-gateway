#!/bin/sh
#live-8  empire.x@qq.com 20150513

hostname=`uci get wifidog.wifidog.gateway_hostname`
#DATE=`date +%Y-%m-%d-%H:%M:%S`
sum=0
#echo --- 开始检查 ---
while [[ $sum -lt 3 ]]
do
  if /bin/ping -c 1 $hostname >/dev/null
    then
#echo --- 服务器可连接，再判断进程是否存在，进入进程守护工作 ---
      ps | grep wifidog | grep -v grep | grep wifidog && echo wifidog-Running.... || /etc/init.d/wifidog start
      
      uci get wifidog.wifidog.wifidog_enable | grep '0' && echo "" > /usr/lm/script/wifidogcron.sh
      
    exit 0
  fi
     sum=$((sum+1))
#     sleep 1
done
  ps | grep wifidog | grep -v grep | grep wifidog && /etc/init.d/wifidog stop
  
  uci get wifidog.wifidog.wifidog_enable | grep '0' && echo "" > /usr/lm/script/wifidogcron.sh

