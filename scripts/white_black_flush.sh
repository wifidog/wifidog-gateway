#!/bin/sh


RUN_DOG_PID=`pidof wifidog`
GATEWAY_INTERFACE=$(uci get wifidog_conf.single.gatewayInterface | awk '{print $NF}')
WHITE_LIST_URL=$(uci get wifidog_conf.whiteBlackList.WhiteList) 
BLACK_LIST_URL=$(uci get wifidog_conf.whiteBlackList.BlackList) 

#touch files
mkdir -p /tmp/.white_black_list

#compare
while [ true ]
do
	
	WHITE_LIST_URL=$(uci get wifidog_conf.whiteBlackList.WhiteList) 
	BLACK_LIST_URL=$(uci get wifidog_conf.whiteBlackList.BlackList)
	
	#detect
	iptables -t nat -L WiFiDog_"$GATEWAY_INTERFACE"_WhiteList -n --line-numbers | awk '{for(i=6;i<NF;i++)printf $i "";print $NF}' | sed "1d" | sed "1d" > /tmp/.white_black_list/.white_list        
	iptables -t mangle -L WiFiDog_"$GATEWAY_INTERFACE"_BlackList -n --line-numbers | awk '{for(i=6;i<NF;i++)printf $i "";print $NF}' | sed "1d" | sed "1d" > /tmp/.white_black_list/.black_list    
	
	rm /tmp/.white_black_list/.white_list_tmp 
	for white_list in $WHITE_LIST_URL
	do
		nslookup $white_list | sed "1d" | sed "1d" | sed "1d" | sed "1d" | awk '{for(i=3;i<NF;i++)printf $i "";print $NF}' >> /tmp/.white_black_list/.white_list_tmp
	done
	invalid=`grep -e ".*0\.0\..*" /tmp/.white_black_list/.white_list_tmp -rn|cut -d : -f 1`
    [ $invalid ] && sed -r -i "/"$invalid/"d" /tmp/.white_black_list/.white_list_tmp
	
	rm /tmp/.white_black_list/.black_list_tmp
	for black_list in $BLACK_LIST_URL
	do
		nslookup $black_list |sed "1d"|sed "1d" |sed "1d" |sed "1d"|awk '{for(i=3;i<NF;i++)printf $i "";print $NF}'  >> /tmp/.white_black_list/.black_list_tmp
	done
	invalid=`grep -e ".*0\.0\..*" /tmp/.white_black_list/.black_list_tmp -rn|cut -d : -f 1`
    [ $invalid ] && sed -r -i "/"$invalid/"d" /tmp/.white_black_list/.black_list_tmp

	#white
	while read line_new
	do
		i=0
	
		 while read line_old
		do
			 if [ "$line_new" != "$line_old" ]; then
			 	i=1
			 else
			 	i=0
			 	break
			 fi
		done < /tmp/.white_black_list/.white_list
	
		if [ "$i" -eq "1" ]; then
			iptables -t nat -A WiFiDog_"$GATEWAY_INTERFACE"_WhiteList -d "$line_new" -j ACCEPT
			iptables -t filter -A WiFiDog_"$GATEWAY_INTERFACE"_WhiteList -d "$line_new" -j ACCEPT
			#echo "-------------------------------------------------------------------------------limeng white diff -------------------------------------------------------------------------"
		fi
	done < /tmp/.white_black_list/.white_list_tmp

	sleep 10

	#black
	while read line_new
	do
		i=0
	
		 while read line_old
		do
			 if [ "$line_new" != "$line_old" ]; then
			 	i=1
			 else
			 	i=0
			 	break
			 fi
		done < /tmp/.white_black_list/.black_list
	
		if [ "$i" -eq "1" ]; then
			iptables -t mangle -A WiFiDog_"$GATEWAY_INTERFACE"_BlackList -d "$line_new" -j DROP
			#echo "-------------------------------------------------------------------------------limeng black diff -------------------------------------------------------------------------"
		fi
	done < /tmp/.white_black_list/.black_list_tmp

	sleep 10
done

