#!/bin/sh                                                                                                       
RUN_WIFIDOG_PID=`pidof wifidog`
GATEWAY_ID=$(uci get wifidog_conf.single.gatewayId | awk '{print $NF}')
GATEWAY_INTERFACE=$(uci get wifidog_conf.single.gatewayInterface | awk '{print $NF}')

TRUSTED_MAC_LIST=$(uci get wifidog_conf.trustedMACList.TrustedMACList) 
UNTRUSTED_MAC_LIST=$(uci get wifidog_conf.untrustedMACList.UntrustedMACList)

WHITE_LIST=$(uci get wifidog_conf.whiteBlackList.WhiteList)
BLACK_LIST=$(uci get wifidog_conf.whiteBlackList.BlackList) 

#WHITE_LIST=`echo $WHITE_LIST | tr " " ","`
#BLACK_LIST=`echo $BLACK_LIST | tr " " ","`
#touch files
mkdir -p /tmp/.white_black_list
                                                                                                                
#compare
while [ true ]
do
        #detect
        iptables -t nat -L WiFiDog_"$GATEWAY_INTERFACE"_WhiteList -n --line-numbers|awk '{for(i=6;i<NF;i++)printf}'
        iptables -t mangle -L WiFiDog_"$GATEWAY_INTERFACE"_BlackList -n --line-numbers|awk '{for(i=6;i<NF;i++)printf}'

        rm /tmp/.white_black_list/.white_list_tmp 
        for white_list in $WHITE_LIST
        do
                nslookup $white_list |sed "1d"|sed "1d" |sed "1d" |sed "1d"|awk '{for(i=3;i<NF;i++)printf $i ""}';
        done 
        invalid=`grep -e ".*0\.0\..*" /tmp/.white_black_list/.white_list_tmp -rn|cut -d : -f 1`
        
        [ $invalid ] && sed -r -i "/"$invalid/"d" /tmp/.white_black_list/.white_list_tmp                            

        rm /tmp/.white_black_list/.black_list_tmp 
        for black_list in $thmd_url
        do                                                                                                      
                nslookup $black_list |sed "1d"|sed "1d" |sed "1d" |sed "1d"|awk '{for(i=3;i<NF;i++)printf $i ""}';
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
                        #echo "-------------------------------------------------------------------------------li
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
                        #echo "-------------------------------------------------------------------------------li
                fi                                                                                              
        done < /tmp/.white_black_list/.black_list_tmp                                                           
                                                                                                                
        sleep 10                                                                                                
done


