#!/bin/sh
###############################################################################################################################
#
# description: get the settings of wireless,
#		lan,wan,reboot_info and dhcp.
#		use in OpenWrt router,based on uci
# Version: 1.0.0
# Author: GaomingPan
#         2015-07-29
#
# Pram:  $1 gw_id
# 	 $2 cmd_id
#
################################################################################################################################
TMP=/tmp/.tmpfile
STMP=/tmp/.stmpfile
RESULT_FILE=/tmp/routersettings
RESULT=""
echo "" > $RESULT_FILE
RESULT="$RESULT$(echo "{\"gw_id\":\"$1\",\"cmd_id\":\"$2\",\"type\":\"getsettings\",")"
RESULT="$RESULT$(echo "\"result\":{\"wireless\":{")"
uci show wireless > $TMP
while read line;do echo $line>$STMP; RESULT="$RESULT$(awk -F "=" '{print "\""$1"\":","\""$2"\"," }'<$STMP)";done < $TMP
RESULT=${RESULT%,}
RESULT="$RESULT},\"lan\":{"
uci show network.lan > $TMP
while read line;do echo $line>$STMP; RESULT="$RESULT$(awk -F "=" '{print "\""$1"\":","\""$2"\"," }'<$STMP)";done < $TMP
RESULT=${RESULT%,}
RESULT="$RESULT},\"wan\":{"
uci show network.wan > $TMP
while read line;do echo $line>$STMP; RESULT="$RESULT$(awk -F "=" '{print "\""$1"\":","\""$2"\"," }'<$STMP)";done < $TMP
RESULT=${RESULT%,}
RESULT="$RESULT},\"dhcp\":{"
uci show dhcp > $TMP
while read line;do echo $line>$STMP; RESULT="$RESULT$(awk -F "=" '{print "\""$1"\":","\""$2"\"," }'<$STMP)";done < $TMP
RESULT=${RESULT%,}
RESULT="$RESULT},\"reboot_info\":\"`cat /etc/crontabs/root | grep -E "reboot" | awk '{print $2" :",$1}'`\","
RESULT="$RESULT\"trustedMacList\":[$(uci get wifidog_conf.trustedMACList.TrustedMACList | awk '{for(i=1;i<=NF;i++) print "\""$i"\","}')"
RESULT=${RESULT%,}],
RESULT="$RESULT\"untrustedMacList\":[$(uci get wifidog_conf.untrustedMACList.UntrustedMACList | awk '{for(i=1;i<=NF;i++) print "\""$i"\","}')"
RESULT=${RESULT%,}],
RESULT="$RESULT\"WhiteList\":[$(uci get wifidog_conf.whiteBlackList.WhiteList | awk '{for(i=1;i<=NF;i++) print "\""$i"\","}')"
RESULT=${RESULT%,}],
RESULT="$RESULT\"BlackList\":[$(uci get wifidog_conf.whiteBlackList.BlackList | awk '{for(i=1;i<=NF;i++) print "\""$i"\","}')"
RESULT=${RESULT%,}]}}

rm $TMP $STMP
echo $RESULT > $RESULT_FILE
#####
#    delete the single quote ' character,because some uci version will echo ' to the file.
#
sed -i 's/'\''//g'  $RESULT_FILE


