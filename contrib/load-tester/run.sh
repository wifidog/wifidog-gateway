#!/bin/bash

# On Ubuntu, you may want this:
# echo "core.%e.%p" > /proc/sys/kernel/core_pattern
# http://stackoverflow.com/a/18368068

echo "core.%e.%p" > /proc/sys/kernel/core_pattern
ulimit -c unlimited

COUNT=40
echo "Make sure to configure GatewayInterface in wifidog_mock.conf"

./generate_interfaces.sh start $COUNT || exit 1

./mock_auth.py &
MA_PID="$!"

# trace-children is necessary because of the libtool wrapper -.-
#sudo valgrind --leak-check=full --trace-children=yes --trace-children-skip=/bin/sh \
#    --log-file=valgrind.log ../../src/wifidog -d 7 -f -c wifidog-mock.conf 2> wifidog.log &

../../src/wifidog -d 7 -f -c wifidog-mock.conf -a /tmp/arp 2> wifidog.log &
WD_PID="$!"

IF=`grep GatewayInterface wifidog-mock.conf | cut -f 2 -d ' '`

echo "Waiting for wifidog to come up"

sleep 10

usage: fire_requests.py [-h] --target-interface TARGET_INTERFACE
                        --source-interface-prefix SOURCE_INTERFACE_PREFIX
                        --source-interface-count SOURCE_INTERFACE_COUNT
                        --process-count PROCESS_COUNT


./fire_requests.py \
    --target-interface $IF \
    --source-interface-prefix mac \
    --source-interface-count $COUNT \
    --process-count 3

#./generate_interfaces.sh stop

function cleanup() {

    kill $MA_PID
    kill $WD_PID
    ./generate_interfaces.sh stop $COUNT

}

trap cleanup EXIT
