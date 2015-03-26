#!/bin/bash


echo "Make sure to configure GatewayInterface in wifidog_mock.conf"

#./generate_interfaces.sh start || exit 1

./mock_auth.py &

# trace-children is necessary because of the libtool wrapper -.-
sudo valgrind --leak-check=full --trace-children=yes --trace-children-skip=/bin/sh \
    --log-file=valgrind.log ../../src/wifidog -d 7 -f -c wifidog-mock.conf 2> wifidog.log &

IF=`grep GatewayInterface wifidog-mock.conf | cut -f 2 -d ' '`

echo "Waiting for wifidog to come up"

sleep 10
./fire_requests.py $IF mac 9

#./generate_interfaces.sh stop


