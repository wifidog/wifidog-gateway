#/bin/bash

IF="eth0"
# for whatever reason, if you use eth0.x as your virtual interface name,
# dhclient will lose the carrier
PREFIX="mac"
# don't touch resolv.conf
DHCP="dhcpcd --waitip -C resolv.conf"
#DHCP="dhclient -v"
NET="10.0.10."
ARPTABLE="/tmp/arp"

COUNT=$2

function start() {
    echo "IP address       HW type     Flags       HW address            Mask     Device" > $ARPTABLE
    # Add internal address for GW
    sudo ip link add internal0 link $IF type macvlan mode bridge || exit 1
    sudo ip addr add ${NET}254 dev internal0
    sudo ip link set internal0 up || exit 2
    for i in `seq 0 $COUNT`; do
        echo "Add link $i"
        # sudo ip link add virtual0 link eth0 type macvlan mode bridge
        sudo ip link add ${PREFIX}${i} link $IF type macvlan mode bridge || exit 1
        echo "Assigning temporary IP address"
        # use link-local address. Ideally, we would check if the
        # address is already aissgned
        sudo ip addr add ${NET}$(($i + 1)) dev ${PREFIX}${i}
        MAC=`ip link show ${PREFIX}${i} | grep ether | sed -e 's,.*link/ether ,,' -e 's, brd.*,,'`
        echo "Marking link $i up"
        sudo ip link set ${PREFIX}${i} up || exit 2
        #echo "Acquiring IP for link $i"
        # when using DHCP, the interface would immediately
        # go down?
        #sudo $DHCP ${PREFIX}${i} || exit 3
        echo " ${NET}$(($i + 1))     0x1         0x2         $MAC     *        ${PREFIX}${i}" >> $ARPTABLE
    done
}

function stop() {
    sudo ip link del internal0 2>/dev/null || true
    for i in `seq 0 $COUNT`; do
        echo "Deleting link $i"
        sudo ip link del ${PREFIX}${i} 2>/dev/null || true
    done
}



if [[ x$1 == x"start" ]]; then
    stop
    start
elif [[ x$1 == x"stop" ]]; then
    stop
else
    echo "Unknown command"
fi
