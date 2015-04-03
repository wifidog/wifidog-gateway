#!/bin/bash

# empty
> vmdata.log
> vmrss.log

WD_PID=$1

function getdatum {
    grep $1 /proc/$WD_PID/status | cut -f 3 -d " "
}

function plot {
    gnuplot memory.plot 
}

function main {
    SLEEP=5
    COUNT=0
    while true; do
        vmdata=`getdatum VmData`
        vmrss=`getdatum VmRSS`
        echo "$(($COUNT * $SLEEP)) $vmdata" >> vmdata.log
        echo "$(($COUNT * $SLEEP)) $vmrss" >> vmrss.log
        COUNT=$(($COUNT + 1))
        sleep $SLEEP
    done
}

main

# on exit, do plot
trap plot EXIT
