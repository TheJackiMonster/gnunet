#!/bin/bash
echo started > block.log
while true
do
    if [ -f stop ]
    then
        break
    fi
    sleep 1
done
echo stopped >> block.log
