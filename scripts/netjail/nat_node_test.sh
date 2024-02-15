#!/bin/bash
dirname=$(dirname "$0")
PORT=$1
PREFIX=$2
DST=$3
echo nat_node_test args $PORT $PREFIX $DST > gaga_$PREFIX.out
(nc -N -l $PORT | $dirname/getmsg.sh $PORT $PREFIX 1 > getmsg_$PREFIX.out) &
printf "first" |nc -N $DST $PORT
sleep 5
printf "second" |nc -N $DST $PORT
sleep 10
printf "third" |nc -N $DST $PORT
sleep 5
if [ "" != "$(grep failure getmsg_$PREFIX.out)" ]
then
    echo FAILURE: We received third message. >> gaga_$PREFIX.out
    exit 1
elif [ "" != "$(grep second getmsg_$PREFIX.out)" ]
then
    echo SUCCESS >> gaga_$PREFIX.out
    exit 0
else
    echo FAILURE: Something unexpected happened. >> gaga_$PREFIX.out
    exit 1
fi
