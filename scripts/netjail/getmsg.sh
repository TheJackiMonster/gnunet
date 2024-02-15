#!/bin/bash
dirname=$(dirname "$0")
if [ $3 -gt 3 ]
then
    exit 1
fi
it=$(($3+1))
read MESSAGE
echo START "$MESSAGE" END
if [ "START second END" != "$MESSAGE" ] || [ "START  END" != "$MESSAGE" ]
then
    (nc -N -l $1 | $dirname/getmsg.sh $1 $2 $it >> getmsg_$2.out) &
else
    echo failure
fi
