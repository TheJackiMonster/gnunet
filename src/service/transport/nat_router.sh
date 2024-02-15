#!/bin/bash
dirname=$(dirname "$0")
PREFIX=$3
echo start $2 >> timeout_$PREFIX.log
if [ $2 -eq 1 ]
then
   if [ ! -d /tmp/netjail_scripts ]
   then
        mkdir /tmp/netjail_scripts
   fi 
   if [ -f timeout_$PREFIX.out ]
   then
       rm timeout_$PREFIX.out
   fi
   touch timeout_$PREFIX.out
   if [ -f timeout_$PREFIX.log ]
   then
       rm timeout_$PREFIX.log
   fi
   touch timeout_$PREFIX.log
   timeout=6000000000
   $dirname/timeout.sh $timeout $PREFIX &
   echo gaga >> timeout_$PREFIX.log
   timeout_pid=$!
   conntrack -E -e NEW -s 192.168.15.1 -d 92.68.150.1/24 | while read line
   do
       protocol=$(echo $line|awk '{printf $2"\n"}'|awk '{printf $1"\n"}')
       dst=$(echo $line|awk -Fdst= '{printf $2"\n"}'|awk '{printf $1"\n"}')
       src=$(echo $line|awk -Fdst= '{printf $1"\n"}'|awk -Fsrc= '{printf $2"\n"}')
       port=$(echo $line|awk -Fdport= '{printf $2"\n"}'|awk '{printf $1"\n"}')
       echo dnat >> timeout_$PREFIX.log
       now=$(date +%s%N)
       kill -TSTP $timeout_pid
       if [ $(wc -l < timeout_$PREFIX.out) -eq 0 ]
       then
           iptables-nft -t nat -A PREROUTING -p $protocol -s $dst -d 92.68.150.$PREFIX -j DNAT --to $src
           # echo iptables-nft -t nat -A PREROUTING -p $protocol -s $dst -d 92.68.150.1 -j DNAT --to $src >> timeout_$PREFIX.out
           echo forwarding >> timeout_$PREFIX.log
       fi
       # echo $line >> timeout_$PREFIX.out
       echo $now $protocol $dst $src $port >> timeout_$PREFIX.out
       kill -CONT $timeout_pid
   done
   echo gigi >> timeout_$PREFIX.log
   rm timeout_$PREFIX.out
else
   #echo "find -L /proc/[1-9]*/task/*/ns/net -samefile /run/netns/$1|while read x" >> timeout_$PREFIX.log
   #find -L /proc/[1-9]*/task/*/ns/net -samefile /run/netns/$1|while read x
   #do
       #if [ "" != "$(ps aux|grep $x|grep conntrack)" ]
       #then
           echo kill conntrack >> timeout_$PREFIX.log
           killall conntrack #$x
       #fi
       #if [ "" != "$(ps aux|grep $x|grep timeout)" ]
       #then
           echo kill timeout >> timeout_$PREFIX.log
           killall timeout.sh #$x
           echo kill getmsg >> timeout_$PREFIX.log
           killall getmsg.sh
       #fi
   #done
fi
