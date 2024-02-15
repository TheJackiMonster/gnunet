#!/bin/bash
timeout=$1
PREFIX=$2
line=$(head -n 1 timeout_$PREFIX.out)
date=$(echo $line|awk '{printf $1"\n"}')
now=$(date +%s%N)
sleeptime=$(bc -l <<< "0.000000001*$1")
if [ "" != "$line" ] && [ $timeout -le $(($now - $date)) ]
then
    sleeptime=0
elif [ "" != "$line" ]
then
    sleeptime=$(bc -l <<< "(${now}-${date})/1000000000")
fi
echo $sleeptime  >> timeout_$PREFIX.log
while sleep $sleeptime
do
    line_num=$(wc -l < timeout_$PREFIX.out)
    if [ 0 -lt $line_num ];then
	    for i in $(seq 1 $line_num)
	    do
	        line=$(head -n 1 timeout_$PREFIX.out)
	        date=$(echo $line|awk '{printf $1"\n"}')
            port=$(echo $line|awk '{printf $5"\n"}')
            dst=$(echo $line|awk '{printf $3"\n"}')
            src=$(echo $line|awk '{printf $4"\n"}')
            protocol=$(echo $line|awk '{printf $2"\n"}')
            ports[$i]=-1
	        now=$(date +%s%N)
	        echo $timeout $now $date >> timeout_$PREFIX.log
	        if [ $timeout -le $(($now - $date)) ]
	        then
                ports[$i]=$port
		        echo delete dnat $port ${ports[$i]} >> timeout_$PREFIX.log
		        sed -i -n -e '2,$p' timeout_$PREFIX.out
                sleeptime=$(bc -l <<< "0.000000001*$1")
            else
                for j in $(seq 1 $i)
                do
                    if [ ${ports[$j]} -eq $port ]
                    then
                        ports[$j]=-1
                    fi
                done
                sleeptime=$(bc -l <<< "(${now}-${date})/1000000000")
                echo $sleeptime  >> timeout_$PREFIX.log
	        fi
	    done
        for i in $(seq 1 $line_num)
        do
            echo $i ${ports[$i]} >> timeout_$PREFIX.log
            if [ ${ports[$i]} -ne -1 ]
            then
                echo iptables-nft -t nat -D PREROUTING -p $protocol -s $dst -d 92.68.150.$PREFIX -j DNAT --to $src >> timeout_$PREFIX.log
                iptables-nft -t nat -D PREROUTING -p $protocol -s $dst -d 92.68.150.$PREFIX -j DNAT --to $src
            fi
        done
    fi
done
