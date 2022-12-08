#!/bin/bash

declare -A K_PLUGIN
declare -A R_TCP
declare -A R_TCP_ALLOWED
declare -i -A R_TCP_ALLOWED_NUMBER
declare -A R_UDP
declare -A R_UDP_ALLOWED
declare -i -A R_UDP_ALLOWED_NUMBER
declare -A P_PLUGIN
declare -A R_SCRIPT

extract_attributes()
{
    line_key=$1
    line=$2

    if [ "$line_key" = "P" ]
    then
	n=$(echo $line|cut -d \| -f 1|awk -F: '{print $2}')
	echo $n
	m=$(echo $line|cut -d \| -f 1|awk -F: '{print $3}')
	echo $m
    else
	number=$(echo $line|cut -d \| -f 1| cut -c 2-|cut -d : -f 2 )
	echo $number
    fi

    #nf=$(echo $line|awk -F: '{print NF}')
    nf=$(echo $line|awk -F\| '{print NF}')
    for ((i=2;i<=$nf;i++))
    do
        entry=$(echo $line |awk -v i=$i -F\| '{print $i}')
        echo $entry
        if [ "$(echo $entry|grep P)" = "" ]; then
	        key=$(echo $entry|cut -d { -f 2|cut -d } -f 1|cut -d : -f 1)
	        echo $key
	        value=$(echo $entry|cut -d { -f 2|cut -d } -f 1|cut -d : -f 2)
	        echo $value
            if [ "$key" = "tcp_port" ]
	        then
                R_TCP_ALLOWED_NUMBER[$number]=0
	            echo tcp port: $value
	            R_TCP[$number]=$value
	        elif [ "$key" = "udp_port" ]
	        then
                R_UDP_ALLOWED_NUMBER[$number]=0
	            echo udp port: $value
	            R_UDP[$number]=$value
	        elif [ "$key" = "plugin" ]
	        then
	            echo plugin: $value
	            echo $line_key
	            if [ "$line_key" = "P" ]
	            then
		            P_PLUGIN[$n,$m]=$value
		            echo $n $m ${P_PLUGIN[$n,$m]}
	            elif [ "$line_key" = "K" ]
	            then
		            K_PLUGIN[$number]=$value
	            fi
            elif [ "$key" = "script" ]
	        then
	            echo script: $value
	            echo $line_key
	            R_SCRIPT[$number]=$value
	        fi
        else
	        p1=$(echo $entry|cut -d P -f 2|cut -d } -f 1|cut -d : -f 2)
            echo $p1
            p2=$(echo $entry|cut -d P -f 2|cut -d } -f 1|cut -d : -f 3)
	        echo $p2
            if [ "$key" = "tcp_port" ]
	        then
                R_TCP_ALLOWED_NUMBER[$number]+=1
	            R_TCP_ALLOWED[$number,${R_TCP_ALLOWED_NUMBER[$number]},1]=$p1
                R_TCP_ALLOWED[$number,${R_TCP_ALLOWED_NUMBER[$number]},2]=$p2
                echo ${R_TCP_ALLOWED_NUMBER[$number]}
                echo ${R_TCP_ALLOWED[$number,${R_TCP_ALLOWED_NUMBER[$number]},1]}
                echo ${R_TCP_ALLOWED[$number,${R_TCP_ALLOWED_NUMBER[$number]},2]}
	        elif [ "$key" = "udp_port" ]
	        then
                R_UDP_ALLOWED_NUMBER[$number]+=1
	            R_UDP_ALLOWED[$number,${R_UDP_ALLOWED_NUMBER[$number]},1]=$p1
                R_UDP_ALLOWED[$number,${R_UDP_ALLOWED_NUMBER[$number]},2]=$p2
            fi
        fi
    done
    #for ((i=2;i<=$nf;i++))
    # do
	#entry=$(echo $line |awk -v i=$i -F\| '{print $i}')
	key=$(echo $entry|cut -d { -f 2|cut -d } -f 1|cut -d : -f 1)
	value=$(echo $entry|cut -d { -f 2|cut -d } -f 1|cut -d : -f 2)
	
    #done
}

parse_line(){
    line=$1
    echo $line
    key=$(cut -c -1 <<< $line)
    if [ "$key" = "M" ]
    then
	LOCAL_M=$(cut -d : -f 2 <<< $line)
	echo $LOCAL_M
    elif [ "$key" = "N" ]
    then
	GLOBAL_N=$(cut -d : -f 2 <<< $line)
	echo $GLOBAL_N
    for ((i=1;i<=$GLOBAL_N;i++))
    do
        R_TCP[$i]=0
        R_UDP[$i]=0
        R_SCRIPT[$i]=""
    done    
    elif [ "$key" = "X" ]
    then
	KNOWN=$(cut -d : -f 2 <<< $line)
	echo $KNOWN
    elif [ "$key" = "T" ]
    then
	PLUGIN=$(cut -d : -f 2 <<< $line)
	echo $PLUGIN
    elif [ "$key" = "B" ]
    then
	BROADCAST=$(cut -d : -f 2 <<< $line)
	echo $BROADCAST
    elif [ "$key" = "K" ]
    then
	echo know node
	extract_attributes $key $line
    elif [ "$key" = "R" ]
    then
	echo router
	extract_attributes $key $line
    elif [ "$key" = "P" ]
    then
	echo node
	extract_attributes $key $line
    fi
}

read_topology_string(){
    string=$1
    IFS=' ' read -r -a array <<< $string
    for element in "${array[@]}"
    do
        echo $element
        parse_line $element
    done
}

read_topology(){
    local filename=$1
    while read line; do
        # reading each line
        parse_line $line
    done < $filename
}



