if [ "$1" != "" ];then
    # echo arg: $1 > /tmp/emu_run_$1.log
    $(/home/t3sserakt/Android/Sdk/platform-tools/adb start-server)
    echo 1 > /tmp/emu_run_$1.log
    $(/home/t3sserakt/Android/Sdk/emulator/emulator -no-window -avd $1) & #>> /tmp/emu_run_$1.log
    echo 2 >> /tmp/emu_run_$1.log
    $(/home/t3sserakt/Android/Sdk/platform-tools/adb wait-for-device shell 'while [[ -z $(getprop sys.boot_completed) ]]; do sleep 1; done;') #>> /tmp/emu_run_$1.log
    echo 3 >> /tmp/emu_run_$1.log
    $(/home/t3sserakt/Android/Sdk/platform-tools/adb forward tcp:5000 tcp:5000) #>> /tmp/emu_run_$1.log
    $(/home/t3sserakt/Android/Sdk/platform-tools/adb forward --list >> /tmp/emu_run_$1.log)
    echo 4 >> /tmp/emu_run_$1.log
    $(/home/t3sserakt/Android/Sdk/platform-tools/adb shell am start -n com.example.androidserver/.MainActivity) #>> /tmp/emu_run_$1.log
    echo 5 >> /tmp/emu_run_$1.log
    sleep 300
    echo 6 >> /tmp/emu_run_$1.log
    $(/home/t3sserakt/Android/Sdk/platform-tools/adb emu kill) #>> /tmp/emu_run_$1.log
    echo 7 >> /tmp/emu_run_$1.log
    $(/home/t3sserakt/Android/Sdk/platform-tools/adb kill-server) 
fi
