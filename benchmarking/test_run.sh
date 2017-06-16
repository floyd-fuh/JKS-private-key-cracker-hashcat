#!/bin/bash
#By floyd https://www.floyd.ch @floyd_ch
#modzero AG https://www.modzero.ch @mod0

CMD_PREP="java -jar ../JksPrivkPrepare.jar"
CMD_NAIVE="time pypy ./jksprivk_naive_crack.py"
CMD_EFFICIENT="time pypy ../jksprivk_crack.py"

KEYSTORE_PREP="pypy /opt/john-1.8.0-jumbo-1/run/keystore2john.py"
KEYSTORE_NAIVE="time pypy ./jkskeystore_crack.py"
KEYSTORE_PREP_CMD=""
KEYSTORE_EFFICIENT="time /opt/john-1.8.0-jumbo-1/run/john --wordlist=wordlist.txt"

function execute () {
    CMD="$1"
    #echo $CMD
    exec 3>&1 4>&2
    TIME=$(TIMEFORMAT="%R"; { time $CMD 1>&3 2>&4; } 2>&1)
    exec 3>&- 4>&-
    TRIES=$(echo "scale = 1; $NUM / $TIME"|bc)
    echo "Took $TIME seconds ($TRIES tries per second): $CMD"

}

function run () {
    FILE=$1
    NUM=$2
    echo
    echo $file
    $CMD_PREP $FILE > privkey_$NUM.txt
    $KEYSTORE_PREP $FILE > keystore_$NUM.txt
    
    #CMD="$CMD_NAIVE privkey_$NUM.txt"
    #execute "$CMD"
    
    CMD="$CMD_EFFICIENT privkey_$NUM.txt"
    execute "$CMD"
    
    #CMD="$KEYSTORE_NAIVE keystore_$NUM.txt"
    #execute "$CMD"
    
    rm /opt/john-1.8.0-jumbo-1/run/john.rec 2> /dev/null
    rm /opt/john-1.8.0-jumbo-1/run/john.pot 2> /dev/null
    rm /opt/john-1.8.0-jumbo-1/run/john.log 2> /dev/null
    CMD="$KEYSTORE_EFFICIENT keystore_$NUM.txt"
    execute "$CMD"
    
}

#find ../example_jks/*123456.jks -type f | while IFS= read -r file; do
#    run $file 123456
#done
#find ../example_jks/*1234567.jks -type f | while IFS= read -r file; do
#    run $file 1234567
#done
find ../example_jks/rsa*12345678.jks -type f | while IFS= read -r file; do
    run $file 12345678
done
find ../example_jks/rsa*123456789.jks -type f | while IFS= read -r file; do
    run $file 123456789
done
find ../example_jks/*1234567890.jks -type f | while IFS= read -r file; do
    run $file 1234567890
done