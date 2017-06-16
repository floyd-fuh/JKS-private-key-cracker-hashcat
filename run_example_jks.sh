#!/bin/bash
#By floyd https://www.floyd.ch @floyd_ch
#modzero AG https://www.modzero.ch @mod0

CMD="time pypy ./jksprivk_crack.py"

function run () {
    FILE=$1
    NUM=$2
    java -jar JksPrivkPrepare.jar $FILE > ./tmp_file
    echo
    echo $file
    exec 3>&1 4>&2
    TIME=$(TIMEFORMAT="%R"; { time $CMD ./tmp_file 1>&3 2>&4; } 2>&1)
    exec 3>&- 4>&-
    echo "Took $TIME seconds"
    TRIES=$(echo "scale = 1; $NUM / $TIME"|bc)
    echo "$TRIES tries per second"
}


find ./example_jks/*123456.jks -type f | while IFS= read -r file; do
    run $file 123456
done
find ./example_jks/*1234567.jks -type f | while IFS= read -r file; do
    run $file 1234567
done
find ./example_jks/*12345678.jks -type f | while IFS= read -r file; do
    run $file 12345678
done
find ./example_jks/*123456789.jks -type f | while IFS= read -r file; do
    run $file 123456789
done
find ./example_jks/*1234567890.jks -type f | while IFS= read -r file; do
    run $file 1234567890
done