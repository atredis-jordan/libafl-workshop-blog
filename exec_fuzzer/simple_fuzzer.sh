#!/bin/bash

TARGET=../fuzz_target/target

while ! [ -f ./core.* ]
do
    head -c 900 /dev/urandom > ./testfile
    cat ./testfile | $TARGET
done
