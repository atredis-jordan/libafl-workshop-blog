#!/bin/bash

FUZZ=afl-fuzz

# right after the inital setup, set up the forkserver
export AFL_ENTRYPOINT=`objdump -t ../fuzz_target/target | grep '\smain' | awk '{print "0x" substr($1,0,length($1))}'`

# we could also write a persistent hook and use the QEMU Persistent mode
# https://github.com/AFLplusplus/AFLplusplus/blob/stable/qemu_mode/README.persistent.md

echo $AFL_ENTRYPOINT

$FUZZ -i ../fuzz_target/corpus/ -o aflpp_sol -Q -- ../fuzz_target/target

