#!/bin/bash

FUZZ=afl-fuzz

# we use -n to indicate there is not feedback
# and we have to use a version of the target that aborts on a win
$FUZZ -i ../fuzz_target/corpus/ -o aflpp_sol -n -- ../fuzz_target/target
