#!/bin/bash

FUZZ=afl-fuzz

# afl++ is a great drop in replacement for libfuzzer
# libfuzzer is now unmaintained, and lacks a lot of features
# so using afl++'s compilers it can automatically insert libAFLDriver.a
# which ends up pretty similar to a persistent fuzzing setup
# but easy to set up with a libfuzzer codebase
# and it will outperform libfuzzer most of the time

$FUZZ -i ../fuzz_target/corpus/ -o aflpp_sol -- ../fuzz_target/target_libfuzzer
