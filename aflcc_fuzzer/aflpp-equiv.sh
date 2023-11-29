#!/bin/bash

FUZZ=afl-fuzz

$FUZZ -i ../fuzz_target/corpus/ -o aflpp_sol -- ../fuzz_target/target_instrumented
