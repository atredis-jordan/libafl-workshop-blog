#!/bin/bash

FUZZ=afl-fuzz

# gotta go fast! Watch the stability indicator on persistent targets
$FUZZ -i ../fuzz_target/corpus/ -o aflpp_sol -- ../fuzz_target/target_persistent
