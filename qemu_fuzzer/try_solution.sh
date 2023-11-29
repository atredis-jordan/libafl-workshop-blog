#!/bin/bash

# expect an argument with the path to the solution

SOLPATH=$1

COMB="{{$(cat $SOLPATH)}}"
echo $COMB | ../fuzz_target/target_dbg