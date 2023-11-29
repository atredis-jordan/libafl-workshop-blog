#!/bin/bash

# just removes some fuzzing side effects

rm -f ./*/.cur_input*
rm -f ./*/core.*
rm -rf ./*/aflpp_sol/
rm -rf ./*/solutions/
