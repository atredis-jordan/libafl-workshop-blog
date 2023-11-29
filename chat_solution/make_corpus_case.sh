#!/bin/bash

sudo tshark -i lo -f 'tcp && port 8088' -T json -j 'tcp' -e 'tcp.payload' -a packets:1 | jq '.[0]._source.layers["tcp.payload"][0]' | xxd -ps -r > case.bin

xxd case.bin
