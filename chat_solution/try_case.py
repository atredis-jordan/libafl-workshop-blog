#!/usr/bin/python3

from socket import *
import sys
import struct

data = bytearray()
with open(sys.argv[1], "rb") as fp:
    data = bytearray(fp.read())

l = struct.pack("<H",len(data) - 8)

data[6:8] = l

print(data.hex())
#sys.stdout.buffer.write(data)

#cat $1 | ncat localhost 8088


s = socket()
s.connect(("localhost", 8088))
s.send(data)
s.close()