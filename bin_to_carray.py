#!/usr/bin/env python
import os, binascii

target = "C:\\Windows\\System32\\cmd.exe"
output_file = "F:\\file.txt"
bytes_per_line = 16


count = 0;
index = 0;
output = "unsigned char binary[] = {\n\t"
with open(target, "rb") as f:
	hexdata = binascii.hexlify(f.read())
hexlist = map(''.join, zip(*[iter(hexdata)]*2))
for hex in hexlist:
	if count >= bytes_per_line:
		output += "\n\t"
		count = 0;
	output += "0x" + str(hexlist[index]).upper() + ","
	count += 1;
	index += 1;
output += "\n};\n"
out = open(output_file, "w")
out.write(output)
out.close()