# RunPE
RunPE Code Injection - Runs an embedded PE image without writing it to disk. Useful for file-less execution, and protecting of embedded binaries. Tested on Windows 10 and built with VS2015

1. Main.cpp - The main RunPE C++ code.
2. bin_to_carray.py - Python script which turns a binary into a c-style array. Useful for converting your own PE to a C/C++ embeddable format.
