# RunPE
RunPE Code Injection - Runs an embedded PE image without dropping it to disk. Useful for file-less execution, and protecting of embedded binaries.

1. Main.cpp - The main RunPE C++ code.
2. bin_to_carray.py - Python script which turns a binary into a c-style array. Useful for converting your own PE to an C/C++ embeddable format
