#!/bin/bash          
# This is an example script to test hollowing against a 64 bit target process, injecting a hello world message box.
#
# Include predefined win64 compiler.
# >>> You can edit the compiler in build/global_win64.sh
# >>> or enter $win64_compiler="mycompiler" here
. build/global_win64.sh
# Build 32 bit hello executable
$win64_compiler -o payloads/hello.exe payloads/hello.c
# Remove debug symbols from payload
strip payloads/hello.exe
# Assume empty defs.h, cleanup
echo "" > defs.h
# Call make_bfg and compile the payload into the executable.
# -H switch enables hollowing functionality
# Set -x flag to use xor obfuscation on the payload
# Set -a flag to use alternative encoding, which is a little more complex
# Set -X flag to declare that target process is 64 bit
./make_bfg -H payloads/hello.exe -a -X
# Compile 
$win64_compiler -o bfg.exe bfg.c 
# Remove debug symbols from generated executable
strip bfg.exe
# Cleanup
echo "" > defs.h
#
# Example usage of generated executable:
# bfg.exe target.exe
# target.exe is the target executable to be hollowed.