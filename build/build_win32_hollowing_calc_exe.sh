#!/bin/bash          
# simple example script for 32 bit process hollowing test, injecting hello world message box
# include script containing the compiler var $win32_compiler
# you can edit the compiler in build/global_win32.sh
# or enter $win32_compiler="mycompiler" here
. build/global_win32.sh
# assume empty defs.h, cleanup
echo "" > defs.h
# call make_bfg, compile payload into executable
# set -x flag to use xor obfuscation
./make_bfg -H payloads/calc.exe -x
# compile 
$win32_compiler -o bfg.exe bfg.c 
strip bfg.exe
# cleanup
echo "" > defs.h
# call like C:\> bfg "c:\Program Files (x86)\KeePass Password Safe\KeePass.exe"
