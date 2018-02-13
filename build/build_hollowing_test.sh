#!/bin/bash          
# simple example script for 32 bit process hollowing test, injecting hello world message box
# include script containing the compiler var $win32_compiler
# you can edit the compiler in build/global_win32.sh
# or enter $win32_compiler="mycompiler" here
. build/global_win32.sh
# build 32 bit hello executable
$win32_compiler -o payloads/hello.exe payloads/hello.c
# assume empty defs.h, cleanup
echo "" > defs.h
# call make_bfg, compile payload into executable
./make_bfg -H payloads/hello.exe
# compile 
$win32_compiler -o bfg.exe bfg.c 
# cleanup
echo "" > defs.h
# call like: C:\>bfg "c:\Program Files (x86)\KeePass Password Safe\KeePass.exe"
