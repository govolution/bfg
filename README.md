BFG
===

What & Why:
- bfg is a tool for executing and injecting shellcode
- it uses some concepts from https://github.com/govolution/avet
- not meant to be another antivirus evasion tool
- this readme applies for Kali 2 (64bit) and tdm-gcc

How to install tdm-gcc with wine:
https://govolution.wordpress.com/2017/02/04/using-tdm-gcc-with-kali-2/


How to use make_bfg and build scripts
-------------------------------------
Compile if needed, for example if you use a 32 bit system:
```
$ gcc -o make_bfg make_bfg.c
```

The purpose of make_bfg is to preconfigure a definition file (defs.h) so that the source code can be compiled in the next step. Let's have a look at the options from make_avet, examples will be given below:
```
-H hollow target process and insert payload executable: pwn.exe svchost.exe
	-H mypayload.exe to set payload to inserted into the hollowed process
	-x flag to XOR obfuscate the payload with a random key byte
-i inject
	-i shellcode for injecting shellcode
	-i dll for injecting a dll
-P inject shellcode by PID as argument, call pwn.exe PID
-I inject shellcode by image name, call for example: pwn.exe keepass.exe
-l load and exec shellcode from given file, call is with mytrojan.exe myshellcode.txt
-f compile and execute shellcode into .exe, needs filename of shellcode file
-X compile for 64 bit
-p print debug information
-q quiet mode (hide console window)
-h help
```

Of course it is possible to run all commands step by step from command line. But it is strongly recommended to use build scripts or the bfg_fabric.py.

The build scripts themselves are written so as they have to be called from within the bfg directory:
```
root@kalidan:~/tools/bfg# ./build/build_win32_meterpreter_rev_https_shikata_loadfile.sh 
```

Here are some explained examples for building the .exe files from the build directory. Please have a look at the other build scripts for further explanation.


Examples
--------
Please refer the files in the build directory.
```
build_hollowing_hello_exe.sh
Hollow target process and insert payload executable (here a simple exe with a messagebox).

build_win32_load_exec_dll.sh
Simply loads and execs a dll.

build_win32_meterpreter_rev_https_50xshikata.sh
Loads and execute a shellcode, the shellcode is compiled into the .exe file.

build_win32_meterpreter_rev_https_shikata_loadfile.sh 
Loads and execute a shellcode from a file.

build_win32_msgbox_inject_dll_imagename.sh
Inject a dll by the imagename.

build_win32_msgbox_inject_dll.sh
Inject a dll by the PID. Call with bfg.exe yourdll.dll PID

build_win32_msgbox_inject_shellcode.sh
Inject a shellcode into a process by PID.

build_win32_msgbox_inject_shellcode_loadfile.sh
Inject and load a shellcode into a process by PID.

build_win32_msgbox_inject_shellcode_imagename.sh
Loads and execute a shellcode that is injected into a process. Therefore the name of 
the process (imagename) has to be specified.

build_win32_load_exec_dll.sh
Build an exe file that loads & execs a dll.

build_win64_bind_tcp_inject_dll.sh
Inject a dll by the PID. Call with bfg.exe yourdll.dll PID

build_win64_bind_tcp_inject_shellcode.sh
Inject a 64bit shellcode into a 64bit process.
```

bfg_fabric.py
-------------
bfg_fabric is an assistant, that loads all build scripts in the build directory (name has to be build*.sh) and then lets the user edit the settings line by line.

Credits
-------
https://github.com/securestate/syringe
https://github.com/tacticaljmp/humble-file-crypter

