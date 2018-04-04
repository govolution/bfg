// Taken from https://github.com/hasherezade/demos (and probably modified)
// Credits go to hasherezade


#pragma once

#include <Windows.h>
#include <stdio.h>

#define false 0
#define true 1
typedef int bool;

IMAGE_NT_HEADERS* get_nt_hdrs(BYTE *pe_buffer)
{
    if (pe_buffer == NULL) return NULL;

    IMAGE_DOS_HEADER *idh = (IMAGE_DOS_HEADER*)pe_buffer;
    if (idh->e_magic != IMAGE_DOS_SIGNATURE) {
        return NULL;
    }
    const LONG kMaxOffset = 1024;
    LONG pe_offset = idh->e_lfanew;
    if (pe_offset > kMaxOffset) return NULL;

    IMAGE_NT_HEADERS *inh = (IMAGE_NT_HEADERS *)((BYTE*)pe_buffer + pe_offset);
    return inh;
}


IMAGE_DATA_DIRECTORY* get_pe_directory(PVOID pe_buffer, DWORD dir_id)
{
    if (dir_id >= IMAGE_NUMBEROF_DIRECTORY_ENTRIES) {		
		return NULL;
	}
		
    //fetch relocation table from current image:
    PIMAGE_NT_HEADERS nt_headers = get_nt_hdrs((BYTE*) pe_buffer);
    if (nt_headers == NULL) {		
		return NULL;
	}

    IMAGE_DATA_DIRECTORY* peDir = &(nt_headers->OptionalHeader.DataDirectory[dir_id]);
	
	#ifdef X64
		if (((PVOID) ((DWORD64) peDir->VirtualAddress)) == NULL) {			
			return NULL;
		}
	#else
		if (((PVOID) peDir->VirtualAddress) == NULL) {
			return NULL;
		}		
	#endif
	
    return peDir;
}


bool is32Bit(PVOID payloadData) {
	PIMAGE_DOS_HEADER payloadDosHeader;
	PIMAGE_NT_HEADERS payloadNtHeader;
	
	// Get payload headers
	payloadDosHeader = (PIMAGE_DOS_HEADER) payloadData;
	payloadNtHeader = (PIMAGE_NT_HEADERS) ((BYTE *) payloadDosHeader + payloadDosHeader->e_lfanew);
	
	if(payloadNtHeader->FileHeader.Machine == IMAGE_FILE_MACHINE_I386) {
		return true;
	} else {
		return false;
	}	
}