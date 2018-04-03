// Taken from https://github.com/hasherezade/demos (and probably modified)
// Credits go to hasherezade


#pragma once
#include <Windows.h>
#include "pe_hdrs_helper.h"

#define RELOC_32BIT_FIELD 3
#define RELOC_64BIT_FIELD 10

#define false 0
#define true 1
typedef int bool;


typedef struct _BASE_RELOCATION_ENTRY {
    WORD Offset : 12;
    WORD Type: 4;
} BASE_RELOCATION_ENTRY;


bool has_relocations(BYTE *pe_buffer)
{
    IMAGE_DATA_DIRECTORY* relocDir = get_pe_directory(pe_buffer, IMAGE_DIRECTORY_ENTRY_BASERELOC);
    if (relocDir == NULL) {
        return false;
    }
    return true;
}


bool apply_reloc_block(BASE_RELOCATION_ENTRY *block, SIZE_T entriesNum, DWORD page, ULONGLONG oldBase, ULONGLONG newBase, PVOID modulePtr)
{
	BASE_RELOCATION_ENTRY* entry = block;
	SIZE_T i = 0;
	for (i = 0; i < entriesNum; i++) {
		DWORD offset = entry->Offset;
		DWORD type = entry->Type;
		
		if (entry == NULL || type == 0) {
			break;
		}
		
		#ifdef X64
			if ((type != RELOC_32BIT_FIELD) && (type != RELOC_64BIT_FIELD)) {
				printf("Not supported relocations format at %d: %d\n", (int) i, type);
				return false;
			}
				
			if(type == RELOC_64BIT_FIELD) {
				DWORD64* relocateAddr64 = (DWORD64*) ((ULONG_PTR) modulePtr + page + offset);
				(*relocateAddr64) = (DWORD64) (*relocateAddr64) - ((ULONG_PTR) oldBase) + newBase;
				entry = (BASE_RELOCATION_ENTRY*)((ULONG_PTR) entry + sizeof(WORD));			
			} else if(type == RELOC_32BIT_FIELD) {
				DWORD* relocateAddr32 = (DWORD*) ((ULONG_PTR) modulePtr + page + offset);
				(*relocateAddr32) = (DWORD) (*relocateAddr32) - ((ULONG_PTR) oldBase) + newBase;
				entry = (BASE_RELOCATION_ENTRY*)((ULONG_PTR) entry + sizeof(WORD));			
			}					
		#else
			if (type != RELOC_32BIT_FIELD) {
				printf("Not supported relocations format at %d: %d\n", (int) i, type);
				return false;
			}
				
			DWORD* relocateAddr32 = (DWORD*) ((ULONG_PTR) modulePtr + page + offset);
			(*relocateAddr32) = (DWORD) (*relocateAddr32) - ((ULONG_PTR) oldBase) + newBase;
			entry = (BASE_RELOCATION_ENTRY*)((ULONG_PTR) entry + sizeof(WORD));					
		#endif			
	}
	//printf("[+] Applied %d relocations\n", (int) i);
	return true;		
}

				
bool apply_relocations(ULONGLONG newBase, ULONGLONG oldBase, PVOID modulePtr)
{
    IMAGE_DATA_DIRECTORY* relocDir = get_pe_directory(modulePtr, IMAGE_DIRECTORY_ENTRY_BASERELOC);
    if (relocDir == NULL) {
        printf ("Cannot relocate - application have no relocation table!\n");
        return false;
    }
    DWORD maxSize = relocDir->Size;
    DWORD relocAddr = relocDir->VirtualAddress;

    IMAGE_BASE_RELOCATION* reloc = NULL;

    DWORD parsedSize = 0;
    while (parsedSize < maxSize) {
        reloc = (IMAGE_BASE_RELOCATION*)(relocAddr + parsedSize + (ULONG_PTR) modulePtr);
        parsedSize += reloc->SizeOfBlock;

		#ifdef X64
        	if ((((PVOID) ((DWORD64) reloc->VirtualAddress)) == NULL) || reloc->SizeOfBlock == 0) {
            	continue;
        	}
		#else
			if ((((PVOID) reloc->VirtualAddress) == NULL) || reloc->SizeOfBlock == 0) {
            	continue;
        	}
		#endif

        //printf("RelocBlock: %x %x\n", reloc->VirtualAddress, reloc->SizeOfBlock);
        
        size_t entriesNum = (reloc->SizeOfBlock - 2 * sizeof(DWORD))  / sizeof(WORD);
        DWORD page = reloc->VirtualAddress;

        BASE_RELOCATION_ENTRY* block = (BASE_RELOCATION_ENTRY*)((ULONG_PTR) reloc + sizeof(DWORD) + sizeof(DWORD));
        if (apply_reloc_block(block, entriesNum, page, oldBase, newBase, modulePtr) == false) {
            return false;
        }
    }
    return true;
}