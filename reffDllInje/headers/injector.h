#ifndef INJECTOR_H
#define INJECTOR_H

#include <Windows.h>
#include <stdio.h>


#ifdef _WIN64
#define PATH "payload_64bit.dll"
#else
#define PATH "payload_32bit.dll"
#endif
#define desireAccess PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION|PROCESS_VM_WRITE | PROCESS_VM_READ

DWORD32 Rva2Offset(DWORD dwRva, UINT_PTR uiBaseAddress);
DWORD inject(DWORD processid);



#endif // !INJECTOR_H
