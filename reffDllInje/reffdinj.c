

#include <Windows.h>
#include <stdio.h>
#include <stdlib.h>
#include "injector.h"




int main(int argc, char **argv)
{

	printf("[*]Reflective dll injection by antonio campus.\n");
	printf("[*]inspired by: https://github.com/stephenfewer/ReflectiveDLLInjection\n");
	printf("[*]Tested on x86 arch\n");
	printf("[*]Usage: binname.exe, to inject in current process\n");
	printf("[*]Usage: binname.exe [pid], to inject in target process\n");

	DWORD pid;
	switch (argc)
	{
	case 1:pid = GetCurrentProcessId(); break;
	case 2:pid = atoi(argv[1]); break;
	default:
		break;
	}
	printf("[*]Usage: Trying to inject code to process %d\n", pid);

	return inject(pid);
}


