// dll: wine gcc -o hello.dll hello.c -shared -mwindows
// exe: wine gcc -o hello.exe hello.c -mwindows
// rundll32 hello.dll,main
#include <windows.h>

void main (int argc, char **argv)
{
	if(argv[0]) MessageBoxA(NULL, argv[0], "hello0", MB_OK | MB_ICONINFORMATION);
	if(argv[1]) MessageBoxA(NULL, argv[1], "hello1", MB_OK | MB_ICONINFORMATION);
	if(argv[2]) MessageBoxA(NULL, argv[2], "hello2", MB_OK | MB_ICONINFORMATION);
	if(argv[3]) MessageBoxA(NULL, argv[3], "hello3", MB_OK | MB_ICONINFORMATION);
	if(argv[4]) MessageBoxA(NULL, argv[4], "hello4", MB_OK | MB_ICONINFORMATION);
}

