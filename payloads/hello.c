// dll: wine gcc -o hello.dll hello.c -shared -mwindows
// exe: wine gcc -o hello.exe hello.c -mwindows
// rundll32 hello.dll,main
#include <windows.h>

void main (int argc, char **argv)
{
	MessageBoxA(NULL, GetCommandLine(), "hello", MB_OK | MB_ICONINFORMATION); 
}

