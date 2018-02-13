// dll: wine gcc -o hello.dll hello.c -shared -mwindows
// exe: wine gcc -o hello.exe hello.c -mwindows
// rundll32 hello.dll,main
#include <windows.h>

void main (void)
{
	MessageBoxW (NULL, L"Hello World!", L"hello", MB_OK | MB_ICONINFORMATION); 
}

