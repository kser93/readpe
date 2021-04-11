#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "ms_dos_header.h"

#define ERRBUF_SIZE 128
#define PE_BUF_SIZE 0x1000
#define PE_MAGIC_SIZE 2


void usage(char* progname)
{
	printf("Usage: %s [PE_FILE]\n\n", progname);
	printf("This program cannot be run in DOS mode and prints out:\n");
	printf("  * Image base\n");
	printf("  * Sections info (name, rwx flags)\n");
	printf("  * Entry point\n");
	printf("  * Size of image\n");
	printf("\n");
	printf("Command-line arguments:\n");
	printf("%10s:%50s\n", "[PE_FILE]", "MS Windows executable in PE format.");
	printf("%61s\n", "By default examines itself.");
}

_Noreturn void errprint(char* cause, char* errvalue, int errcode)
{
	char *errbuf = strerror(errcode);
	if (errbuf == NULL)
	{
		abort();
	}
	printf("[%s] %s: %s\n", cause, errvalue, errbuf);
	exit(errcode);
}

int main(int argc, char* argv[])
{
	char* target_name = NULL;
	FILE* fp = NULL;
	int e_code = 0;

	if (argc != 2)
	{
		char* progname = strrchr(argv[0], '\\');
		if (progname == NULL)
		{
			progname = strrchr(argv[0], '/');
		}
		if (progname == NULL)
		{
			progname = argv[0];
		}
		else
		{
			++progname;
		}

		usage(progname);
		target_name = argv[0];
	}
	else
	{
		target_name = argv[1];
	}

	fp = fopen(target_name, "rb");
	if (fp == NULL)
	{
		char* target_last_name = strrchr(target_name, '\\');
		target_last_name = (target_last_name == NULL) ? target_name : target_last_name + 1;
		errprint("PE_FILE", target_last_name, EINVAL);
	}

	char pe_buf[PE_BUF_SIZE];
	struct dos_header* stub_p = (struct dos_header*)pe_buf;
	fread((void*)stub_p, sizeof(dos_header), 1, fp);
	if (stub_p->e_magic != DOSMAGIC)
	{
		fclose(fp);
		errprint("PE_MAGIC", pe_buf, EINVAL);
	}

	dump_dos_header(stub_p);

	e_code = fseek(fp, stub_p->e_lfanew, SEEK_SET);
	if (e_code != 0)
	{
		fclose(fp);

		char errmsg_buf[20];
		sprintf(errmsg_buf, "e_lfanew = 0x%X", stub_p->e_lfanew);
		errprint("PE_DOSHDR", errmsg_buf, EINVAL);
	}

	// ...
	fclose(fp);
	return 0;
}
