#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "ms_dos_stub.h"

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
	size_t read_size = 0;

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
		printf("[%p] %s\n", progname, progname);

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

	/* parse PE magic which must be equal MZ */
	char pe_buf[PE_BUF_SIZE];
	read_size = fread((void*)pe_buf, sizeof(char), PE_MAGIC_SIZE, fp);
	pe_buf[read_size] = '\0';
	if (strncmp(pe_buf, "MZ", PE_MAGIC_SIZE) != 0)
	{
		fclose(fp);
		errprint("PE_MAGIC", pe_buf, EINVAL);
	}

	struct ms_dos_stub* stub_p = (struct ms_dos_stub*)pe_buf;
	rewind(fp);
	read_size = fread((void *)stub_p, sizeof(ms_dos_stub), 1, fp);
	dump_dos_stub(stub_p);

	e_code = fseek(fp, stub_p->e_lfanew, SEEK_SET);
	if (e_code != 0)
	{
		fclose(fp);
		// ...
	}

	fclose(fp);
	return 0;
}
