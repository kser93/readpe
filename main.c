#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "pe_guts.h"

#define ERRBUF_SIZE 128
#define PE_BUF_SIZE 0x1000

FILE* fp = NULL;
char* pe_buf = NULL;

void free_resources()
{
	if (pe_buf != NULL)
	{
		free(pe_buf);
		pe_buf = NULL;
	}
	if (fp != NULL)
	{
		fclose(fp);
		fp = NULL;
	}
}

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

_Noreturn void die(char* cause, char* errvalue, int errcode)
{
	char *errbuf = strerror(errcode);
	if (errbuf == NULL)
	{
		abort();
	}
	printf("[%s] %s: %s\n", cause, errvalue, errbuf);
	free_resources();
	exit(errcode);
}

int main(int argc, char* argv[])
{
	char* target_name = NULL;
	fp = NULL;
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
		die("SYS", target_last_name, EINVAL);
	}

	pe_buf = (char *)calloc(PE_BUF_SIZE, 1);
	if (pe_buf == NULL)
	{
		die("SYS", "pe_buf", EINVAL);
	}

	image_dos_header_t *dos_heaher_p = (image_dos_header_t *)pe_buf;
	fread((void *)dos_heaher_p, sizeof(image_dos_header_t), 1, fp);
	if (dos_heaher_p->e_magic != DOSMAGIC)
	{
		die("DOS_MAGIC", pe_buf, EINVAL);
	}

	dump_dos_header(dos_heaher_p);

	e_code = fseek(fp, dos_heaher_p->e_lfanew, SEEK_SET);
	if (e_code != 0)
	{
		char errmsg_buf[20];
		sprintf(errmsg_buf, "e_lfanew = 0x%X", dos_heaher_p->e_lfanew);
		die("PE_DOSHDR", errmsg_buf, EINVAL);
	}

	image_nt_headers32_t *nt_headers32_p = (image_nt_headers32_t *)pe_buf;
	//image_nt_headers64_t *nt_headers64_p = (image_nt_headers64_t *)pe_buf;

	fread((void *)nt_headers32_p, sizeof(image_nt_headers32_t), 1, fp);
	if (nt_headers32_p->signature != PEMAGIC)
	{
		die("PE_MAGIC", pe_buf, EINVAL);
	}

	// TODO: ImageBase: image_nt_headers[32|64]_t.image_optional_header[32|64]_t.ImageBase
	// TODO: EntryPoint: image_nt_headers[32|64]_t.image_optional_header[32|64]_t.AddressOfEntryPoint
	// TODO: SizeOfImage: image_nt_headers[32|64]_t.image_optional_header[32|64]_t.SizeOfImage
	// For each section (NumberOfSections: image_nt_headers[32|64]_t.image_file_header_t.NumberOfSections)
	// TODO: SectionName: image_nt_headers[32|64]_t.image_section_header_t.Name
	// TODO: Characteristics: image_nt_headers[32|64]_t.image_section_header_t.Characteristics
	// Use MSDN rules: [https://docs.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-image_section_header?redirectedfrom=MSDN#members]

	free_resources();
	return 0;
}
