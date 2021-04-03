#include <stddef.h>
#include <stdio.h>
#include <string.h>

#include "ms_dos_stub.h"

// dirty hack to make this code compile in both MSVC and gcc
#define uint64_t unsigned long long

void dump_dos_stub(ms_dos_stub *hdr)
{
	ms_dos_stub reference_stub = {
		.e_magic = DOSMAGIC,
		.e_cblp = 0x90,
		.e_cp = 0x3,
		.e_crlc = 0x0,
		.e_cparhdr = 0x4,
		.e_minalloc = 0x0,
		.e_maxalloc = 0xFFFF,
		.e_ss = 0x0,
		.e_sp = 0xB8,
		.e_csum = 0x0,
		.e_ip = 0x0,
		.e_cs = 0x0,
		.e_lfarlc = 0x40,
		.e_ovno = 0x0,
		.e_res = {0x0, 0x0, 0x0, 0x0},
		.e_oemid = 0x0,
		.e_oeminfo = 0x0,
		.e_res2 = {0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0},
		.e_lfanew = 0x80,
		.dos_program = {
			0x0E, 0x1F, 0xBA, 0x0E, 0x00, 0xB4, 0x09, 0xCD, 0x21, 0xB8, 0x01, 0x4C, 0xCD, 0x21,
			'T', 'h', 'i', 's', ' ', 'p', 'r', 'o', 'g', 'r', 'a', 'm', ' ', 'c', 'a', 'n', 'n', 'o', 't', ' ',
			'b', 'e', ' ', 'r', 'u', 'n', ' ', 'i', 'n', ' ', 'D', 'O', 'S', ' ', 'm', 'o', 'd', 'e', '.', '\r', '\r', '\n',
			0x24, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
		}
	};
	char *default_color = "\x1B[0m";
	char *diff_color = "\x1B[33m";
	char *color_fmt = NULL;
	uint64_t offset = 0;
	printf("%s\n", "DOS Header");
	printf("%-16s %-8s %-8s %-32s %-32s\n", "field", "offset", "size", "ref", "val");
	printf("%s\n", "=================================================================================================");

	color_fmt = (hdr->e_magic != reference_stub.e_magic) ? diff_color : default_color;
	offset = (uint64_t)&reference_stub.e_magic - (uint64_t)&reference_stub;
	printf(
		"%-16s 0x%-6.02llX 0x%-6.02lX ",
		"e_magic",
		offset,  // offsetof(ms_dos_stub, e_magic)
		sizeof(reference_stub.e_magic)
	);
	printf("0x%-30.2X %s0x%-30.2X%s\n", reference_stub.e_magic, color_fmt, hdr->e_magic, default_color);

	color_fmt = (hdr->e_cblp != reference_stub.e_cblp) ? diff_color : default_color;
	printf(
		"%-16s 0x%-6.02llX 0x%-6.02lX ",
		"e_cblp",
		(uint64_t)&reference_stub.e_cblp - (uint64_t)&reference_stub,  // offsetof(ms_dos_stub, e_cblp)
		sizeof(reference_stub.e_cblp)
	);
	printf("0x%-30.2X %s0x%-30.2X%s\n", reference_stub.e_cblp, color_fmt, hdr->e_cblp, default_color);

	color_fmt = (hdr->e_cp != reference_stub.e_cp) ? diff_color : default_color;
	printf(
		"%-16s 0x%-6.02llX 0x%-6.02lX ",
		"e_cp",
		(uint64_t)&reference_stub.e_cp - (uint64_t)&reference_stub,  // offsetof(ms_dos_stub, e_cp)
		sizeof(reference_stub.e_cp)
	);
	printf("0x%-30.2X %s0x%-30.2X%s\n", reference_stub.e_cp, color_fmt, hdr->e_cp, default_color);

	color_fmt = (hdr->e_crlc != reference_stub.e_crlc) ? diff_color : default_color;
	printf(
		"%-16s 0x%-6.02llX 0x%-6.02lX ",
		"e_crlc",
		(uint64_t)&reference_stub.e_crlc - (uint64_t)&reference_stub,  // offsetof(ms_dos_stub, e_crlc)
		sizeof(reference_stub.e_crlc)
	);
	printf("0x%-30.2X %s0x%-30.2X%s\n", reference_stub.e_crlc, color_fmt, hdr->e_crlc, default_color);

	color_fmt = (hdr->e_cparhdr != reference_stub.e_cparhdr) ? diff_color : default_color;
	printf(
		"%-16s 0x%-6.02llX 0x%-6.02lX ",
		"e_cparhdr",
		(uint64_t)&reference_stub.e_cparhdr - (uint64_t)&reference_stub,  // offsetof(ms_dos_stub, e_cparhdr)
		sizeof(reference_stub.e_cparhdr)
	);
	printf("0x%-30.2X %s0x%-30.2X%s\n", reference_stub.e_cparhdr, color_fmt, hdr->e_cparhdr, default_color);

	color_fmt = (hdr->e_minalloc != reference_stub.e_minalloc) ? diff_color : default_color;
	printf(
		"%-16s 0x%-6.02llX 0x%-6.02lX ",
		"e_minalloc",
		(uint64_t)&reference_stub.e_minalloc - (uint64_t)&reference_stub,  // offsetof(ms_dos_stub, e_minalloc)
		sizeof(reference_stub.e_minalloc)
	);
	printf("0x%-30.2X %s0x%-30.2X%s\n", reference_stub.e_minalloc, color_fmt, hdr->e_minalloc, default_color);

	color_fmt = (hdr->e_maxalloc != reference_stub.e_maxalloc) ? diff_color : default_color;
	printf(
		"%-16s 0x%-6.02llX 0x%-6.02lX ",
		"e_maxalloc",
		(uint64_t)&reference_stub.e_maxalloc - (uint64_t)&reference_stub,  // offsetof(ms_dos_stub, e_maxalloc)
		sizeof(reference_stub.e_maxalloc)
	);
	printf("0x%-30.2X %s0x%-30.2X%s\n", reference_stub.e_maxalloc, color_fmt, hdr->e_maxalloc, default_color);

	color_fmt = (hdr->e_ss != reference_stub.e_ss) ? diff_color : default_color;
	printf(
		"%-16s 0x%-6.02llX 0x%-6.02lX ",
		"e_ss",
		(uint64_t)&reference_stub.e_ss - (uint64_t)&reference_stub,  // offsetof(ms_dos_stub, e_ss)
		sizeof(reference_stub.e_ss)
	);
	printf("0x%-30.2X %s0x%-30.2X%s\n", reference_stub.e_ss, color_fmt, hdr->e_ss, default_color);

	color_fmt = (hdr->e_sp != reference_stub.e_sp) ? diff_color : default_color;
	printf(
		"%-16s 0x%-6.02llX 0x%-6.02lX ",
		"e_sp",
		(uint64_t)&reference_stub.e_sp - (uint64_t)&reference_stub,  // offsetof(ms_dos_stub, e_sp)
		sizeof(reference_stub.e_sp)
	);
	printf("0x%-30.2X %s0x%-30.2X%s\n", reference_stub.e_sp, color_fmt, hdr->e_sp, default_color);

	color_fmt = (hdr->e_csum != reference_stub.e_csum) ? diff_color : default_color;
	printf(
		"%-16s 0x%-6.02llX 0x%-6.02lX ",
		"e_csum",
		(uint64_t)&reference_stub.e_csum - (uint64_t)&reference_stub,  // offsetof(ms_dos_stub, e_csum)
		sizeof(reference_stub.e_csum)
	);
	printf("0x%-30.2X %s0x%-30.2X%s\n", reference_stub.e_csum, color_fmt, hdr->e_csum, default_color);

	color_fmt = (hdr->e_ip != reference_stub.e_ip) ? diff_color : default_color;
	printf(
		"%-16s 0x%-6.02llX 0x%-6.02lX ",
		"e_ip",
		(uint64_t)&reference_stub.e_ip - (uint64_t)&reference_stub,  // offsetof(ms_dos_stub, e_ip)
		sizeof(reference_stub.e_ip)
	);
	printf("0x%-30.2X %s0x%-30.2X%s\n", reference_stub.e_ip, color_fmt, hdr->e_ip, default_color);

	color_fmt = (hdr->e_cs != reference_stub.e_cs) ? diff_color : default_color;
	printf(
		"%-16s 0x%-6.02llX 0x%-6.02lX ",
		"e_cs",
		(uint64_t)&reference_stub.e_cs - (uint64_t)&reference_stub,  // offsetof(ms_dos_stub, e_cs)
		sizeof(reference_stub.e_cs)
	);
	printf("0x%-30.2X %s0x%-30.2X%s\n", reference_stub.e_cs, color_fmt, hdr->e_cs, default_color);

	color_fmt = (hdr->e_lfarlc != reference_stub.e_lfarlc) ? diff_color : default_color;
	printf(
		"%-16s 0x%-6.02llX 0x%-6.02lX ",
		"e_lfarlc",
		(uint64_t)&reference_stub.e_lfarlc - (uint64_t)&reference_stub,  // offsetof(ms_dos_stub, e_lfarlc)
		sizeof(reference_stub.e_lfarlc)
	);
	printf("0x%-30.2X %s0x%-30.2X%s\n", reference_stub.e_lfarlc, color_fmt, hdr->e_lfarlc, default_color);
	
	color_fmt = (hdr->e_ovno != reference_stub.e_ovno) ? diff_color : default_color;
	printf(
		"%-16s 0x%-6.02llX 0x%-6.02lX ",
		"e_ovno",
		(uint64_t)&reference_stub.e_ovno - (uint64_t)&reference_stub,  // offsetof(ms_dos_stub, e_ovno)
		sizeof(reference_stub.e_ovno)
	);
	printf("0x%-30.2X %s0x%-30.2X%s\n", reference_stub.e_ovno, color_fmt, hdr->e_ovno, default_color);
	
	color_fmt = memcmp(&(hdr->e_res), &(reference_stub.e_res), sizeof(reference_stub.e_res)) != 0 ? diff_color : default_color;
	printf(
		"%-16s 0x%-6.02llX 0x%-6.02lX",
		"e_res",
		(uint64_t)&reference_stub.e_res - (uint64_t)&reference_stub,  // offsetof(ms_dos_stub, e_res)
		sizeof(reference_stub.e_res)
	);
	for (int i = 0; i < sizeof(reference_stub.e_res) / sizeof(reference_stub.e_res[0]); ++i)
	{
		printf(" %02X", reference_stub.e_res[i]);
	}
	printf("%s", "                     ");
	for (int i = 0; i < sizeof(reference_stub.e_res) / sizeof(reference_stub.e_res[0]); ++i)
	{
		color_fmt = (hdr->e_res[i] != reference_stub.e_res[i]) ? diff_color : default_color;
		printf(" %s%02X%s", color_fmt, hdr->e_res[i], default_color);
	}
	printf("%s", "\n");
	
	color_fmt = (hdr->e_oemid != reference_stub.e_oemid) ? diff_color : default_color;
	printf(
		"%-16s 0x%-6.02llX 0x%-6.02lX ",
		"e_oemid",
		(uint64_t)&reference_stub.e_oemid - (uint64_t)&reference_stub,  // offsetof(ms_dos_stub, e_oemid)
		sizeof(reference_stub.e_oemid)
	);
	printf("0x%-30.2X %s0x%-30.2X%s\n", reference_stub.e_oemid, color_fmt, hdr->e_oemid, default_color);
	
	color_fmt = (hdr->e_oeminfo != reference_stub.e_oeminfo) ? diff_color : default_color;
	printf(
		"%-16s 0x%-6.02llX 0x%-6.02lX ",
		"e_oeminfo",
		(uint64_t)&reference_stub.e_oeminfo - (uint64_t)&reference_stub,  // offsetof(ms_dos_stub, e_oeminfo)
		sizeof(reference_stub.e_oeminfo)
	);
	printf("0x%-30.2X %s0x%-30.2X%s\n", reference_stub.e_oeminfo, color_fmt, hdr->e_oeminfo, default_color);
	
	printf(
		"%-16s 0x%-6.02llX 0x%-6.02lX",
		"e_res2",
		(uint64_t)&reference_stub.e_res2 - (uint64_t)&reference_stub,  // offsetof(ms_dos_stub, e_res2)
		sizeof(reference_stub.e_res2)
	);
	for (int i = 0; i < sizeof(reference_stub.e_res2) / sizeof(reference_stub.e_res2[0]); ++i)
	{
		printf(" %02X", reference_stub.e_res2[i]);
	}
	printf("%s", "   ");
	for (int i = 0; i < sizeof(reference_stub.e_res2) / sizeof(reference_stub.e_res2[0]); ++i)
	{
		color_fmt = (hdr->e_res2[i] != reference_stub.e_res2[i]) ? diff_color : default_color;
		printf(" %s%02X%s", color_fmt, hdr->e_res2[i], default_color);
	}
	printf("%s", "\n");


	color_fmt = (hdr->e_lfanew != reference_stub.e_lfanew) ? diff_color : default_color;
	printf(
		"%-16s 0x%-6.02llX 0x%-6.02lX ",
		"e_lfanew",
		(uint64_t)&reference_stub.e_lfanew - (uint64_t)&reference_stub,  // offsetof(ms_dos_stub, e_lfanew)
		sizeof(reference_stub.e_lfanew)
	);
	printf("0x%-30.2X %s0x%-30.2X%s\n", reference_stub.e_lfanew, color_fmt, hdr->e_lfanew, default_color);

	printf(
		"%-16s 0x%-6.02llX 0x%-6.02lX",
		"dos_program",
		(uint64_t)&reference_stub.dos_program - (uint64_t)&reference_stub,  // offsetof(ms_dos_stub, dos_program)
		sizeof(reference_stub.dos_program)
	);

	for (int pos = 0; pos < sizeof(reference_stub.dos_program) / sizeof(reference_stub.dos_program[0]); pos += 8)
	{
		if (pos > 0)
		{
			printf("%s%s", "\n", "                                  ");
		}
		for (int i = pos; i < (pos + 8); ++i)
		{
			printf(" %02hhX", reference_stub.dos_program[i]);
		}
		printf("%s", "         ");
		for (int i = pos; i < (pos + 8); ++i)
		{
			color_fmt = (hdr->dos_program[i] != reference_stub.dos_program[i]) ? diff_color : default_color;
			printf(" %s%02hhX%s", color_fmt, hdr->dos_program[i], default_color);
		}
	}
	printf("%s", "\n");

	return;
}
