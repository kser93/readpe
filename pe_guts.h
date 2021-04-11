#ifndef _PE_READER_H
#define _PE_READER_H

#include <stdint.h>

#define DOSMAGIC 0x5a4d
#define PEMAGIC 0x4550
#define IMAGE_NUMBEROF_DIRECTORY_ENTRIES 16  // TODO: find out what to do with variable number of DIRECTORY_ENTRIES
#define IMAGE_SIZEOF_SHORT_NAME 8

typedef struct image_dos_header_t
{
	/* DOS header fields - always at offset zero in the EXE file. */
	uint16_t e_magic; /* Magic number, 0x5a4d. (DOSMAGIC above) */
	uint16_t e_cblp; /* uint8_ts on last page of file, 0x90. */
	uint16_t e_cp; /* Pages in file, 0x3. */
	uint16_t e_crlc; /* Relocations, 0x0. */
	uint16_t e_cparhdr; /* Size of header in paragraphs, 0x4. */
	uint16_t e_minalloc; /* Minimum extra paragraphs needed, 0x0. */
	uint16_t e_maxalloc; /* Maximum extra paragraphs needed, 0xFFFF. */
	uint16_t e_ss; /* Initial (relative) SS value, 0x0. */
	uint16_t e_sp; /* Initial SP value, 0xb8. */
	uint16_t e_csum; /* Checksum, 0x0. */
	uint16_t e_ip; /* Initial IP value, 0x0. */
	uint16_t e_cs; /* Initial (relative) CS value, 0x0. */
	uint16_t e_lfarlc; /* File address of relocation table, 0x40. */
	uint16_t e_ovno; /* Overlay number, 0x0. */
	uint16_t e_res[4]; /* Reserved uint16_ts, all 0x0. */
	uint16_t e_oemid; /* OEM identifier (for e_oeminfo), 0x0. */
	uint16_t e_oeminfo; /* OEM information; e_oemid specific, 0x0. */
	uint16_t e_res2[10]; /* Reserved uint16_ts, all 0x0. */
	uint32_t e_lfanew; /* File address of new exe header, usually 0x80. */
} image_dos_header_t;

typedef struct image_file_header_t {
	uint16_t Machine;
	uint16_t NumberOfSections;
	uint32_t TimeDateStamp;
	uint32_t PointerToSymbolTable;
	uint32_t NumberOfSymbols;
	uint16_t SizeOfOptionalHeader;
	uint16_t Characteristics;
} image_file_header_t;

typedef struct image_data_directory_t {
	uint32_t VirtualAddress;
	uint32_t Size;
} image_data_directory_t;

typedef struct image_optional_header32_t {
	uint16_t Magic;
	uint8_t MajorLinkerVersion;
	uint8_t MinorLinkerVersion;
	uint32_t SizeOfCode;
	uint32_t SizeOfInitializedData;
	uint32_t SizeOfUninitializedData;
	uint32_t AddressOfEntryPoint;
	uint32_t BaseOfCode;
	uint32_t BaseOfData;
	uint32_t ImageBase;
	uint32_t SectionAlignment;
	uint32_t FileAlignment;
	uint16_t MajorOperatingSystemVersion;
	uint16_t MinorOperatingSystemVersion;
	uint16_t MajorImageVersion;
	uint16_t MinorImageVersion;
	uint16_t MajorSubsystemVersion;
	uint16_t MinorSubsystemVersion;
	uint32_t Win32VersionValue;
	uint32_t SizeOfImage;
	uint32_t SizeOfHeaders;
	uint32_t CheckSum;
	uint16_t Subsystem;
	uint16_t DllCharacteristics;
	uint32_t SizeOfStackReserve;
	uint32_t SizeOfStackCommit;
	uint32_t SizeOfHeapReserve;
	uint32_t SizeOfHeapCommit;
	uint32_t LoaderFlags;
	uint32_t NumberOfRvaAndSizes;
	image_data_directory_t DataDirectory[IMAGE_NUMBEROF_DIRECTORY_ENTRIES];
} image_optional_header32_t;

typedef struct image_optional_header64_t {
	uint16_t Magic;
	uint8_t MajorLinkerVersion;
	uint8_t MinorLinkerVersion;
	uint32_t SizeOfCode;
	uint32_t SizeOfInitializedData;
	uint32_t SizeOfUninitializedData;
	uint32_t AddressOfEntryPoint;
	uint32_t BaseOfCode;
	uint64_t ImageBase;
	uint32_t SectionAlignment;
	uint32_t FileAlignment;
	uint16_t MajorOperatingSystemVersion;
	uint16_t MinorOperatingSystemVersion;
	uint16_t MajorImageVersion;
	uint16_t MinorImageVersion;
	uint16_t MajorSubsystemVersion;
	uint16_t MinorSubsystemVersion;
	uint32_t Win32VersionValue;
	uint32_t SizeOfImage;
	uint32_t SizeOfHeaders;
	uint32_t CheckSum;
	uint16_t Subsystem;
	uint16_t DllCharacteristics;
	uint64_t SizeOfStackReserve;
	uint64_t SizeOfStackCommit;
	uint64_t SizeOfHeapReserve;
	uint64_t SizeOfHeapCommit;
	uint32_t LoaderFlags;
	uint32_t NumberOfRvaAndSizes;
	image_data_directory_t DataDirectory[IMAGE_NUMBEROF_DIRECTORY_ENTRIES];
} image_optional_header64_t;

typedef struct image_nt_headers32_t {
	uint32_t signature;
	image_file_header_t file_header;
	image_optional_header32_t optional_header;
} image_nt_headers32_t;

typedef struct image_nt_headers64_t {
	uint32_t signature;
	image_file_header_t file_header;
	image_optional_header64_t optional_header;
} image_nt_headers64_t;

typedef struct image_section_header_t {
	uint8_t Name[IMAGE_SIZEOF_SHORT_NAME];
	union {
		uint32_t PhysicalAddress;
		uint32_t VirtualSize;
	} Misc;
	uint32_t VirtualAddress;
	uint32_t SizeOfRawData;
	uint32_t PointerToRawData;
	uint32_t PointerToRelocations;
	uint32_t PointerToLinenumbers;
	uint16_t NumberOfRelocations;
	uint16_t NumberOfLinenumbers;
	uint32_t Characteristics;
} image_section_header_t;

void dump_dos_header(image_dos_header_t* hdr);

#endif /* _PE_READER_H */
