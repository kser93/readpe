import requests
import xml.etree.ElementTree as ET
from bs4 import BeautifulSoup

characteristics = dict()

r = requests.get('https://docs.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-image_section_header')
soup = BeautifulSoup(r.text, 'html.parser')
flag_table = soup.find('main').find(text='Flag').find_parent('table')

for row in flag_table.findAll('tr'):
    if row.find(text='Flag') is not None:
        continue

    nameval_el, comment_el = row.findAll('td')
    try:
        comment = comment_el.text.replace('\n', '')
    except AttributeError:
        comment = ''

    try:
        name_el, val_el = nameval_el.findAll('dt')
    except ValueError:
        val_el = nameval_el.find('dt')
        try:
            value = val_el.text
        except AttributeError:
            value = 'UNKNOWN'

        name = '_'.join(['RESERVED', value.replace('0x', '').replace('0X', '')])

    else:
        try:
            name = name_el.find('b').text
        except AttributeError:
            name = 'RESERVED'

        try:
            value = val_el.text
        except AttributeError:
            value = 'UNKNOWN'

    characteristics[name] = int(value, 16)

ref_characteristics = {
    'RESERVED_00000000': 0,
    'RESERVED_00000001': 1,
    'RESERVED_00000002': 2,
    'RESERVED_00000004': 4,
    'IMAGE_SCN_TYPE_NO_PAD': 8,
    'RESERVED_00000010': 16,
    'IMAGE_SCN_CNT_CODE': 32,
    'IMAGE_SCN_CNT_INITIALIZED_DATA': 64,
    'IMAGE_SCN_CNT_UNINITIALIZED_DATA': 128,
    'IMAGE_SCN_LNK_OTHER': 256,
    'IMAGE_SCN_LNK_INFO': 512,
    'RESERVED_00000400': 1024,
    'IMAGE_SCN_LNK_REMOVE': 2048,
    'IMAGE_SCN_LNK_COMDAT': 4096,
    'RESERVED_00002000': 8192,
    'IMAGE_SCN_NO_DEFER_SPEC_EXC': 16384,
    'IMAGE_SCN_GPREL': 32768,
    'RESERVED_00010000': 65536,
    'IMAGE_SCN_MEM_PURGEABLE': 131072,
    'IMAGE_SCN_MEM_LOCKED': 262144,
    'IMAGE_SCN_MEM_PRELOAD': 524288,
    'IMAGE_SCN_ALIGN_1BYTES': 1048576,
    'IMAGE_SCN_ALIGN_2BYTES': 2097152,
    'IMAGE_SCN_ALIGN_4BYTES': 3145728,
    'IMAGE_SCN_ALIGN_8BYTES': 4194304,
    'IMAGE_SCN_ALIGN_16BYTES': 5242880,
    'IMAGE_SCN_ALIGN_32BYTES': 6291456,
    'IMAGE_SCN_ALIGN_64BYTES': 7340032,
    'IMAGE_SCN_ALIGN_128BYTES': 8388608,
    'IMAGE_SCN_ALIGN_256BYTES': 9437184,
    'IMAGE_SCN_ALIGN_512BYTES': 10485760,
    'IMAGE_SCN_ALIGN_1024BYTES': 11534336,
    'IMAGE_SCN_ALIGN_2048BYTES': 12582912,
    'IMAGE_SCN_ALIGN_4096BYTES': 13631488,
    'IMAGE_SCN_ALIGN_8192BYTES': 14680064,
    'IMAGE_SCN_LNK_NRELOC_OVFL': 16777216,
    'IMAGE_SCN_MEM_DISCARDABLE': 33554432,
    'IMAGE_SCN_MEM_NOT_CACHED': 67108864,
    'IMAGE_SCN_MEM_NOT_PAGED': 134217728,
    'IMAGE_SCN_MEM_SHARED': 268435456,
    'IMAGE_SCN_MEM_EXECUTE': 536870912,
    'IMAGE_SCN_MEM_READ': 1073741824,
    'IMAGE_SCN_MEM_WRITE': 2147483648
}

print(characteristics == ref_characteristics)
