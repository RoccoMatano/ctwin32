################################################################################
#
# Copyright 2021-2026 Rocco Matano
# SPDX-License-Identifier: MIT
#
################################################################################
#
# This script dumps DLL and function names of an import library.
#
################################################################################

import sys
from ctwin32 import (
    IMAGE_ARCHIVE_START,
    IMAGE_ARCHIVE_START_SIZE,
    IMAGE_FILE_MACHINE_UNKNOWN,
    )
from ctwin32.wtypes import CHAR, DWORD, Struct, WORD
from ctwin32.dbghelp import UnDecorateSymbolName

################################################################################

class IMAGE_ARCHIVE_MEMBER_HEADER(Struct):
    _fields_ = (
        ("Name", CHAR * 16),
        ("Date", CHAR * 12),
        ("UserID", CHAR * 6),
        ("GroupID", CHAR * 6),
        ("Mode", CHAR * 8),
        ("Size", CHAR * 10),
        ("EndHeader", CHAR * 2),
    )

################################################################################

IMPORT_OBJECT_HDR_SIG2 = 0xffff

class IMPORT_OBJECT_HEADER(Struct):
    _fields_ = (
        ("Sig1",          WORD), # Must be IMAGE_FILE_MACHINE_UNKNOWN
        ("Sig2",          WORD), # Must be IMPORT_OBJECT_HDR_SIG2
        ("Version",       WORD),
        ("Machine",       WORD),
        ("TimeDateStamp", DWORD),
        ("SizeOfData",    DWORD),
        ("OrdinalOrHint", WORD),
        ("TypeNameRes",   WORD),
        )

################################################################################

def dump_import_lib(lib_name, do_undec):
    with open(lib_name, "rb") as f:
        data = f.read()

    offs = IMAGE_ARCHIVE_START_SIZE
    if data[:offs] != IMAGE_ARCHIVE_START:
        raise ValueError(f"not a library: {lib_name}")

    iamh_size = IMAGE_ARCHIVE_MEMBER_HEADER._size_
    ioh_size = IMPORT_OBJECT_HEADER._size_
    data_end = len(data) - iamh_size

    print(f"dump of {lib_name}:\n")

    while offs < data_end:
        a_end = offs + iamh_size
        ahdr = IMAGE_ARCHIVE_MEMBER_HEADER.from_buffer_copy(data[offs:a_end])
        obj_size = int(ahdr.Size)
        if obj_size < ioh_size:
            raise ValueError("corrupt library: obj_size < IMPORT_OBJECT_HEADER")

        ioh_offs = offs + iamh_size
        bites = data[ioh_offs: ioh_offs + ioh_size]
        ioh = IMPORT_OBJECT_HEADER.from_buffer_copy(bites)
        sig_valid = (
            ioh.Sig1 == IMAGE_FILE_MACHINE_UNKNOWN and
            ioh.Sig2 == IMPORT_OBJECT_HDR_SIG2
            )
        if sig_valid:
            start = ioh_offs + ioh_size
            bites = data[start:ioh_offs + obj_size]
            sym, dll, *_ = map(bytes.decode, bites.split(b"\0"))
            if do_undec and sym[0] == "?":
                uds_name = f" ({UnDecorateSymbolName(sym)}"
            else:
                uds_name = ""
            print(f"{dll} {sym}{uds_name}")

        member_size = obj_size + iamh_size
        offs += member_size + (member_size & 1)  # round up to even

################################################################################

if __name__ == "__main__":
    dump_import_lib(sys.argv[1], len(sys.argv) > 2)

################################################################################
