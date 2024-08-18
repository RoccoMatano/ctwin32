################################################################################
#
# Copyright 2021-2024 Rocco Matano
# SPDX-License-Identifier: MIT
#
################################################################################

# This sample demonstrates how to extract icons from *.ico files and from
# executable files (*.exe, *.dll etc.). It prints the extracted data in the
# format that is used in ctwin32.wndcls to store such data in python code
# (lzma-compressed and b85-encoded). You can compare the output of running
# 'python extract_ico.py ..\doc\images\ctwin32.ico 1' with the definition of
# ctwin32.wndcls._ctwin32_icon.

################################################################################

import sys
from types import SimpleNamespace
from ctwin32 import (
    ctypes,
    kernel,
    wndcls,
    LOAD_LIBRARY_AS_IMAGE_RESOURCE,
    LOAD_LIBRARY_AS_DATAFILE,
    RT_GROUP_ICON,
    RT_ICON,
    )
from ctwin32.wtypes import BYTE, WORD, DWORD

################################################################################

# https://docs.microsoft.com/en-us/previous-versions/ms997538(v=msdn.10)

class ICONDIR_HEADER(ctypes.Structure):
    _fields_ = (
        ("reserved", WORD),
        ("type", WORD),
        ("count", WORD),
        )

# ico file
class ICONDIRENTRY(ctypes.Structure):
    _fields_ = (
        ("width", BYTE),
        ("height", BYTE),
        ("colors", BYTE),
        ("reserved", BYTE),
        ("planes", WORD),
        ("bitcount", WORD),
        ("bytesinres", DWORD),
        ("imgoffest", DWORD),
        )

# icon resource
class GRPICONDIRENTRY(ctypes.Structure):
    _pack_ = 2
    _fields_ = (
        ("width", BYTE),
        ("height", BYTE),
        ("colors", BYTE),
        ("reserved", BYTE),
        ("planes", WORD),
        ("bitcount", WORD),
        ("bytesinres", DWORD),
        ("ico_id", WORD),
        )

################################################################################

def print_lzma_b85(data):
    b85 = wndcls.to_lzb85(data)
    llen = 72
    while len(b85) > llen:
        print(b85[:llen])
        b85 = b85[llen:]
    print(b85)

################################################################################

def get_ico_file_info(filename):
    with open(filename, "rb") as file:
        dta = file.read(ctypes.sizeof(ICONDIR_HEADER))
        idh = ICONDIR_HEADER.from_buffer_copy(dta)
        ICON_ENTRIES = ICONDIRENTRY * idh.count
        dta = file.read(ctypes.sizeof(ICON_ENTRIES))
        entries = ICON_ENTRIES.from_buffer_copy(dta)
        image_info = [
            SimpleNamespace(
                width=e.width if e.width else 256,
                height=e.height if e.height else 256,
                colors=e.colors if e.colors else 1 << min(e.bitcount, 24),
                size=e.bytesinres,
                offset=e.imgoffest,
                )
            for e in entries
            ]
        return [(0, image_info)]

################################################################################

def extract_from_ico(filename, fmt):
    with open(filename, "rb") as file:
        file.seek(fmt.offset)
        print_lzma_b85(file.read(fmt.size))

################################################################################

def get_executable_file_info(hmod):
    ids = kernel.get_resource_names(hmod, RT_GROUP_ICON)
    res = []
    for i in ids:
        addr, size = kernel.get_resource_info(hmod, i, RT_GROUP_ICON)
        idh = ICONDIR_HEADER.from_address(addr)
        addr += ctypes.sizeof(ICONDIR_HEADER)
        ICON_ENTRIES = GRPICONDIRENTRY * idh.count
        entries = ICON_ENTRIES.from_address(addr)
        image_info = [
            SimpleNamespace(
                width=e.width if e.width else 256,
                height=e.height if e.height else 256,
                colors=e.colors if e.colors else 1 << min(e.bitcount, 24),
                ico_id=e.ico_id,
                )
            for e in entries
            ]
        res.append((i, image_info))
    return res

################################################################################

def extract_from_executable(hmod, fmt):
    addr, size = kernel.get_resource_info(hmod, fmt.ico_id, RT_ICON)
    print_lzma_b85(ctypes.string_at(addr, size))

################################################################################

def print_info(infos):
    indent = "    " if len(infos) > 1 else ""
    for iid, fmts in infos:
        if indent:
            print(f"icon id {iid}:")
        for n, fmt in enumerate(fmts):
            w = fmt.width
            h = fmt.height
            c = fmt.colors
            c = str(c) if c < 1_000_000 else f"{c >> 20}M"
            print(f"{indent}format {n:2}: {w}.{h}.{c}")
    print()

################################################################################

def main():
    if len(sys.argv) < 2:
        print("need file name (icon or executable)", file=sys.stderr)
        return 1
    filename = sys.argv[1]

    # ============== gather info =================

    flags = LOAD_LIBRARY_AS_IMAGE_RESOURCE | LOAD_LIBRARY_AS_DATAFILE
    try:
        hmod = kernel.LoadLibraryEx(filename, flags)
    except OSError:
        hmod = None

    if hmod is None:
        infos = get_ico_file_info(filename)
    else:
        infos = get_executable_file_info(hmod)

    # === print info if no further arguments =====

    if len(sys.argv) == 2:
        print_info(infos)
        return 0

    # ======== process further arguments =========

    if len(infos) > 1:
        if len(sys.argv) == 3:
            print("need icon AND format ID", file=sys.stderr)
            return 2
        try:
            ico_id = int(sys.argv[2])
        except ValueError:
            # also allow string identifier
            ico_id = sys.argv[2]
        fmt_id = int(sys.argv[3])
    else:
        ico_id = infos[0][0]
        fmt_id = int(sys.argv[2])

    # ============= try to extract ===============

    for iid, fmts in infos:
        if iid == ico_id:
            fmt = fmts[fmt_id]
            break
    else:
        raise ValueError("invalid icon id")

    if hmod is None:
        extract_from_ico(filename, fmt)
    else:
        extract_from_executable(hmod, fmt)

    return 0

################################################################################

if __name__ == "__main__":
    sys.exit(main())

################################################################################
