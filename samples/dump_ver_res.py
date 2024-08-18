################################################################################
#
# Copyright 2021-2024 Rocco Matano
# SPDX-License-Identifier: MIT
#
################################################################################

# In contrast to sample `py_ver.py` where functions from `version.dll` are used
# to get information from version resources, this sample shows how to parse
# version resources `by hand`. This can be usefull to get string entries that
# do not use the standard names (see ctwin32.version._str_info_names). You might
# try `dump_ver_res.py %SystemRoot%\system32` to see lots of output.

import os
import sys
import ctypes
import pathlib
from types import SimpleNamespace
from pprint import pprint
from ctwin32 import (
    kernel,
    suppress_winerr,
    ERROR_ACCESS_DENIED,
    ERROR_BAD_EXE_FORMAT,
    ERROR_FILE_NOT_FOUND,
    ERROR_FILE_INVALID,
    ERROR_RESOURCE_DATA_NOT_FOUND,
    ERROR_RESOURCE_TYPE_NOT_FOUND,
    ERROR_SHARING_VIOLATION,
    LOAD_LIBRARY_AS_DATAFILE,
    LOAD_LIBRARY_AS_IMAGE_RESOURCE,
    RT_VERSION,
    )
from ctwin32.wtypes import (
    PSTR,
    PVOID,
    WORD,
    )
from ctwin32.version import VS_FIXEDFILEINFO

################################################################################

# See these pages from the `Old New Thing` (Raymond Chen) blog:
# https://devblogs.microsoft.com/oldnewthing/20061220-15/?p=28653
# https://devblogs.microsoft.com/oldnewthing/20061221-02/?p=28643
# https://devblogs.microsoft.com/oldnewthing/20061222-00/?p=28623

class VS_NODE(ctypes.Structure):
    _fields_ = (
        ("node_size", WORD),
        ("value_size", WORD),
        ("type", WORD),
        # followed by zero terminated name (WCHAR[])
        # followed by DWORD padding
        )

################################################################################

def parse_version_resource(ver_res_bytes):
    # A lot of version resources out there contain minor deviations from the
    # actual rules. This code tries to find the right balance between requiring
    # a minimum of conformance and forgiving those little glitches.

    ############################################################################

    def dword_align(x):
        return (x + 3) & (~ 3)

    ############################################################################

    def parse_ver_node(ver_res_bytes, offs):
        info = VS_NODE.from_buffer_copy(ver_res_bytes, offs)
        end = offs + info.node_size
        offs += ctypes.sizeof(VS_NODE)
        addr = ctypes.cast(PSTR(ver_res_bytes), PVOID).value + offs
        strng = ctypes.wstring_at(addr)
        return strng, dword_align(offs + (len(strng) + 1) * 2), end, info

    ############################################################################

    INVALID = ValueError("invalid version resource data")
    HEX_SET = set("abcdefABCDEF0123456789")
    name, offs, end_root, root = parse_ver_node(ver_res_bytes, 0)
    valid = (
        root.type == 0 and
        root.value_size == ctypes.sizeof(VS_FIXEDFILEINFO) and
        name == "VS_VERSION_INFO"
        )
    if not valid:
        raise INVALID

    fix = VS_FIXEDFILEINFO.from_buffer_copy(ver_res_bytes, offs)
    offs += ctypes.sizeof(VS_FIXEDFILEINFO)
    fix = {f: getattr(fix, f) for f, _ in fix._fields_}
    result = SimpleNamespace(fixed_info=fix, string_info={})
    # sizeof(VS_FIXEDFILEINFO) is a multiple of DWORDs -> no padding required

    while offs < end_root:
        name, offs, end_strings, _ = parse_ver_node(ver_res_bytes, offs)
        if name != "StringFileInfo":
            # unknown or unused (i.e. VarFileInfo) node type -> skip it
            # padding between nodes is not part of 'node_size' -> dword_align
            offs = dword_align(end_strings)
            continue

        while offs < end_strings:
            name, offs, end_translation, _ = parse_ver_node(ver_res_bytes, offs)
            if len(name) != 8 or not set(name).issubset(HEX_SET):
                raise INVALID
            translation = name[:4], name[4:]
            pairs = {}
            while offs < end_translation:
                key, offs, val_end, _ = parse_ver_node(ver_res_bytes, offs)

                # Buggy resource compilers often write the wrong value for
                # value_size. so we don't trust that and simply work with
                # what's left. But this remaining part has to have an even
                # length if we want to decode it as utf-16.
                size = (val_end - offs) & ~(0x1)
                val = ver_res_bytes[offs : offs + size]
                val = val.decode("utf-16").rstrip("\0")

                # padding between nodes is not part of 'node_size'
                offs = dword_align(val_end)
                pairs[key] = val
            result.string_info[translation] = pairs

    return result

################################################################################

EXPECTED_ERR = (
    ERROR_ACCESS_DENIED,
    ERROR_BAD_EXE_FORMAT,
    ERROR_FILE_NOT_FOUND,
    ERROR_FILE_INVALID,
    ERROR_RESOURCE_DATA_NOT_FOUND,
    ERROR_RESOURCE_TYPE_NOT_FOUND,
    ERROR_SHARING_VIOLATION,
    )
LOLI_FLAGS = LOAD_LIBRARY_AS_DATAFILE | LOAD_LIBRARY_AS_IMAGE_RESOURCE

def find_ver_res_in_file(fname):
    with suppress_winerr(*EXPECTED_ERR):
        with kernel.LoadLibraryEx(str(fname), LOLI_FLAGS) as hmod:
            for name in kernel.get_resource_names(hmod, RT_VERSION):
                addr, size = kernel.get_resource_info(hmod, name, RT_VERSION)
                yield ctypes.string_at(addr, size)

################################################################################

if __name__ == "__main__":
    start_path = os.path.expandvars(sys.argv[1]) if len(sys.argv) > 1 else "."
    p = pathlib.Path(start_path).resolve()
    for file in (e for e in p.rglob("*") if e.is_file()):
        try:
            for ver_res_bytes in find_ver_res_in_file(file):
                ver_res = parse_version_resource(ver_res_bytes)
                print(f"\n{75 * '-'}\n\n{file}\n\nfixed:")
                for name, value in ver_res.fixed_info.items():
                    print(f"    {name:18} = 0x{value:x}")
                print("\nstrings:")
                pprint(ver_res.string_info)
                print()
        except Exception as err:
            print(file, err)
            raise

################################################################################
