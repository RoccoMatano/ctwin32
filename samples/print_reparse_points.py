################################################################################
#
# Copyright 2021-2026 Rocco Matano
# SPDX-License-Identifier: MIT
#
################################################################################

import os
import ctypes
import ctwin32
from ctwin32 import (
    suppress_winerr,
    ERROR_MORE_DATA,
    FILE_ATTRIBUTE_REPARSE_POINT,
    FILE_FLAG_OPEN_REPARSE_POINT,
    FILE_FLAG_BACKUP_SEMANTICS,
    IO_REPARSE_TAG_APPEXECLINK,
    IO_REPARSE_TAG_LX_SYMLINK,
    IO_REPARSE_TAG_MOUNT_POINT,
    IO_REPARSE_TAG_SYMLINK,
    )
from ctwin32.wtypes import (
    CHAR,
    Struct,
    ULONG,
    USHORT,
    WCHAR,
    WCHAR_SIZE,
    wchar_len_sz,
    )
from ctwin32.kernel import create_file, DeviceIoControl, iter_dir

################################################################################

class REPARSE_DATA_HEADER(Struct):
    _fields_ = (
        ("ReparseTag", ULONG),
        ("ReparseDataLength", USHORT),
        ("Reserved", USHORT),
        )

class RP_DATA_SYMLINK(Struct):
    _fields_ = (
        ("_hdr", REPARSE_DATA_HEADER),
        ("SubstituteNameOffset", USHORT),
        ("SubstituteNameLength", USHORT),
        ("PrintNameOffset", USHORT),
        ("PrintNameLength", USHORT),
        ("Flags", ULONG),
        ("PathBuffer", WCHAR * 1),
        )
    _anonymous_ = ("_hdr",)

class RP_DATA_MOUNTPOINT(Struct):
    _fields_ = (
        ("_hdr", REPARSE_DATA_HEADER),
        ("SubstituteNameOffset", USHORT),
        ("SubstituteNameLength", USHORT),
        ("PrintNameOffset", USHORT),
        ("PrintNameLength", USHORT),
        ("PathBuffer", WCHAR * 1),
        )
    _anonymous_ = ("_hdr",)

class RP_DATA_APPEXECLINK(Struct):
    _fields_ = (
        ("_hdr", REPARSE_DATA_HEADER),
        ("Version", ULONG),
        ("StringList", WCHAR * 1),
        # 'StringList' is a multistring (Consecutive UTF-16 strings each ending
        # with a NUL). There are normally 4 strings here. Ex:
        # Package ID : L"Microsoft.WindowsTerminal_8wekyb3d8bbwe"
        # Entry Point: L"Microsoft.WindowsTerminal_8wekyb3d8bbwe!App"
        # Executable : L"<PATH>\wt.exe"
        # Appl. Type : L"0"  # int as string. "0" = Desktop bridge application;
        #                      else sandboxed UWP application
        )
    _anonymous_ = ("_hdr",)

class RP_DATA_LX_SYMLINK(Struct):
    _fields_ = (
        ("_hdr", REPARSE_DATA_HEADER),
        ("Version", ULONG),
        ("Target", CHAR * 1),
        )
    _anonymous_ = ("_hdr",)

FSCTL_GET_REPARSE_POINT = 0x000900a8

################################################################################

def readlink(link, *, get_subst_name=False):
    flags = FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS
    with create_file(link, 0, 0, flags) as hdl:
        size = 512
        while True:
            with suppress_winerr(ERROR_MORE_DATA):
                buf = DeviceIoControl(hdl, FSCTL_GET_REPARSE_POINT, None, size)
                break
            size *= 2
    tag = ULONG.from_buffer(buf).value
    addr = ctypes.addressof(buf)

    if tag == IO_REPARSE_TAG_APPEXECLINK:
        addr += RP_DATA_APPEXECLINK.StringList.offset
        for _ in range(2):
            addr += wchar_len_sz(ctypes.wstring_at(addr)) * WCHAR_SIZE
        return ctypes.wstring_at(addr)

    if tag == IO_REPARSE_TAG_LX_SYMLINK:
        addr += RP_DATA_LX_SYMLINK.Target.offset
        return ctypes.string_at(addr).decode(errors="backslashreplace")

    if tag == IO_REPARSE_TAG_SYMLINK:
        rpd = RP_DATA_SYMLINK.from_buffer(buf)
        path_buff = addr + RP_DATA_SYMLINK.PathBuffer.offset

    elif tag == IO_REPARSE_TAG_MOUNT_POINT:
        rpd = RP_DATA_MOUNTPOINT.from_buffer(buf)
        path_buff = addr + RP_DATA_MOUNTPOINT.PathBuffer.offset

    else:
        raise RuntimeError(f"unhandled tag: 0x{tag:08x}")

    if get_subst_name:
        saddr = path_buff + rpd.SubstituteNameOffset
        slen = rpd.SubstituteNameLength // WCHAR_SIZE
    else:
        saddr = path_buff + rpd.PrintNameOffset
        slen = rpd.PrintNameLength // WCHAR_SIZE

    return ctypes.wstring_at(saddr, slen)

################################################################################

reparse_tags = {
    v: k for k, v in vars(ctwin32).items() if k.startswith("IO_REPARSE_TAG_")
    }
follow = (
    IO_REPARSE_TAG_APPEXECLINK,
    IO_REPARSE_TAG_LX_SYMLINK,
    IO_REPARSE_TAG_MOUNT_POINT,
    IO_REPARSE_TAG_SYMLINK,
    )

for directory, info in iter_dir(os.environ["SYSTEMDRIVE"]):
    if info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT:
        rpp = rf"{directory}\{info.cFileName}"
        tag = reparse_tags.get(
            info.dwReserved0,
            f"UNKNOWN: 0x{info.dwReserved0:08x}"
            )
        if info.dwReserved0 in follow:
            print(f"{tag:32} {rpp}\n    -> {readlink(rpp)}")
        else:
            print(f"{tag:32} {rpp}")

################################################################################
