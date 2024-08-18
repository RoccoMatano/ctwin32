################################################################################
#
# Copyright 2021-2024 Rocco Matano
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
    IO_REPARSE_TAG_SYMLINK,
    IO_REPARSE_TAG_MOUNT_POINT,
    )
from ctwin32.wtypes import (
    BYTE,
    ULONG,
    USHORT,
    WCHAR,
    )
from ctwin32.kernel import create_file, DeviceIoControl, iter_dir

################################################################################

class RP_DATA_SYMLINK(ctypes.Structure):
    _fields_ = (
        ("SubstituteNameOffset", USHORT),
        ("SubstituteNameLength", USHORT),
        ("PrintNameOffset", USHORT),
        ("PrintNameLength", USHORT),
        ("Flags", ULONG),
        ("PathBuffer", WCHAR * 1),
        )

class RP_DATA_MOUNTPOINT(ctypes.Structure):
    _fields_ = (
        ("SubstituteNameOffset", USHORT),
        ("SubstituteNameLength", USHORT),
        ("PrintNameOffset", USHORT),
        ("PrintNameLength", USHORT),
        ("PathBuffer", WCHAR * 1),
        )

class RP_DATA_GENERIC(ctypes.Structure):
    _fields_ = (
        ("DataBuffer", BYTE * 1),
        )

class RP_DATA_UN(ctypes.Union):
    _fields_ = (
        ("SymbolicLinkReparseBuffer", RP_DATA_SYMLINK),
        ("MountPointReparseBuffer", RP_DATA_MOUNTPOINT),
        ("GenericReparseBuffer", RP_DATA_GENERIC),
        )

class REPARSE_DATA_BUFFER(ctypes.Structure):
    _fields_ = (
        ("ReparseTag", ULONG),
        ("ReparseDataLength", USHORT),
        ("Reserved", USHORT),
        ("_anon", RP_DATA_UN),
        )
    _anonymous_ = ("_anon",)

FSCTL_GET_REPARSE_POINT = 0x000900a8

################################################################################

def readlink(link, get_subst_name=False):
    flags = FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS
    with create_file(link, 0, 0, flags) as hdl:
        size = 512
        while True:
            with suppress_winerr(ERROR_MORE_DATA):
                buf = DeviceIoControl(hdl, FSCTL_GET_REPARSE_POINT, None, size)
                break
            size *= 2
    rpd = REPARSE_DATA_BUFFER.from_buffer(buf)
    if rpd.ReparseTag == IO_REPARSE_TAG_SYMLINK:
        path_buff = (
            ctypes.addressof(rpd) +
            REPARSE_DATA_BUFFER.SymbolicLinkReparseBuffer.offset +
            RP_DATA_SYMLINK.PathBuffer.offset
            )
        src = rpd.SymbolicLinkReparseBuffer
    elif rpd.ReparseTag == IO_REPARSE_TAG_MOUNT_POINT:
        path_buff = (
            ctypes.addressof(rpd) +
            REPARSE_DATA_BUFFER.MountPointReparseBuffer.offset +
            RP_DATA_MOUNTPOINT.PathBuffer.offset
            )
        src = rpd.MountPointReparseBuffer
    else:
        raise RuntimeError(f"unhandled tag: 0x{rpd.ReparseTag:08x}")
    if get_subst_name:
        saddr = path_buff + src.SubstituteNameOffset
        slen = src.SubstituteNameLength // 2
    else:
        saddr = path_buff + src.PrintNameOffset
        slen = src.PrintNameLength // 2

    return ctypes.wstring_at(saddr, slen)

################################################################################

reparse_tags = {
    v: k for k, v in vars(ctwin32).items() if k.startswith("IO_REPARSE_TAG_")
    }
follow = (IO_REPARSE_TAG_SYMLINK, IO_REPARSE_TAG_MOUNT_POINT)

for directory, info in iter_dir(os.environ["SYSTEMDRIVE"]):
    if info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT:
        rpp = rf"{directory}\{info.cFileName}"
        if info.dwReserved0 in reparse_tags:
            tag = reparse_tags[info.dwReserved0]
        else:
            tag = f"UNKNOWN: 0x{info.dwReserved0:08x}"
        if info.dwReserved0 in follow:
            print(f"{tag:32} {rpp}\n    -> {readlink(rpp)}")
        else:
            print(f"{tag:32} {rpp}")

################################################################################
