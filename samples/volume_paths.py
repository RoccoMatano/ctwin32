################################################################################
#
# Copyright 2021-2023 Rocco Matano
#
# Permission is hereby granted, free of charge, to any person obtaining a
# copy of this software and associated documentation files (the "Software"),
# to deal in the Software without restriction, including without limitation
# the rights to use, copy, modify, merge, publish, distribute, sublicense,
# and/or sell copies of the Software, and to permit persons to whom the
# Software is furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included
# in all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
# THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
# FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
# DEALINGS IN THE SOFTWARE.
#
################################################################################

import ctypes
from ctwin32 import (
    advapi,
    kernel,
    suppress_winerr,
    ERROR_FILE_NOT_FOUND,
    ERROR_INVALID_FUNCTION,
    ERROR_MORE_DATA,
    ERROR_NOT_SUPPORTED,
    GENERIC_EXECUTE,
    )
from ctwin32.wtypes import ULONG, LARGE_INTEGER, ENDIANNESS

################################################################################

IOCTL_VOLUME_GET_VOLUME_DISK_EXTENTS = 0x00560000

class DISK_EXTENT(ctypes.Structure):
    _fields_ = (
        ("DiskNumber", ULONG),
        ("StartingOffset", LARGE_INTEGER),
        ("ExtentLength", LARGE_INTEGER),
        )

def get_disk_extends(data_bytes):
    num = int.from_bytes(
        data_bytes[:ctypes.sizeof(ULONG)],
        byteorder=ENDIANNESS
        )
    class VOLUME_DISK_EXTENTS(ctypes.Structure):
        _fields_ = (
            ("NumberOfDiskExtents", ULONG),
            ("Extents", DISK_EXTENT * num),
            )
    return VOLUME_DISK_EXTENTS.from_buffer_copy(data_bytes).Extents

################################################################################

def get_volume_extends(vol_name):
    with kernel.create_file(vol_name, GENERIC_EXECUTE) as hdl:
        bites = None
        size = 128
        while True:
            size *= 2
            with suppress_winerr(ERROR_MORE_DATA):
                bites = kernel.DeviceIoControl(
                    hdl,
                    IOCTL_VOLUME_GET_VOLUME_DISK_EXTENTS,
                    None,
                    size
                    )
                break
    return get_disk_extends(bites)

################################################################################

def get_disks(vol, dev, pth):
    if advapi.running_as_admin():
        # while all volumes have names, that can be opened, this requires
        # administrative privileges
        name = vol[:-1]
    elif pth:
        name = rf"\\.\{pth[0][:-1]}"
    else:
        name = dev.replace(r"\Device", r"\\?")

    try:
        extends = get_volume_extends(name)
    except OSError as e:
        if e.winerror in (ERROR_INVALID_FUNCTION, ERROR_NOT_SUPPORTED):
            return "not supported"
        return e.strerror

    return ", ".join(str(e.DiskNumber) for e in extends)

################################################################################

for volume in kernel.enum_volumes():
    # strip '\\?\' prefix and trailing '\'
    device = kernel.QueryDosDevice(volume[4:-1])
    paths = []
    with suppress_winerr(ERROR_FILE_NOT_FOUND):
        paths = kernel.GetVolumePathNamesForVolumeName(volume)
    disks = get_disks(volume, device, paths)
    paths = ", ".join(paths)

    print(f"\nvolume: {volume}")
    print(f"    device: {device}")
    print(f"    paths: {paths}")
    print(f"    disks: {disks}")
