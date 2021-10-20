################################################################################
#
# Copyright 2021 Rocco Matano
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

# see here for equivalent C++ sample code
# https://github.com/microsoft/Windows-classic-samples/blob/main/Samples/Hyper-V/Storage/cpp/AttachVirtualDisk.cpp

import sys
from ctwin32 import (
    virtdisk,
    ATTACH_VIRTUAL_DISK_FLAG_PERMANENT_LIFETIME,
    ATTACH_VIRTUAL_DISK_FLAG_READ_ONLY,
    OPEN_VIRTUAL_DISK_VERSION_1,
    OPEN_VIRTUAL_DISK_VERSION_2,
    OPEN_VIRTUAL_DISK_FLAG_NONE,
    VIRTUAL_DISK_ACCESS_READ,
    VIRTUAL_DISK_ACCESS_NONE,
    )

path = sys.argv[1]
do_detach = len(sys.argv) > 2

oparams = virtdisk.OPEN_VIRTUAL_DISK_PARAMETERS()
oflags = OPEN_VIRTUAL_DISK_FLAG_NONE

# Specify UNKNOWN for both device and vendor so the system will use
# the file extension to determine the correct VHD format. The default values
# do exactly that.
storage_type = virtdisk.VIRTUAL_STORAGE_TYPE()


ext = path.rsplit(".", 1)[1].lower()
if ext == "iso":
    read_only = True
    oparams.Version = OPEN_VIRTUAL_DISK_VERSION_1
    acc_masc = VIRTUAL_DISK_ACCESS_READ
    aflags = (
        ATTACH_VIRTUAL_DISK_FLAG_PERMANENT_LIFETIME
        | ATTACH_VIRTUAL_DISK_FLAG_READ_ONLY
        )
else:
    oparams.Version = OPEN_VIRTUAL_DISK_VERSION_2
    oparams.Version2.GetInfoOnly = False
    acc_masc = VIRTUAL_DISK_ACCESS_NONE # change this
    aflags = ATTACH_VIRTUAL_DISK_FLAG_PERMANENT_LIFETIME

    # not tested -> CHANGE THIS
    acc_masc = VIRTUAL_DISK_ACCESS_NONE


hdl = virtdisk.OpenVirtualDisk(storage_type, path, acc_masc, oflags, oparams)
if do_detach:
    virtdisk.DetachVirtualDisk(hdl)
else:
    virtdisk.AttachVirtualDisk(hdl, flags_ro if read_only else flags_rw)
