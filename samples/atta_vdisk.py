################################################################################
#
# Copyright 2021-2024 Rocco Matano
# SPDX-License-Identifier: MIT
#
################################################################################

# see here for equivalent C++ sample code
# https://github.com/microsoft/Windows-classic-samples/blob/main/Samples/Hyper-V/Storage/cpp/AttachVirtualDisk.cpp

import sys
from ctwin32 import virtdisk as vdsk

path = sys.argv[1]
do_detach = len(sys.argv) > 2

oparams = vdsk.OPEN_VIRTUAL_DISK_PARAMETERS()
oflags = vdsk.OPEN_VIRTUAL_DISK_FLAG_NONE

# Specify UNKNOWN for both device and vendor so the system will use
# the file extension to determine the correct VHD format. The default values
# do exactly that.
storage_type = vdsk.VIRTUAL_STORAGE_TYPE()

if (ext := path.rsplit(".", 1)[1].lower()) == "iso":
    oparams.Version = vdsk.OPEN_VIRTUAL_DISK_VERSION_1
    acc_mask = vdsk.VIRTUAL_DISK_ACCESS_READ
    aflags = (
        vdsk.ATTACH_VIRTUAL_DISK_FLAG_PERMANENT_LIFETIME
        | vdsk.ATTACH_VIRTUAL_DISK_FLAG_READ_ONLY
        )
else:
    oparams.Version = vdsk.OPEN_VIRTUAL_DISK_VERSION_2
    oparams.Version2.GetInfoOnly = False
    aflags = vdsk.ATTACH_VIRTUAL_DISK_FLAG_PERMANENT_LIFETIME

    # not tested -> CHANGE THIS
    acc_mask = vdsk.VIRTUAL_DISK_ACCESS_NONE

with vdsk.OpenVirtualDisk(storage_type, path, acc_mask, oflags, oparams) as vd:
    if do_detach:
        vdsk.DetachVirtualDisk(vd)
    else:
        vdsk.AttachVirtualDisk(vd, aflags)
