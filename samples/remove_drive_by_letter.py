################################################################################
#
# Copyright 2021-2024 Rocco Matano
# SPDX-License-Identifier: MIT
#
################################################################################
# This sample was inspired by
# https://www.codeproject.com/Articles/13839/How-to-Prepare-a-USB-Drive-for-Safe-Removal
#
# It demonstrates how to prepare a disk drive for safe removal. The easy part
# is calling CM_Request_Device_Eject. The difficult one is to find the devinst
# that corresponds to a certain drive letter. There are lots cases where this
# will NOT work (e.g. mounted ISO, VHD or VeraCrypt volumes). In fact, it is
# a oversimplification to assume that there is always a one-to-one relationship
# between drive letter and disk device. But for the simple cases like USB
# sticks or USB harddisks this should work.
#
################################################################################

import sys
import time
import ctypes

from ctwin32 import (
    kernel,
    cfgmgr,
    setupapi,
    FILE_DEVICE_CD_ROM,
    FILE_DEVICE_DVD,
    FILE_DEVICE_DISK,
    )
from ctwin32.wtypes import INT, ULONG, GUID

################################################################################

# from winioctl.h

class STORAGE_DEVICE_NUMBER(ctypes.Structure):
    _fields_ = (
        ("DeviceType", INT),
        ("DeviceNumber", ULONG),
        ("PartitionNumber", ULONG),
        )

IOCTL_STORAGE_GET_DEVICE_NUMBER = 0x002d1080
GUID_IFACE_DISK = GUID("53f56307-b6bf-11d0-94f2-00a0c91efb8b")
GUID_IFACE_CDROM = GUID("53f56308-b6bf-11d0-94f2-00a0c91efb8b")

################################################################################

def get_drive_type_number(file_name):
    with kernel.create_file(file_name, 0) as vol:
        sdn = kernel.DeviceIoControl(
            vol,
            IOCTL_STORAGE_GET_DEVICE_NUMBER,
            None,
            ctypes.sizeof(STORAGE_DEVICE_NUMBER)
            )
    sdn = STORAGE_DEVICE_NUMBER.from_buffer(sdn)
    return sdn.DeviceType, sdn.DeviceNumber

################################################################################

def get_drive_devinst(drv_type, drv_num):
    # In order to find the devinst that corresponds to a certain drive, we
    # have to iterate over all device interfaces that match the drive type. The
    # drive number is only unique within the group of devices that share the
    # same interface.
    if drv_type in (FILE_DEVICE_CD_ROM, FILE_DEVICE_DVD):
        guid = GUID_IFACE_CDROM
    elif drv_type == FILE_DEVICE_DISK:
        # ignoring that floppies ever existed
        guid = GUID_IFACE_DISK
    else:
        raise ValueError(f"unhandled drive type: {drv_type}")

    for iset, did in setupapi.enum_dev_interfaces(guid):
        dev_path, deinda = setupapi.SetupDiGetDeviceInterfaceDetail(iset, did)
        dtype, dnum = get_drive_type_number(dev_path)
        if dtype == drv_type and dnum == drv_num:
            return deinda.DevInst

    raise OSError(f"devinst not found for {drv_type} {drv_num}")

################################################################################

def remove_drive_by_letter(letter):
    o = ord(letter)
    if o < ord("A") or o > ord("Z"):
        raise ValueError(f"invalid drive letter: {letter}")

    drv_type, drv_num = get_drive_type_number(f"\\\\.\\{letter}:")
    devinst = get_drive_devinst(drv_type, drv_num)
    parent = cfgmgr.CM_Get_Parent(devinst)

    MAX_TRIES = 3
    for i in range(MAX_TRIES):
        try:
            cfgmgr.CM_Request_Device_Eject(parent)
            err = None
            break
        except OSError as e:
            err = e
        if i < MAX_TRIES - 1:
            time.sleep(0.5)

    if err is None:
        print("--> Sucess <--")
    else:
        print(err)

################################################################################

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("need drive letter")
    else:
        remove_drive_by_letter(sys.argv[1][0].upper())

################################################################################
