################################################################################
#
# Copyright 2021-2024 Rocco Matano
# SPDX-License-Identifier: MIT
#
################################################################################

import ctypes
from .wtypes import (
    BOOL,
    DWORD,
    GUID,
    LONG,
    POINTER,
    PVOID,
    PWSTR,
    ULARGE_INTEGER,
    ULONG,
    )
from . import ref, fun_fact, raise_on_err

from .kernel import KHANDLE, PKHANDLE

_vdisk = ctypes.WinDLL("virtdisk.dll", use_last_error=True)

################################################################################

ATTACH_VIRTUAL_DISK_FLAG_NONE = 0
ATTACH_VIRTUAL_DISK_FLAG_READ_ONLY = 0x1
ATTACH_VIRTUAL_DISK_FLAG_NO_DRIVE_LETTER = 0x2
ATTACH_VIRTUAL_DISK_FLAG_PERMANENT_LIFETIME = 0x4
ATTACH_VIRTUAL_DISK_FLAG_NO_LOCAL_HOST = 0x8
ATTACH_VIRTUAL_DISK_FLAG_NO_SECURITY_DESCRIPTOR = 0x10
ATTACH_VIRTUAL_DISK_FLAG_BYPASS_DEFAULT_ENCRYPTION_POLICY = 0x20
ATTACH_VIRTUAL_DISK_FLAG_NON_PNP = 0x40
ATTACH_VIRTUAL_DISK_FLAG_RESTRICTED_RANGE = 0x80
ATTACH_VIRTUAL_DISK_FLAG_SINGLE_PARTITION = 0x100
ATTACH_VIRTUAL_DISK_FLAG_REGISTER_VOLUME = 0x200

VIRTUAL_DISK_ACCESS_NONE = 0
VIRTUAL_DISK_ACCESS_ATTACH_RO = 0x10000
VIRTUAL_DISK_ACCESS_ATTACH_RW = 0x20000
VIRTUAL_DISK_ACCESS_DETACH = 0x40000
VIRTUAL_DISK_ACCESS_GET_INFO = 0x80000
VIRTUAL_DISK_ACCESS_CREATE = 0x100000
VIRTUAL_DISK_ACCESS_METAOPS = 0x200000
VIRTUAL_DISK_ACCESS_READ = 0xd0000
VIRTUAL_DISK_ACCESS_ALL = 0x3f0000
VIRTUAL_DISK_ACCESS_WRITABLE = 0x320000

OPEN_VIRTUAL_DISK_FLAG_NONE = 0
OPEN_VIRTUAL_DISK_FLAG_NO_PARENTS = 0x1
OPEN_VIRTUAL_DISK_FLAG_BLANK_FILE = 0x2
OPEN_VIRTUAL_DISK_FLAG_BOOT_DRIVE = 0x4
OPEN_VIRTUAL_DISK_FLAG_CACHED_IO = 0x8
OPEN_VIRTUAL_DISK_FLAG_CUSTOM_DIFF_CHAIN = 0x10
OPEN_VIRTUAL_DISK_FLAG_PARENT_CACHED_IO = 0x20
OPEN_VIRTUAL_DISK_FLAG_VHDSET_FILE_ONLY = 0x40
OPEN_VIRTUAL_DISK_FLAG_IGNORE_RELATIVE_PARENT_LOCATOR = 0x80
OPEN_VIRTUAL_DISK_FLAG_NO_WRITE_HARDENING = 0x100
OPEN_VIRTUAL_DISK_FLAG_SUPPORT_COMPRESSED_VOLUMES = 0x200

OPEN_VIRTUAL_DISK_VERSION_UNSPECIFIED = 0
OPEN_VIRTUAL_DISK_VERSION_1 = 1
OPEN_VIRTUAL_DISK_VERSION_2 = 2
OPEN_VIRTUAL_DISK_VERSION_3 = 3

DETACH_VIRTUAL_DISK_FLAG_NONE = 0

ATTACH_VIRTUAL_DISK_VERSION_1 = 1
ATTACH_VIRTUAL_DISK_VERSION_2 = 2

################################################################################

class VIRTUAL_STORAGE_TYPE(ctypes.Structure):
    _fields_ = (
        ("DeviceId", ULONG),
        ("VendorId", GUID),
        )
PVIRTUAL_STORAGE_TYPE = POINTER(VIRTUAL_STORAGE_TYPE)

################################################################################

class _OVDP_VERSION1(ctypes.Structure):
    _fields_ = (
        ("RWDepth", ULONG),
        )

class _OVDP_VERSION2(ctypes.Structure):
    _fields_ = (
        ("GetInfoOnly", BOOL),
        ("ReadOnly", BOOL),
        ("ResiliencyGuid", GUID),
        )

class _OVDP_VERSION3(ctypes.Structure):
    _fields_ = (
        ("GetInfoOnly", BOOL),
        ("ReadOnly", BOOL),
        ("ResiliencyGuid", GUID),
        ("SnapshotId", GUID),
        )

class _OVDP_UNION(ctypes.Union):
    _fields_ = (
        ("Version1", _OVDP_VERSION1),
        ("Version2", _OVDP_VERSION2),
        ("Version3", _OVDP_VERSION3),
        )

class OPEN_VIRTUAL_DISK_PARAMETERS(ctypes.Structure):
    _fields_ = (("Version", LONG), ("u", _OVDP_UNION))
    _anonymous_ = ("u",)
POPEN_VIRTUAL_DISK_PARAMETERS = POINTER(OPEN_VIRTUAL_DISK_PARAMETERS)

################################################################################

class _AVDP_VERSION1(ctypes.Structure):
    _fields_ = (
        ("Reserved", ULONG),
        )

class _AVDP_VERSION2(ctypes.Structure):
    _fields_ = (
        ("RestrictedOffset", ULARGE_INTEGER),
        ("RestrictedLength", ULARGE_INTEGER),
        )

class _AVDP_UNION(ctypes.Union):
    _fields_ = (
        ("Version1", _OVDP_VERSION1),
        ("Version2", _OVDP_VERSION2),
        )

class ATTACH_VIRTUAL_DISK_PARAMETERS(ctypes.Structure):
    _fields_ = (("Version", LONG), ("u", _AVDP_UNION))
    _anonymous_ = ("u",)
PATTACH_VIRTUAL_DISK_PARAMETERS = POINTER(ATTACH_VIRTUAL_DISK_PARAMETERS)

################################################################################

_OpenVirtualDisk = fun_fact(
    _vdisk.OpenVirtualDisk, (
        DWORD,
        PVIRTUAL_STORAGE_TYPE,
        PWSTR,
        LONG,
        LONG,
        POPEN_VIRTUAL_DISK_PARAMETERS,
        PKHANDLE
        )
    )

def OpenVirtualDisk(storage_type, path, access_mask, flags, parameters=None):
    hdl = KHANDLE()
    raise_on_err(
        _OpenVirtualDisk(
            ref(storage_type),
            path,
            access_mask,
            flags,
            None if parameters is None else ref(parameters),
            ref(hdl)
            )
        )
    return hdl

################################################################################

_AttachVirtualDisk = fun_fact(
    _vdisk.AttachVirtualDisk, (
        DWORD,
        KHANDLE,
        PVOID,  # no interest in supplying a security descriptor
        LONG,
        ULONG,
        PATTACH_VIRTUAL_DISK_PARAMETERS,
        PVOID,  # no interest in supplying an overlapped
        )
    )

def AttachVirtualDisk(hdl, flags, prov_flags=0, parameters=None):
    raise_on_err(
        _AttachVirtualDisk(
            hdl,
            None,
            flags,
            prov_flags,
            None if parameters is None else ref(parameters),
            None
            )
        )

################################################################################

_DetachVirtualDisk = fun_fact(
    _vdisk.DetachVirtualDisk, (
        DWORD,
        KHANDLE,
        LONG,
        ULONG,
        )
    )

def DetachVirtualDisk(hdl, flags=0, prov_flags=0):
    raise_on_err(_DetachVirtualDisk(hdl, flags, prov_flags))

################################################################################
