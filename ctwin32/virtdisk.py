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

import ctypes as _ct

from .wtypes import *
from . import _fun_fact, _raise_on_err

from .kernel import KHANDLE, PKHANDLE

_ref = _ct.byref
_vdisk = _ct.windll.virtdisk

################################################################################

class VIRTUAL_STORAGE_TYPE(_ct.Structure):
    _fields_ = (
        ("DeviceId", ULONG),
        ("VendorId", GUID),
        )
PVIRTUAL_STORAGE_TYPE = _ct.POINTER(VIRTUAL_STORAGE_TYPE)

################################################################################

class _OVDP_VERSION1(_ct.Structure):
    _fields_ = (
        ("RWDepth", ULONG),
        )
class _OVDP_VERSION2(_ct.Structure):
    _fields_ = (
        ("GetInfoOnly", BOOL),
        ("ReadOnly", BOOL),
        ("ResiliencyGuid", GUID),
        )
class _OVDP_VERSION3(_ct.Structure):
    _fields_ = (
        ("GetInfoOnly", BOOL),
        ("ReadOnly", BOOL),
        ("ResiliencyGuid", GUID),
        ("SnapshotId", GUID),
        )
class _OVDP_UNION(_ct.Union):
    _fields_ = (
        ("Version1", _OVDP_VERSION1),
        ("Version2", _OVDP_VERSION2),
        ("Version3", _OVDP_VERSION3),
        )

class OPEN_VIRTUAL_DISK_PARAMETERS(_ct.Structure):
    _fields_ = (("Version", LONG), ("u", _OVDP_UNION))
    _anonymous_ = ("u",)
POPEN_VIRTUAL_DISK_PARAMETERS = _ct.POINTER(OPEN_VIRTUAL_DISK_PARAMETERS)

################################################################################

class _AVDP_VERSION1(_ct.Structure):
    _fields_ = (
        ("Reserved", ULONG),
        )
class _AVDP_VERSION2(_ct.Structure):
    _fields_ = (
        ("RestrictedOffset", ULARGE_INTEGER),
        ("RestrictedLength", ULARGE_INTEGER),
        )
class _AVDP_UNION(_ct.Union):
    _fields_ = (
        ("Version1", _OVDP_VERSION1),
        ("Version2", _OVDP_VERSION2),
        )

class ATTACH_VIRTUAL_DISK_PARAMETERS(_ct.Structure):
    _fields_ = (("Version", LONG), ("u", _AVDP_UNION))
    _anonymous_ = ("u",)
PATTACH_VIRTUAL_DISK_PARAMETERS = _ct.POINTER(ATTACH_VIRTUAL_DISK_PARAMETERS)

################################################################################

_OpenVirtualDisk = _fun_fact(
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
    _raise_on_err(
        _OpenVirtualDisk(
            _ref(storage_type),
            path,
            access_mask,
            flags,
            None if parameters is None else _ref(parameters),
            _ref(hdl)
            )
        )
    return hdl

################################################################################

_AttachVirtualDisk = _fun_fact(
    _vdisk.AttachVirtualDisk, (
        DWORD,
        KHANDLE,
        PVOID, # no interest in supplying a security descriptor
        LONG,
        ULONG,
        PATTACH_VIRTUAL_DISK_PARAMETERS,
        PVOID, # no interest in supplying an overlapped
        )
    )

def AttachVirtualDisk(hdl, flags, prov_flags=0, parameters=None):
    _raise_on_err(
        _AttachVirtualDisk(
            hdl,
            None,
            flags,
            prov_flags,
            None if parameters is None else _ref(parameters),
            None
            )
        )

################################################################################

_DetachVirtualDisk = _fun_fact(
    _vdisk.DetachVirtualDisk, (
        DWORD,
        KHANDLE,
        LONG,
        ULONG,
        )
    )

def DetachVirtualDisk(hdl, flags=0, prov_flags=0):
    _raise_on_err(_DetachVirtualDisk(hdl, flags, prov_flags))

################################################################################
