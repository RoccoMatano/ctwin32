################################################################################
#
# Copyright 2021-2022 Rocco Matano
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

from .wtypes import *
from . import (
    ref,
    fun_fact,
    MAX_DEVICE_ID_LEN,
    MAX_PATH,
    CR_SUCCESS,
    ERROR_FLOPPY_UNKNOWN_ERROR,
    ERROR_CURRENT_DIRECTORY,
    )
_cfg = ctypes.WinDLL("cfgmgr32.dll")

################################################################################

CM_MapCrToWin32Err = fun_fact(_cfg.CM_MapCrToWin32Err, (DWORD, DWORD, DWORD))

def raise_on_cr(cfgret):
    if cfgret != CR_SUCCESS:
        # use an unlikely default value. anyone out there still using floppies?
        err = CM_MapCrToWin32Err(cfgret, ERROR_FLOPPY_UNKNOWN_ERROR)
        raise ctypes.WinError(err)

################################################################################

_CM_Get_Device_ID = fun_fact(
    _cfg.CM_Get_Device_IDW,
    (DWORD, DWORD, PWSTR, ULONG, ULONG)
    )

def CM_Get_Device_ID(devinst):
    idstr = ctypes.create_unicode_buffer(MAX_DEVICE_ID_LEN)
    raise_on_cr(_CM_Get_Device_ID(devinst, idstr, MAX_DEVICE_ID_LEN, 0))
    return idstr.value

################################################################################

_CM_Get_DevNode_Status = fun_fact(
    _cfg.CM_Get_DevNode_Status,
    (DWORD, PULONG, PULONG, DWORD, ULONG)
    )

def CM_Get_DevNode_Status(dev_inst):
    status = ULONG()
    problem = ULONG()
    raise_on_cr(_CM_Get_DevNode_Status(ref(status), ref(problem), dev_inst, 0))
    return status.value, problem.value

################################################################################

_CM_Enumerate_Enumerators = fun_fact(
    _cfg.CM_Enumerate_EnumeratorsW,
    (DWORD, ULONG, PWSTR, PULONG, ULONG)
    )

def CM_Enumerate_Enumerators(idx):
    enum_str = ctypes.create_unicode_buffer(MAX_DEVICE_ID_LEN)
    size = ULONG(MAX_DEVICE_ID_LEN)
    raise_on_cr(_CM_Enumerate_Enumerators(idx, enum_str, ref(size), 0))
    return enum_str.value

################################################################################

_CM_Enumerate_Classes = fun_fact(
    _cfg.CM_Enumerate_Classes, (DWORD, ULONG, PGUID, ULONG)
    )

def CM_Enumerate_Classes(idx, flags=0):
    guid = GUID()
    raise_on_cr(_CM_Enumerate_Classes(idx, ref(guid), flags))
    return guid

################################################################################

_CM_Get_Parent = fun_fact(
    _cfg.CM_Get_Parent, (DWORD, PDWORD, DWORD, ULONG)
    )

def CM_Get_Parent(devinst):
    parent = DWORD()
    raise_on_cr(_CM_Get_Parent(ref(parent), devinst, 0))
    return parent.value

################################################################################

_CM_Request_Device_Eject = fun_fact(
    _cfg.CM_Request_Device_EjectW, (
        DWORD,
        DWORD,
        PINT,
        PWSTR,
        ULONG,
        ULONG
        )
    )

def CM_Request_Device_Eject(devinst):
    veto_type = INT()
    veto_name = ctypes.create_unicode_buffer(MAX_PATH)
    err = _CM_Request_Device_Eject(
        devinst,
        ref(veto_type),
        veto_name,
        MAX_PATH,
        0
        )
    if err != CR_SUCCESS or veto_type.value != 0:
        vv = veto_type.value
        vn = veto_name.value
        def_err = ERROR_CURRENT_DIRECTORY
        err = CM_MapCrToWin32Err(err, def_err) or def_err
        raise OSError(err, f"device removal was vetoed ({vv}): {vn}")

################################################################################
