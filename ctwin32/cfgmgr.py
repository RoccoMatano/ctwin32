################################################################################
#
# Copyright 2021-2024 Rocco Matano
# SPDX-License-Identifier: MIT
#
################################################################################

import ctypes
from .wtypes import (
    byte_buffer,
    string_buffer,
    DWORD,
    GUID,
    INT,
    PDWORD,
    PGUID,
    PINT,
    PVOID,
    PWSTR,
    PULONG,
    ULONG,
    WinError,
    )
from . import (
    ref,
    fun_fact,
    multi_str_from_str,
    MAX_DEVICE_ID_LEN,
    MAX_PATH,
    CM_GET_DEVICE_INTERFACE_LIST_PRESENT,
    CM_LOCATE_DEVNODE_NORMAL,
    CR_BUFFER_SMALL,
    CR_SUCCESS,
    ERROR_FLOPPY_UNKNOWN_ERROR,
    ERROR_CURRENT_DIRECTORY,
    )
from .advapi import registry_to_py
_cfg = ctypes.WinDLL("cfgmgr32.dll", use_last_error=True)

################################################################################

CM_MapCrToWin32Err = fun_fact(_cfg.CM_MapCrToWin32Err, (DWORD, DWORD, DWORD))

def raise_on_cr(cfgret):
    if cfgret != CR_SUCCESS:
        # use an unlikely default value. anyone out there still using floppies?
        err = CM_MapCrToWin32Err(cfgret, ERROR_FLOPPY_UNKNOWN_ERROR)
        raise WinError(err)

################################################################################

_CM_Get_Device_ID = fun_fact(
    _cfg.CM_Get_Device_IDW,
    (DWORD, DWORD, PWSTR, ULONG, ULONG)
    )

def CM_Get_Device_ID(devinst):
    idstr = string_buffer(MAX_DEVICE_ID_LEN)
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
    enum_str = string_buffer(MAX_DEVICE_ID_LEN)
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
    veto_name = string_buffer(MAX_PATH)
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

_CM_Locate_DevNode = fun_fact(
    _cfg.CM_Locate_DevNodeW, (DWORD, PDWORD, PWSTR, ULONG)
    )

def CM_Locate_DevNode(device_id, flags=CM_LOCATE_DEVNODE_NORMAL):
    devinst = DWORD()
    raise_on_cr(_CM_Locate_DevNode(ref(devinst), device_id, flags))
    return devinst.value

################################################################################

_CM_Get_DevNode_Registry_Property = fun_fact(
    _cfg.CM_Get_DevNode_Registry_PropertyW, (
        DWORD,
        DWORD,
        ULONG,
        PULONG,
        PVOID,
        PULONG,
        ULONG
        )
    )

def CM_Get_DevNode_Registry_Property(devinst, prop):
    reg_type = DWORD()
    req_size = DWORD()
    _CM_Get_DevNode_Registry_Property(
        devinst,
        prop,
        ref(reg_type),
        None,
        ref(req_size),
        0
        )
    buf = byte_buffer(req_size.value)
    raise_on_cr(
        _CM_Get_DevNode_Registry_Property(
            devinst,
            prop,
            ref(reg_type),
            buf,
            ref(req_size),
            0
            )
        )
    return registry_to_py(reg_type.value, buf.raw[:req_size.value])

################################################################################

_CM_Get_Device_Interface_List_Size = fun_fact(
    _cfg.CM_Get_Device_Interface_List_SizeW, (
        DWORD,
        PULONG,
        PGUID,
        PWSTR,
        ULONG
        )
    )

def CM_Get_Device_Interface_List_Size(
    guid,
    didstr,
    flags=CM_GET_DEVICE_INTERFACE_LIST_PRESENT
    ):
    size = ULONG()
    raise_on_cr(
        _CM_Get_Device_Interface_List_Size(
            ref(size),
            ref(guid),
            didstr,
            flags
            )
        )
    return size.value

################################################################################

_CM_Get_Device_Interface_List = fun_fact(
    _cfg.CM_Get_Device_Interface_ListW, (
        DWORD,
        PGUID,
        PWSTR,
        PWSTR,
        ULONG,
        ULONG
        )
    )

def CM_Get_Device_Interface_List(
    guid,
    didstr,
    flags=CM_GET_DEVICE_INTERFACE_LIST_PRESENT
    ):
    res = CR_BUFFER_SMALL
    while res == CR_BUFFER_SMALL:
        size = ULONG(CM_Get_Device_Interface_List_Size(guid, didstr, flags))
        iface = string_buffer(size.value)
        res = _CM_Get_Device_Interface_List(
            ref(guid),
            didstr,
            iface,
            size,
            flags
            )
        if res == CR_SUCCESS:
            return multi_str_from_str(iface.value)
        if res != CR_BUFFER_SMALL:
            raise_on_cr(res)
    return []

################################################################################
