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
import re

from .wtypes import *
from . import (
    _raise_if,
    _fun_fact,
    INVALID_HANDLE_VALUE,
    DIGCF_PRESENT,
    DIGCF_ALLCLASSES,
    DIGCF_DEVICEINTERFACE,
    DICS_ENABLE,
    DICS_DISABLE,
    DICS_FLAG_CONFIGSPECIFIC,
    MAX_DEVICE_ID_LEN,
    MAX_PATH,
    DIF_PROPERTYCHANGE,
    CR_SUCCESS,
    SPDRP_DEVICEDESC,
    ERROR_NO_MORE_ITEMS,
    )
from .advapi import registry_to_py

_sua = _ct.windll.setupapi
_ref = _ct.byref

################################################################################

class SP_DEVINFO_DATA(_ct.Structure):
    _fields_ = (
        ("cbSize", DWORD),
        ("ClassGuid", GUID),
        ("DevInst", DWORD),
        ("Reserved", ULONG_PTR),
        )
    def __init__(self):
        self.cbSize = _ct.sizeof(self)

PSP_DEVINFO_DATA = _ct.POINTER(SP_DEVINFO_DATA)

################################################################################

class SP_CLASSINSTALL_HEADER(_ct.Structure):
    _fields_ = (
        ("cbSize", DWORD),
        ("InstallFunction", DWORD),
        )

################################################################################

class SP_PROPCHANGE_PARAMS(_ct.Structure):
    _fields_ = (
        ("ClassInstallHeader", SP_CLASSINSTALL_HEADER),
        ("StateChange", DWORD),
        ("Scope", DWORD),
        ("HwProfile", DWORD),
        )
    def __init__(self, func, change, scope=DICS_FLAG_CONFIGSPECIFIC, prof=0):
        self.ClassInstallHeader.cbSize = _ct.sizeof(self.ClassInstallHeader)
        self.ClassInstallHeader.InstallFunction = func
        self.StateChange = change
        self.Scope = scope
        self.HwProfile = prof

PSP_PROPCHANGE_PARAMS = _ct.POINTER(SP_PROPCHANGE_PARAMS)

################################################################################

class SP_DEVICE_INTERFACE_DATA(_ct.Structure):
    _fields_ = [
        ("cbSize", DWORD),
        ("InterfaceClassGuid", GUID),
        ("Flags", DWORD),
        ("Reserved", ULONG_PTR),
        ]
    def __init__(self):
        self.cbSize = _ct.sizeof(self)

PSP_DEVICE_INTERFACE_DATA = _ct.POINTER(SP_DEVICE_INTERFACE_DATA)

class SP_DEVICE_INTERFACE_DETAIL_DATA(_ct.Structure):
    _fields_ = [
        ("cbSize", DWORD),
        ("DevicePath", WCHAR * 1),
        ]

################################################################################

_SetupDiGetClassDevs = _fun_fact(
    _sua.SetupDiGetClassDevsW,
    (HANDLE, PGUID, PWSTR, HWND, DWORD)
    )

def SetupDiGetClassDevs(
    guid=None,
    enumerator=None,
    flags=DIGCF_PRESENT | DIGCF_ALLCLASSES,
    hwnd=None
    ):
    if guid is not None:
        guid = _ref(guid)
        flags &= ~ DIGCF_ALLCLASSES
    res = _SetupDiGetClassDevs(guid, enumerator, hwnd, flags)
    _raise_if(res == INVALID_HANDLE_VALUE)
    return res

################################################################################

_SetupDiDestroyDeviceInfoList = _fun_fact(
    _sua.SetupDiDestroyDeviceInfoList, (BOOL, HANDLE)
    )

def SetupDiDestroyDeviceInfoList(info_set):
    _raise_if(not _SetupDiDestroyDeviceInfoList(info_set))

################################################################################

_SetupDiEnumDeviceInfo = _fun_fact(
    _sua.SetupDiEnumDeviceInfo,
    (BOOL, HANDLE, DWORD, PSP_DEVINFO_DATA)
    )

def SetupDiEnumDeviceInfo(info_set, idx, deinda):
    return _SetupDiEnumDeviceInfo(info_set, idx, deinda)

################################################################################

_CM_Get_Device_ID = _fun_fact(
    _sua.CM_Get_Device_IDW,
    (DWORD, DWORD, PWSTR, ULONG, ULONG)
    )

def CM_Get_Device_ID(devinst):
    idstr = _ct.create_unicode_buffer(MAX_DEVICE_ID_LEN)
    _raise_if(_CM_Get_Device_ID(devinst, idstr, MAX_DEVICE_ID_LEN, 0))
    return idstr.value

################################################################################

_CM_Get_DevNode_Status = _fun_fact(
    _sua.CM_Get_DevNode_Status,
    (DWORD, PULONG, PULONG, DWORD, ULONG)
    )

def CM_Get_DevNode_Status(dev_inst):
    status = ULONG()
    problem = ULONG()
    _raise_if(_CM_Get_DevNode_Status(_ref(status), _ref(problem), dev_inst, 0))
    return status.value, problem.value

################################################################################

_CM_Enumerate_Enumerators = _fun_fact(
    _sua.CM_Enumerate_EnumeratorsW,
    (DWORD, ULONG, PWSTR, PULONG, ULONG)
    )

def CM_Enumerate_Enumerators(idx):
    enum_str = _ct.create_unicode_buffer(MAX_DEVICE_ID_LEN)
    size = ULONG(MAX_DEVICE_ID_LEN)
    _raise_if(_CM_Enumerate_Enumerators(idx, enum_str, _ref(size), 0))
    return enum_str.value

################################################################################

_CM_Get_Parent = _fun_fact(
    _sua.CM_Get_Parent, (DWORD, PDWORD, DWORD, ULONG)
    )

def CM_Get_Parent(devinst):
    parent = DWORD()
    _raise_if(_CM_Get_Parent(_ref(parent), devinst, 0))
    return parent.value

################################################################################

_CM_Request_Device_Eject = _fun_fact(
    _sua.CM_Request_Device_EjectW, (
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
    veto_name = _ct.create_unicode_buffer(MAX_PATH)
    err = _CM_Request_Device_Eject(
        devinst,
        _ref(veto_type),
        veto_name,
        MAX_PATH,
        0
        )
    if err != 0 or veto_type.value != 0:
        vv = veto_type.value
        vn = veto_name.value
        raise OSError(16, f"device removal was vetoed ({vv}): {vn}")

################################################################################

def get_device_enumerators():
    res = []
    idx = 0
    while True:
        try:
            res.append(CM_Enumerate_Enumerators(idx))
            idx += 1
        except OSError as e:
            break
    return res

################################################################################

_CM_Enumerate_Classes = _fun_fact(
    _sua.CM_Enumerate_Classes, (DWORD, ULONG, PGUID, ULONG)
    )

def CM_Enumerate_Classes(idx, flags=0):
    guid = GUID()
    _raise_if(_CM_Enumerate_Classes(idx, _ref(guid), flags))
    return guid

################################################################################

def get_device_classes(flags=0):
    res = []
    idx = 0
    while True:
        try:
            res.append(CM_Enumerate_Classes(idx, flags))
            idx += 1
        except OSError as e:
            break
    return res

################################################################################

_SetupDiClassNameFromGuid = _fun_fact(
    _sua.SetupDiClassNameFromGuidW,
    (BOOL, PGUID, PWSTR, DWORD, PDWORD)
    )

def SetupDiClassNameFromGuid(guid):
    guid = GUID(guid)
    req_size = DWORD(0)
    _SetupDiClassNameFromGuid(_ref(guid), None, 0, _ref(req_size))
    name = _ct.create_unicode_buffer(req_size.value)
    _raise_if(
        not _SetupDiClassNameFromGuid(
            _ref(guid),
            name,
            req_size.value,
            _ref(req_size)
            )
        )
    return name.value

################################################################################

_SetupDiRemoveDevice = _fun_fact(
    _sua.SetupDiRemoveDevice, (BOOL, HANDLE, PSP_DEVINFO_DATA)
    )

def SetupDiRemoveDevice(info_set, deinda):
    _raise_if(not _SetupDiRemoveDevice(info_set, deinda))

################################################################################

_SetupDiCreateDeviceInfoList = _fun_fact(
    _sua.SetupDiCreateDeviceInfoList, (HANDLE, PGUID, HWND)
    )

def SetupDiCreateDeviceInfoList(guid=None, hwnd=None):
    if guid is not None:
        g = GUID(guid)
        guid = _ref(g)
    res = _SetupDiCreateDeviceInfoList(guid, hwnd)
    _raise_if(res == INVALID_HANDLE_VALUE)
    return res;

################################################################################

_SetupDiGetDeviceInstanceId = _fun_fact(
    _sua.SetupDiGetDeviceInstanceIdW,
    (BOOL, HANDLE, PSP_DEVINFO_DATA, PWSTR, DWORD, PDWORD)
    )

def SetupDiGetDeviceInstanceId(info_set, deinda):
    req_size = DWORD()
    _SetupDiGetDeviceInstanceId(info_set, deinda, None, 0, _ref(req_size))
    idstr = _ct.create_unicode_buffer(req_size.value)
    _raise_if(
        not _SetupDiGetDeviceInstanceId(
            info_set,
            deinda,
            idstr,
            req_size.value,
            _ref(req_size)
            )
        )
    return idstr.value

################################################################################

_SetupDiOpenDeviceInfo = _fun_fact(
    _sua.SetupDiOpenDeviceInfoW,
    (BOOL, HANDLE, PWSTR, HWND, DWORD, PSP_DEVINFO_DATA)
    )

def SetupDiOpenDeviceInfo(info_set, inst_id, hwnd=None, flags=0, p_info=None):
    _raise_if(
        not _SetupDiOpenDeviceInfo(info_set, inst_id, hwnd, flags, p_info)
        )

################################################################################

_SetupDiClassGuidsFromNameEx = _fun_fact(
    _sua.SetupDiClassGuidsFromNameExW, (
        BOOL,
        PWSTR,
        PGUID,
        DWORD,
        PDWORD,
        PWSTR,
        PVOID
        )
    )

def SetupDiClassGuidsFromNameEx(cls_name, machine_name=None):
    req_size = DWORD()
    _SetupDiClassGuidsFromNameEx(
        cls_name,
        None,
        0,
        _ref(req_size),
        machine_name,
        None
        )
    CLASS_GUIDS = GUID * req_size.value
    guids = CLASS_GUIDS()
    _raise_if(
        not _SetupDiClassGuidsFromNameEx(
            cls_name,
            _ct.cast(guids, PGUID),
            req_size.value,
            _ref(req_size),
            machine_name,
            None
            )
        )
    return [g.uuid() for g in guids]

################################################################################

def enum_dev_ids(guid=None, enumerator=None, flags=None, rx=None):
    if flags is None:
        flags = DIGCF_PRESENT | DIGCF_ALLCLASSES
    if isinstance(rx, str):
        rx = re.compile(rx)

    devs = SetupDiGetClassDevs(guid, enumerator, flags)
    deinda = SP_DEVINFO_DATA()
    idx = 0
    res = []
    while SetupDiEnumDeviceInfo(devs, idx, _ref(deinda)):
        did = CM_Get_Device_ID(deinda.DevInst)
        if rx is None or rx.search(did):
            res.append(did)
        idx += 1
    SetupDiDestroyDeviceInfoList(devs)
    return res

################################################################################

def build_info_set(guid=None, enumerator=None, flags=None, rx=None):
    selected = SetupDiCreateDeviceInfoList()
    if guid is None and enumerator is None and rx is None:
        return selected

    if flags is None:
        flags = DIGCF_PRESENT | DIGCF_ALLCLASSES
    if isinstance(rx, str):
        rx = re.compile(rx)

    enum_devs = SetupDiGetClassDevs(guid, enumerator, flags)
    deinda = SP_DEVINFO_DATA()
    idx = 0
    while SetupDiEnumDeviceInfo(enum_devs, idx, _ref(deinda)):
        did = CM_Get_Device_ID(deinda.DevInst)
        if rx is None or rx.search(did):
            SetupDiOpenDeviceInfo(selected, did)
        idx += 1
    SetupDiDestroyDeviceInfoList(enum_devs)
    return selected

################################################################################

def get_non_present_info_set():
    non_present = SetupDiCreateDeviceInfoList()
    all_devs = SetupDiGetClassDevs(flags=DIGCF_ALLCLASSES)
    deinda = SP_DEVINFO_DATA()
    idx = 0
    while SetupDiEnumDeviceInfo(all_devs, idx, _ref(deinda)):
        # If the device isn't currently present (as indicated by
        # failure to retrieve its status), then add it to the list.
        try:
            CM_Get_DevNode_Status(deinda.DevInst)
        except OSError:
            SetupDiOpenDeviceInfo(non_present, CM_Get_Device_ID(deinda.DevInst))
        idx += 1
    SetupDiDestroyDeviceInfoList(all_devs)
    return non_present

################################################################################

def enum_info_set(info_set, cleanup=True):
    deinda = SP_DEVINFO_DATA()
    idx = 0
    try:
        while SetupDiEnumDeviceInfo(info_set, idx, _ref(deinda)):
            yield info_set, deinda
            idx += 1
    finally:
        if cleanup:
            SetupDiDestroyDeviceInfoList(info_set)

################################################################################

def remove_non_present_devices():
    for iset, ddat in enum_info_set(get_non_present_info_set()):
        SetupDiRemoveDevice(iset, ddat)

################################################################################

_SetupDiSetClassInstallParams = _fun_fact(
    _sua.SetupDiSetClassInstallParamsW,
    (BOOL, HANDLE, PSP_DEVINFO_DATA, PSP_PROPCHANGE_PARAMS, DWORD)
    )

def SetupDiSetClassInstallParams(info_set, deinda, pparams):
    _raise_if(
        not _SetupDiSetClassInstallParams(
            info_set,
            deinda,
            pparams,
            _ct.sizeof(SP_PROPCHANGE_PARAMS)
            )
        )

################################################################################

_SetupDiCallClassInstaller = _fun_fact(
    _sua.SetupDiCallClassInstaller,
    (BOOL, DWORD, HANDLE, PSP_DEVINFO_DATA)
    )

def SetupDiCallClassInstaller(func, info_set, deinda):
    _raise_if(not _SetupDiCallClassInstaller(func, info_set, deinda))

################################################################################

def _prop_change(
    info_set,
    deinda,
    change,
    scope=DICS_FLAG_CONFIGSPECIFIC,
    prof=0
    ):
    params = SP_PROPCHANGE_PARAMS(DIF_PROPERTYCHANGE, change, scope, prof)
    SetupDiSetClassInstallParams(info_set, deinda, _ref(params))
    SetupDiCallClassInstaller(DIF_PROPERTYCHANGE, info_set, deinda)

################################################################################

def _change_devices(change, guid=None, enumerator=None, rx=None):
    info_set = build_info_set(guid, enumerator, None, rx)
    deinda = SP_DEVINFO_DATA()
    idx = 0
    while SetupDiEnumDeviceInfo(info_set, idx, _ref(deinda)):
        _prop_change(info_set, deinda, change)
        idx += 1
    SetupDiDestroyDeviceInfoList(info_set)

################################################################################

def enable_devices(guid=None, enumerator=None, rx=None):
    _change_devices(DICS_ENABLE, guid, enumerator, rx)

################################################################################

def disable_devices(guid=None, enumerator=None, rx=None):
    _change_devices(DICS_DISABLE, guid, enumerator, rx)

################################################################################

_SetupDiGetDeviceRegistryProperty = _fun_fact(
    _sua.SetupDiGetDeviceRegistryPropertyW, (
        BOOL,
        HANDLE,
        PSP_DEVINFO_DATA,
        DWORD,
        PDWORD,
        PBYTE,
        DWORD,
        PDWORD
        )
    )

def SetupDiGetDeviceRegistryProperty(info_set, deinda, prop):
    reg_type = DWORD()
    req_size = DWORD()
    _SetupDiGetDeviceRegistryProperty(
        info_set,
        deinda,
        prop,
        _ref(reg_type),
        None,
        0,
        _ref(req_size)
        )
    buf = _ct.create_string_buffer(req_size.value)
    _raise_if(
        not _SetupDiGetDeviceRegistryProperty(
            info_set,
            deinda,
            prop,
            _ref(reg_type),
            _ct.cast(buf, PBYTE),
            req_size,
            _ref(req_size)
            )
        )
    return registry_to_py(reg_type.value, buf.raw[:req_size.value])

################################################################################

def desc_from_info_set(info_set, deinda):
    return SetupDiGetDeviceRegistryProperty(
        info_set,
        deinda,
        SPDRP_DEVICEDESC
        )[0]

################################################################################

_SetupDiEnumDeviceInterfaces = _fun_fact(
    _sua.SetupDiEnumDeviceInterfaces, (
        BOOL,
        HANDLE,
        PSP_DEVINFO_DATA,
        PGUID,
        DWORD,
        PSP_DEVICE_INTERFACE_DATA
        )
    )

def SetupDiEnumDeviceInterfaces(info_set, guid, idx):
    did = SP_DEVICE_INTERFACE_DATA()
    _raise_if(
        not _SetupDiEnumDeviceInterfaces(
            info_set,
            None,
            _ref(GUID(guid)),
            idx,
            _ref(did)
            )
        )
    return did

################################################################################

def enum_dev_interfaces(guid):
    info_set = SetupDiGetClassDevs(
        flags=DIGCF_PRESENT | DIGCF_DEVICEINTERFACE,
        guid=guid
        )
    idx = 0
    try:
        while True:
            try:
                did = SetupDiEnumDeviceInterfaces(info_set, guid, idx)
            except OSError as e:
                if e.winerror == ERROR_NO_MORE_ITEMS:
                    break
                raise
            idx += 1
            yield info_set, did
    finally:
        SetupDiDestroyDeviceInfoList(info_set)

################################################################################

_SetupDiGetDeviceInterfaceDetail = _fun_fact(
    _sua.SetupDiGetDeviceInterfaceDetailW, (
        BOOL,
        HANDLE,
        PSP_DEVICE_INTERFACE_DATA,
        PVOID,
        DWORD,
        PDWORD,
        PSP_DEVINFO_DATA
        )
    )

def SetupDiGetDeviceInterfaceDetail(info_set, did):
    req_size = DWORD(0)
    _SetupDiGetDeviceInterfaceDetail(
        info_set,
        _ref(did),
        None,
        0,
        _ref(req_size),
        None
        )

    diff = req_size.value - _ct.sizeof(DWORD)
    class LOCAL_SPDIDD(_ct.Structure):
        _fields_ = [
            ("cbSize", DWORD),
            ("DevicePath", BYTE * diff),
            ]
    ifdetail = LOCAL_SPDIDD()
    ifdetail.cbSize = _ct.sizeof(SP_DEVICE_INTERFACE_DETAIL_DATA)
    deinda = SP_DEVINFO_DATA()

    _raise_if(
        not _SetupDiGetDeviceInterfaceDetail(
            info_set,
            _ref(did),
            _ref(ifdetail),
            req_size,
            _ref(req_size),
            _ref(deinda),
            )
        )
    return _ct.wstring_at(_ct.addressof(ifdetail.DevicePath)), deinda

################################################################################
