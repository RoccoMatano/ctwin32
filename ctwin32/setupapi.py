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
import ctypes.wintypes as _wt
import uuid
import re

from . import (
    _raise_if,
    _fun_fact,
    UINT_PTR,
    LONG_PTR,
    INVALID_HANDLE_VALUE,
    GUID,
    PGUID,
    DIGCF_PRESENT,
    DIGCF_ALLCLASSES,
    DICS_ENABLE,
    DICS_DISABLE,
    DICS_FLAG_CONFIGSPECIFIC,
    MAX_DEVICE_ID_LEN,
    DIF_PROPERTYCHANGE,
    CR_SUCCESS,
    SPDRP_DEVICEDESC,
    )
from .advapi import registry_to_py

_sua = _ct.windll.setupapi
_ref = _ct.byref

################################################################################

class SP_DEVINFO_DATA(_ct.Structure):
    _fields_ = (
        ("cbSize", _wt.DWORD),
        ("ClassGuid", GUID),
        ("DevInst", _wt.DWORD),
        ("Reserved", UINT_PTR),
        )
    def __init__(self):
        self.cbSize = _ct.sizeof(self)

PSP_DEVINFO_DATA = _ct.POINTER(SP_DEVINFO_DATA)

################################################################################

class SP_CLASSINSTALL_HEADER(_ct.Structure):
    _fields_ = (
        ("cbSize", _wt.DWORD),
        ("InstallFunction", _wt.DWORD),
        )

################################################################################

class SP_PROPCHANGE_PARAMS(_ct.Structure):
    _fields_ = (
        ("ClassInstallHeader", SP_CLASSINSTALL_HEADER),
        ("StateChange", _wt.DWORD),
        ("Scope", _wt.DWORD),
        ("HwProfile", _wt.DWORD),
        )
    def __init__(self, func, change, scope=DICS_FLAG_CONFIGSPECIFIC, prof=0):
        self.ClassInstallHeader.cbSize = _ct.sizeof(self.ClassInstallHeader)
        self.ClassInstallHeader.InstallFunction = func
        self.StateChange = change
        self.Scope = scope
        self.HwProfile = prof

PSP_PROPCHANGE_PARAMS = _ct.POINTER(SP_PROPCHANGE_PARAMS)

################################################################################

_SetupDiGetClassDevs = _fun_fact(
    _sua.SetupDiGetClassDevsW,
    (_wt.HANDLE, PGUID, _wt.LPCWSTR, _wt.HWND, _wt.DWORD)
    )

def SetupDiGetClassDevs(
    guid=None,
    enumerator=None,
    flags=DIGCF_PRESENT | DIGCF_ALLCLASSES,
    hwnd=None
    ):
    if guid is not None:
        if not isinstance(guid, uuid.UUID):
            raise TypeError(f"guid '{guid}' is not a UUID")
        g = GUID(guid)
        guid = _ref(g)
        flags &= ~ DIGCF_ALLCLASSES
    res = _SetupDiGetClassDevs(guid, enumerator, hwnd, flags)
    _raise_if(res == INVALID_HANDLE_VALUE)
    return res

################################################################################

_SetupDiDestroyDeviceInfoList = _fun_fact(
    _sua.SetupDiDestroyDeviceInfoList, (_wt.BOOL, _wt.HANDLE)
    )

def SetupDiDestroyDeviceInfoList(info_set):
    _raise_if(not _SetupDiDestroyDeviceInfoList(info_set))

################################################################################

_SetupDiEnumDeviceInfo = _fun_fact(
    _sua.SetupDiEnumDeviceInfo,
    (_wt.BOOL, _wt.HANDLE, _wt.DWORD, PSP_DEVINFO_DATA)
    )

def SetupDiEnumDeviceInfo(info_set, idx, deinda):
    return _SetupDiEnumDeviceInfo(info_set, idx, deinda)

################################################################################

_CM_Get_Device_ID = _fun_fact(
    _sua.CM_Get_Device_IDW,
    (_wt.DWORD, _wt.DWORD, _wt.LPWSTR, _wt.ULONG, _wt.ULONG)
    )

def CM_Get_Device_ID(devinst):
    idstr = _ct.create_unicode_buffer(MAX_DEVICE_ID_LEN)
    _raise_if(_CM_Get_Device_ID(devinst, idstr, MAX_DEVICE_ID_LEN, 0))
    return idstr.value

################################################################################

_CM_Get_DevNode_Status = _fun_fact(
    _sua.CM_Get_DevNode_Status,
    (_wt.DWORD, _wt.PULONG, _wt.PULONG, _wt.DWORD, _wt.ULONG)
    )

def CM_Get_DevNode_Status(dev_inst):
    status = _wt.ULONG()
    problem = _wt.ULONG()
    _raise_if(_CM_Get_DevNode_Status(_ref(status), _ref(problem), dev_inst, 0))
    return status.value, problem.value

################################################################################

_CM_Enumerate_Enumerators = _fun_fact(
    _sua.CM_Enumerate_EnumeratorsW,
    (_wt.DWORD, _wt.ULONG, _wt.LPWSTR, _wt.PULONG, _wt.ULONG)
    )

def CM_Enumerate_Enumerators(idx):
    enum_str = _ct.create_unicode_buffer(MAX_DEVICE_ID_LEN)
    size = _wt.ULONG(MAX_DEVICE_ID_LEN)
    _raise_if(_CM_Enumerate_Enumerators(idx, enum_str, _ref(size), 0))
    return enum_str.value

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
    _sua.CM_Enumerate_Classes, (_wt.DWORD, _wt.ULONG, PGUID, _wt.ULONG)
    )

def CM_Enumerate_Classes(idx, flags=0):
    guid = GUID()
    _raise_if(_CM_Enumerate_Classes(idx, _ref(guid), flags))
    return guid.uuid()

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
    (_wt.BOOL, PGUID, _wt.LPWSTR, _wt.DWORD, _wt.PDWORD)
    )

def SetupDiClassNameFromGuid(guid):
    guid = GUID(guid)
    req_size = _wt.DWORD(0)
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
    _sua.SetupDiRemoveDevice, (_wt.BOOL, _wt.HANDLE, PSP_DEVINFO_DATA)
    )

def SetupDiRemoveDevice(info_set, deinda):
    _raise_if(not _SetupDiRemoveDevice(info_set, deinda))

################################################################################

_SetupDiCreateDeviceInfoList = _fun_fact(
    _sua.SetupDiCreateDeviceInfoList, (_wt.HANDLE, PGUID, _wt.HWND)
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
    (_wt.BOOL, _wt.HANDLE, PSP_DEVINFO_DATA, _wt.LPWSTR, _wt.DWORD, _wt.PDWORD)
    )

def SetupDiGetDeviceInstanceId(info_set, deinda):
    req_size = _wt.DWORD()
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
    (_wt.BOOL, _wt.HANDLE, _wt.LPWSTR, _wt.HWND, _wt.DWORD, PSP_DEVINFO_DATA)
    )

def SetupDiOpenDeviceInfo(info_set, inst_id, hwnd=None, flags=0, p_info=None):
    _raise_if(
        not _SetupDiOpenDeviceInfo(info_set, inst_id, hwnd, flags, p_info)
        )

################################################################################

_SetupDiClassGuidsFromNameEx = _fun_fact(
    _sua.SetupDiClassGuidsFromNameExW,
    (_wt.BOOL, _wt.LPWSTR, PGUID, _wt.DWORD, _wt.PDWORD, _wt.LPWSTR, _wt.LPVOID)
    )

def SetupDiClassGuidsFromNameEx(cls_name, machine_name=None):
    req_size = _wt.DWORD()
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
    while SetupDiEnumDeviceInfo(info_set, idx, _ref(deinda)):
        yield info_set, deinda
        idx += 1
    if cleanup:
        SetupDiDestroyDeviceInfoList(info_set)

################################################################################

def remove_non_present_devices():
    for iset, ddat in enum_info_set(get_non_present_info_set()):
        SetupDiRemoveDevice(iset, ddat)

################################################################################

_SetupDiSetClassInstallParams = _fun_fact(
    _sua.SetupDiSetClassInstallParamsW,
    (_wt.BOOL, _wt.HANDLE, PSP_DEVINFO_DATA, PSP_PROPCHANGE_PARAMS, _wt.DWORD)
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
    (_wt.BOOL, _wt.DWORD, _wt.HANDLE, PSP_DEVINFO_DATA)
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
        _wt.BOOL,
        _wt.HANDLE,
        PSP_DEVINFO_DATA,
        _wt.DWORD,
        _wt.PDWORD,
        _wt.PBYTE,
        _wt.DWORD,
        _wt.PDWORD
        )
    )

def SetupDiGetDeviceRegistryProperty(info_set, deinda, prop):
    reg_type = _wt.DWORD()
    req_size = _wt.DWORD()
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
            _ct.cast(buf, _wt.PBYTE),
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
