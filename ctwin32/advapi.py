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

import ctypes as _ct
from types import SimpleNamespace as _namespace
from datetime import datetime as _dt

from .wtypes import *
from . import (
    _raise_if,
    _raise_on_err,
    _fun_fact,
    REG_DWORD,
    REG_QWORD,
    REG_BINARY,
    REG_SZ,
    REG_EXPAND_SZ,
    REG_MULTI_SZ,
    KEY_READ,
    KEY_ALL_ACCESS,
    KEY_WOW64_64KEY,
    SC_ENUM_PROCESS_INFO,
    SC_STATUS_PROCESS_INFO,
    ERROR_MORE_DATA,
    ERROR_NO_MORE_ITEMS,
    ERROR_HANDLE_EOF,
    ERROR_INSUFFICIENT_BUFFER,
    CRED_TYPE_GENERIC,
    EVENTLOG_SEQUENTIAL_READ,
    EVENTLOG_BACKWARDS_READ,
    )
from .kernel import LocalFree, GetLastError

_a32 = _ct.windll.advapi32
_ref = _ct.byref

################################################################################

# values of predefined keys

_PREDEFINED_KEYS = {
    0x80000000: "HKEY_CLASSES_ROOT",
    0x80000001: "HKEY_CURRENT_USER",
    0x80000002: "HKEY_LOCAL_MACHINE",
    0x80000003: "HKEY_USERS",
    0x80000004: "HKEY_PERFORMANCE_DATA",
    0x80000050: "HKEY_PERFORMANCE_TEXT",
    0x80000060: "HKEY_PERFORMANCE_NLSTEXT",
    0x80000005: "HKEY_CURRENT_CONFIG",
    0x80000006: "HKEY_DYN_DATA",
    0x80000007: "HKEY_CURRENT_USER_LOCAL_SETTINGS",
    }

################################################################################

_RegCloseKey = _fun_fact(_a32.RegCloseKey, (LONG, HANDLE))

def RegCloseKey(key):
    _raise_on_err(_RegCloseKey(key))

################################################################################

class HKEY(ScdToBeClosed, HANDLE, close_func=RegCloseKey, invalid=0):

    def close(self):
        # predefined keys cannot be closed (ERROR_INVALID_HANDLE)
        if self.value not in _PREDEFINED_KEYS:
            super().close()

PHKEY = _ct.POINTER(HKEY)

################################################################################

# predefined keys as instances of HKEY
globals().update((n, HKEY(v)) for v, n in _PREDEFINED_KEYS.items())

HKCR = HKEY_CLASSES_ROOT
HKCU = HKEY_CURRENT_USER
HKLM = HKEY_LOCAL_MACHINE

################################################################################

def registry_to_py(reg_type, data):
    if reg_type in (REG_SZ, REG_EXPAND_SZ, REG_MULTI_SZ):
        if len(data) <= 1:
            result = [] if reg_type == REG_MULTI_SZ else ""
        else:
            if (len(data) & 1) != 0 and data[-1] == 0:
                data = data[:-1]
            result = data.decode("utf-16").strip("\0")
            if reg_type == REG_MULTI_SZ:
                result = result.split("\0")
    elif reg_type in (REG_DWORD, REG_QWORD) :
        result = int.from_bytes(data, byteorder="little", signed=False)
    else:
        result = data

    return result, reg_type

################################################################################

_RegOpenKeyEx = _fun_fact(
    _a32.RegOpenKeyExW,
    (LONG, HKEY, PWSTR, DWORD, DWORD, PHKEY)
    )

def RegOpenKeyEx(parent, name, access=KEY_READ):
    key = HKEY()
    _raise_on_err(_RegOpenKeyEx(parent, name, 0, access, _ref(key)))
    return key

################################################################################

_RegQueryInfoKey = _fun_fact(
    _a32.RegQueryInfoKeyW, (
        LONG,
        HKEY,
        PWSTR,
        PDWORD,
        PDWORD,
        PDWORD,
        PDWORD,
        PDWORD,
        PDWORD,
        PDWORD,
        PDWORD,
        PDWORD,
        PFILETIME
        )
    )

def RegQueryInfoKey(key):
    num_sub_keys = DWORD()
    max_sub_key_len = DWORD()
    num_values = DWORD()
    max_value_name_len = DWORD()
    max_value_len = DWORD()
    last_written = FILETIME()
    _raise_on_err(
        _RegQueryInfoKey(
            key.value,
            None,
            None,
            None,
            _ref(num_sub_keys),
            _ref(max_sub_key_len),
            None,
            _ref(num_values),
            _ref(max_value_name_len),
            _ref(max_value_len),
            None,
            _ref(last_written)
            )
        )
    return _namespace(
        num_sub_keys=num_sub_keys.value,
        max_sub_key_len=max_sub_key_len.value,
        num_values=num_values.value,
        max_value_name_len=max_value_name_len.value,
        max_value_len=max_value_len.value,
        last_written=last_written,
        )

################################################################################

_RegCreateKeyEx = _fun_fact(
    _a32.RegCreateKeyExW, (
        LONG,
        HKEY,
        PWSTR,
        DWORD,
        PWSTR,
        DWORD,
        DWORD,
        PVOID,
        PHKEY,
        PDWORD,
        )
    )

def RegCreateKeyEx(parent, name, access=KEY_ALL_ACCESS):
    key = HKEY()
    _raise_on_err(
        _RegCreateKeyEx(
            parent,
            name,
            0,
            0,
            access,
            None,
            _ref(key),
            None
            )
        )
    return key

################################################################################

_RegDeleteKeyEx = _fun_fact(
    _a32.RegDeleteKeyExW, (LONG, HKEY, PWSTR, DWORD, DWORD)
    )

def RegDeleteKeyEx(parent, name, access=KEY_WOW64_64KEY):
    _raise_on_err(
        _RegDeleteKeyEx(
            parent,
            name,
            assess,
            0
            )
        )

################################################################################

_RegDeleteValue = _fun_fact(
    _a32.RegDeleteValueW, (LONG, HKEY, PWSTR)
    )

def RegDeleteValue(key, name):
    _raise_on_err(_RegDeleteValue(key, name))

################################################################################

_RegDeleteKeyValue = _fun_fact(
    _a32.RegDeleteKeyValueW, (LONG, HKEY, PWSTR, PWSTR)
    )

def RegDeleteKeyValue(parent, key_name, value_name):
    _raise_on_err(
        _RegDeleteKeyValue(
            parent,
            key_name,
            value_name
            )
        )

################################################################################

# The Windows docs claim that the max key name length is 255 characters, plus
# a terminating null character.  However, empirical testing demonstrates that
# it is possible to create a 256 character key that is missing the terminating
# null.  RegEnumKeyEx requires a 257 character buffer to retrieve such a key
# name.
_MAX_KEY_LEN = 257

################################################################################

_RegEnumKeyEx = _fun_fact(
    _a32.RegEnumKeyExW, (
        LONG,
        HKEY,
        DWORD,
        PWSTR,
        PDWORD,
        PDWORD,
        PWSTR,
        PDWORD,
        PFILETIME
        )
    )

def RegEnumKeyEx(key, index):
    name_len = DWORD(_MAX_KEY_LEN)
    name = _ct.create_unicode_buffer(_MAX_KEY_LEN)
    _raise_on_err(
        _RegEnumKeyEx(
            key,
            index,
            name,
            _ref(name_len),
            None,
            None,
            None,
            None
            )
        )
    return name.value

################################################################################

def reg_enum_keys(key):
    index = 0
    while True:
        try:
            sub_key_name = RegEnumKeyEx(key, index)
            index += 1
            yield sub_key_name
        except OSError as e:
            if e.winerror == ERROR_NO_MORE_ITEMS:
                break
            else:
                raise

################################################################################


_RegEnumValue = _fun_fact(
    _a32.RegEnumValueW, (
        LONG,
        HKEY,
        DWORD,
        PWSTR,
        PDWORD,
        PDWORD,
        PDWORD,
        PBYTE,
        PDWORD,
        )
    )

def RegEnumValue(key, index):
    info = RegQueryInfoKey(key)
    nlen = DWORD(info.max_value_name_len + 1)
    vlen = DWORD(info.max_value_len + 1)
    name = _ct.create_unicode_buffer(nlen.value)
    value = _ct.create_string_buffer(vlen.value)
    typ = DWORD()
    while True:
        err = _RegEnumValue(
            key,
            index,
            name,
            _ref(nlen),
            None,
            _ref(typ),
            _ct.cast(value, PBYTE),
            _ref(vlen)
            )
        if err == 0:
            break
        elif err == ERROR_MORE_DATA:
            vlen = DWORD(vlen.value * 2)
            value = _ct.create_string_buffer(vlen.value)
        else:
            raise _ct.WinError(err)

    return (name.value,) + registry_to_py(typ.value, value.raw[:vlen.value])

################################################################################

def reg_enum_values(key):
    index = 0
    while True:
        try:
            tpl = RegEnumValue(key, index)
            index += 1
            yield tpl
        except OSError as e:
            if e.winerror == ERROR_NO_MORE_ITEMS:
                break
            else:
                raise

################################################################################

_RegQueryValueEx = _fun_fact(
    _a32.RegQueryValueExW, (
        LONG,
        HKEY,
        PWSTR,
        PDWORD,
        PDWORD,
        PBYTE,
        PDWORD
        )
    )

def RegQueryValueEx(key, name):
    vlen = DWORD(256)
    value = _ct.create_string_buffer(vlen.value)
    typ = DWORD()
    while True:
        err = _RegQueryValueEx(
            key,
            name,
            None,
            _ref(typ),
            _ct.cast(value, PBYTE),
            _ref(vlen)
            )
        if err == 0:
            break
        elif err == ERROR_MORE_DATA:
            vlen = DWORD(vlen.value * 2)
            value = _ct.create_string_buffer(vlen.value)
        else:
            raise _ct.WinError(err)

    return registry_to_py(typ.value, value[:vlen.value])

################################################################################

_RegSetValueEx = _fun_fact(
    _a32.RegSetValueExW, (
        LONG,
        HKEY,
        PWSTR,
        DWORD,
        DWORD,
        PVOID,
        DWORD,
        )
    )

def RegSetValueEx(key, name, typ, data):
    dta = _ct.create_string_buffer(data)
    _raise_on_err(
        _RegSetValueEx(
            key,
            name,
            0,
            typ,
            _ref(dta),
            len(data)
            )
        )

################################################################################

_RegSetKeyValue = _fun_fact(
    _a32.RegSetKeyValueW, (
        LONG,
        HKEY,
        PWSTR,
        PWSTR,
        DWORD,
        PVOID,
        DWORD,
        )
    )

def RegSetKeyValue(parent, key_name, value_name, typ, data):
    dta = _ct.create_string_buffer(data)
    _raise_on_err(
        _RegSetKeyValue(
            parent,
            key_name,
            value_name,
            typ,
            _ref(dta),
            len(data)
            )
        )

################################################################################

def reg_set_str(key, name, string, typ=None):
    typ = REG_SZ if typ is None else typ
    if not typ in (REG_SZ, REG_EXPAND_SZ, REG_MULTI_SZ):
        raise ValueError(f"invalid registry type: {typ}")
    value = _ct.create_unicode_buffer(string)
    _raise_on_err(
        _RegSetValueEx(
            key,
            name,
            0,
            typ,
            _ref(value),
            _ct.sizeof(value)
            )
        )

################################################################################

def reg_set_dword(key, name, dword):
    size = _ct.sizeof(DWORD)
    data = dword.to_bytes(size, 'little')
    _raise_on_err(
        _RegSetValueEx(
            key,
            name,
            0,
            REG_DWORD,
            _ref(data),
            size
            )
        )

################################################################################

_IsValidSid = _fun_fact(_a32.IsValidSid, (BOOL, PVOID))

def IsValidSid(psid):
    return _IsValidSid(psid) != 0

################################################################################

_GetLengthSid = _fun_fact(_a32.GetLengthSid, (DWORD, PVOID))

def GetLengthSid(psid):
    if not IsValidSid(psid):
        raise ValueError(f"invalid SID: {psid}")
    return _GetLengthSid(psid)

################################################################################

_ConvertStringSidToSid = _fun_fact(
    _a32.ConvertStringSidToSidW, (BOOL, PWSTR, PVOID)
    )

def ConvertStringSidToSid(string_sid):
    sid = PVOID()
    try:
        _raise_if(not _ConvertStringSidToSid(string_sid, _ref(sid)))
        return _ct.string_at(sid, GetLengthSid(sid))
    finally:
        LocalFree(sid)

################################################################################

_ConvertSidToStringSid = _fun_fact(
    _a32.ConvertSidToStringSidW, (BOOL, PVOID, PPWSTR)
    )

def ConvertSidToStringSid(sid):
    bin_sid = _ct.create_string_buffer(sid)
    str_sid = PWSTR()
    try:
        _raise_if(not _ConvertSidToStringSid(_ref(bin_sid), _ref(str_sid)))
        return _ct.wstring_at(str_sid)
    finally:
        LocalFree(str_sid)

################################################################################

_CheckTokenMembership = _fun_fact(
    _a32.CheckTokenMembership, (
        BOOL,
        HANDLE,
        PVOID,
        PBOOL
        )
    )

def CheckTokenMembership(token_handle, sid_to_check):
    res = BOOL()
    sid = _ct.create_string_buffer(sid_to_check)
    _raise_if(not _CheckTokenMembership(token_handle, _ref(sid), _ref(res)))
    return res.value != 0

################################################################################

def running_as_admin():
    # well known sid of aministrators group
    return CheckTokenMembership(None, ConvertStringSidToSid("S-1-5-32-544"))

################################################################################

_OpenProcessToken = _fun_fact(
    _a32.OpenProcessToken, (BOOL, HANDLE, DWORD, PHANDLE)
    )

def OpenProcessToken(proc_handle, desired_acc):
    token = HANDLE()
    _raise_if(not _OpenProcessToken(proc_handle, desired_acc, _ref(token)))
    return token

################################################################################

class LUID(_ct.Structure):
    _fields_ = (
        ("LowPart", DWORD),
        ("HighPart", LONG)
        )

_LookupPrivilegeValue = _fun_fact(
    _a32.LookupPrivilegeValueW, (
        BOOL,
        PWSTR,
        PWSTR,
        _ct.POINTER(LUID)
        )
    )

def LookupPrivilegeValue(sys_name, name):
    luid = LUID()
    _raise_if(not _LookupPrivilegeValue(sys_name, name, _ref(luid)))
    return luid

################################################################################

class LUID_AND_ATTRIBUTES(_ct.Structure):
    _fields_ = (
        ("Luid", LUID),
        ("Attributes", DWORD)
        )

_AdjustTokenPrivileges = _a32.AdjustTokenPrivileges
_AdjustTokenPrivileges.restype = BOOL

def AdjustTokenPrivileges(token, luids_and_attributes, disable_all=False):
    num_la = len(luids_and_attributes)
    if not num_la:
        return

    class TOKEN_PRIVILEGES(_ct.Structure):
        _fields_ = (
            ("PrivilegeCount", DWORD),
            ("Privileges", LUID_AND_ATTRIBUTES * num_la)
            )
    PTOKEN_PRIVILEGES = _ct.POINTER(TOKEN_PRIVILEGES)
    _AdjustTokenPrivileges = _fun_fact(
        _a32.AdjustTokenPrivileges, (
            BOOL,
            HANDLE,
            BOOL,
            PTOKEN_PRIVILEGES,
            DWORD,
            PTOKEN_PRIVILEGES,
            PDWORD,
            )
        )
    privs = TOKEN_PRIVILEGES()
    privs.PrivilegeCount = num_la
    for n, la in enumerate(luids_and_attributes):
        privs.Privileges[n].Luid = la.Luid
        privs.Privileges[n].Attributes = la.Attributes

    suc = _AdjustTokenPrivileges(
        token,
        disable_all,
        _ref(privs),
        0,
        None,
        None
        )
    _raise_if(not suc or _ct.GetLastError())

################################################################################

_CloseServiceHandle = _fun_fact(_a32.CloseServiceHandle, (BOOL, HANDLE))

def CloseServiceHandle(handle):
    _raise_if(not _CloseServiceHandle(handle))

################################################################################

_OpenSCManager = _fun_fact(
    _a32.OpenSCManagerW, (HANDLE, PWSTR, PWSTR, DWORD)
    )

def OpenSCManager(machine_name, database_name, desired_acc):
    res = _OpenSCManager(machine_name, database_name, desired_acc)
    _raise_if(not res)
    return res

################################################################################

_OpenService = _fun_fact(
    _a32.OpenServiceW, (HANDLE, HANDLE, PWSTR, DWORD)
    )

def OpenService(scm, name, desired_acc):
    res = _OpenService(scm, name, desired_acc)
    _raise_if(not res)
    return res

################################################################################

_CreateService = _fun_fact(
    _a32.CreateServiceW, (
        HANDLE,
        HANDLE,
        PWSTR,
        PWSTR,
        DWORD,
        DWORD,
        DWORD,
        DWORD,
        PWSTR,
        PWSTR,
        PDWORD,
        PWSTR,
        PWSTR,
        PWSTR,
        )
    )

def CreateService(
    scm,
    service_name,
    display_name,
    desired_acc,
    service_type,
    start_type,
    error_control,
    binary_path_name,
    load_order_group,
    dependencies,
    service_start_name,
    password
    ):
    res = _CreateService(
        scm,
        service_name,
        display_name,
        desired_acc,
        service_type,
        start_type,
        error_control,
        binary_path_name,
        load_order_group,
        None,
        _ct.create_unicode_buffer("\x00".join(dependencies)),
        service_start_name,
        password
        )
    _raise_if(not res)
    return res

################################################################################

_StartService = _fun_fact(
    _a32.StartServiceW, (
        BOOL,
        HANDLE,
        DWORD,
        PPWSTR
        )
    )

def StartService(handle, args):
    if args:
        alen = len(args)
        argv = (PWSTR * alen)()
        for n, a in enumerate(args):
            argv[n] = a
        pargv = _ref(argv)
    else:
        alen = 0
        pargv = None

    _raise_if(not _StartService(handle, alen, pargv))

################################################################################

class SERVICE_STATUS(_ct.Structure):
    _fields_ = (
        ("ServiceType", DWORD),
        ("CurrentState", DWORD),
        ("ControlsAccepted", DWORD),
        ("Win32ExitCode", DWORD),
        ("ServiceSpecificExitCode", DWORD),
        ("CheckPoint", DWORD),
        ("WaitHint", DWORD),
        )

_ControlService = _fun_fact(
    _a32.ControlService, (
        BOOL,
        HANDLE,
        DWORD,
        _ct.POINTER(SERVICE_STATUS)
        )
    )

def ControlService(service, control):
    status = SERVICE_STATUS()
    _raise_if(not _ControlService(service, control, _ref(status)))
    return status

################################################################################

_DeleteService = _fun_fact(_a32.DeleteService, (BOOL, HANDLE))

def DeleteService(service):
    _raise_if(not _DeleteService(service))

################################################################################

class SERVICE_STATUS_PROCESS(_ct.Structure):
    _fields_ = (
        ("ServiceType", DWORD),
        ("CurrentState", DWORD),
        ("ControlsAccepted", DWORD),
        ("Win32ExitCode", DWORD),
        ("ServiceSpecificExitCode", DWORD),
        ("CheckPoint", DWORD),
        ("WaitHint", DWORD),
        ("ProcessId", DWORD),
        ("ServiceFlags", DWORD),
        )

_QueryServiceStatusEx = _fun_fact(
    _a32.QueryServiceStatusEx, (
        BOOL,
        HANDLE,
        INT,
        _ct.POINTER(SERVICE_STATUS_PROCESS),
        DWORD,
        PDWORD
        )
    )

def QueryServiceStatusEx(service):
    status = SERVICE_STATUS_PROCESS()
    needed = DWORD()
    _raise_if(
        not _QueryServiceStatusEx(
            service,
            SC_STATUS_PROCESS_INFO,
            _ref(status),
            _ct.sizeof(status),
            _ref(needed)
            )
        )
    return status

################################################################################

class ENUM_SERVICE_STATUS_PROCESS(_ct.Structure):
    _fields_ = (
        ("ServiceName", PWSTR),
        ("DisplayName", PWSTR),
        ("ServiceStatusProcess", SERVICE_STATUS_PROCESS),
        )

_EnumServicesStatusEx = _fun_fact(
    _a32.EnumServicesStatusExW, (
        BOOL,
        HANDLE,
        INT,
        DWORD,
        DWORD,
        PBYTE,
        DWORD,
        PDWORD,
        PDWORD,
        PDWORD,
        PWSTR
        )
    )

def EnumServicesStatusEx(scm, stype, sstate, group_name=None):
    esize = _ct.sizeof(ENUM_SERVICE_STATUS_PROCESS)

    res = []
    buf = _ct.create_string_buffer(0)
    buf_len = 0
    needed = DWORD()
    num_ret = DWORD()
    resume = DWORD()

    while True:
        buf_addr = _ct.addressof(buf)
        suc = _EnumServicesStatusEx(
            scm,
            SC_ENUM_PROCESS_INFO,
            stype,
            sstate,
            _ct.cast(buf_addr, PBYTE),
            buf_len,
            _ref(needed),
            _ref(num_ret),
            _ref(resume),
            group_name
            )
        _raise_if(not suc and GetLastError() != ERROR_MORE_DATA)

        for n in range(num_ret.value):
            essp = ENUM_SERVICE_STATUS_PROCESS.from_address(
                buf_addr + n * esize
                )
            res.append(
                _namespace(
                    ServiceName=essp.ServiceName,
                    DisplayName=essp.DisplayName,
                    ServiceStatus=essp.ServiceStatusProcess
                    )
                )

        if suc:
            break
        buf = _ct.create_string_buffer(needed.value)
        buf_len = needed

    return res

################################################################################

class CREDENTIAL_ATTRIBUTE(_ct.Structure):
    _fields_ = (
        ("Keyword", PWSTR),
        ("Flags", DWORD),
        ("ValueSize", DWORD),
        ("Value", PBYTE),
        )
PCREDENTIAL_ATTRIBUTE = _ct.POINTER(CREDENTIAL_ATTRIBUTE)

class CREDENTIAL(_ct.Structure):
    _fields_ = (
        ("Flags", DWORD),
        ("Type", DWORD),
        ("TargetName", PWSTR),
        ("Comment", PWSTR),
        ("LastWritten", FILETIME),
        ("CredentialBlobSize", DWORD),
        ("CredentialBlob", PBYTE),
        ("Persist", DWORD),
        ("AttributeCount", DWORD),
        ("Attributes", PCREDENTIAL_ATTRIBUTE),
        ("TargetAlias", PWSTR),
        ("UserName", PWSTR),
        )
PCREDENTIAL = _ct.POINTER(CREDENTIAL)
PPCREDENTIAL = _ct.POINTER(PCREDENTIAL)
PPPCREDENTIAL = _ct.POINTER(PPCREDENTIAL)

_CredRead = _fun_fact(
    _a32.CredReadW, (
        BOOL,
        PWSTR,
        DWORD,
        DWORD,
        PPCREDENTIAL
        )
    )
_CredEnumerate = _fun_fact(
    _a32.CredEnumerateW, (
        BOOL,
        PWSTR,
        DWORD,
        PDWORD,
        PPPCREDENTIAL
        )
    )
_CredWrite = _fun_fact(_a32.CredWriteW, (BOOL, PCREDENTIAL, DWORD))
_CredFree = _fun_fact(_a32.CredFree, (None, PVOID))

################################################################################

def _ns_from_cred(cred):
    def a2ns(attr):
        return _namespace(
            Keyword=attr.Keyword,
            Flags=attr.Flags,
            Value=_ct.string_at(attr.Value, attr.ValueSize),
            )
    attr = tuple(a2ns(cred.Attributes[n]) for n in range(cred.AttributeCount))
    blob = _ct.string_at(cred.CredentialBlob,cred.CredentialBlobSize)
    return _namespace(
        TargetName=cred.TargetName,
        UserName=cred.UserName,
        CredentialBlob=blob,
        Attributes=attr,
        Flags=cred.Flags,
        Type=cred.Type,
        Comment=cred.Comment,
        LastWritten=cred.LastWritten,
        Persist=cred.Persist,
        TargetAlias=cred.TargetAlias,
        )

################################################################################

def CreadRead(TargetName, Type=CRED_TYPE_GENERIC, Flags=0):
    ptr = PCREDENTIAL()
    try:
        _raise_if(not _CredRead(TargetName, Type, Flags, _ref(ptr)))
        return _ns_from_cred(ptr.contents)
    finally:
        _CredFree(ptr)

################################################################################

def CredEnumerate(Filter=None, Flags=0):
    pptr = PPCREDENTIAL()
    cnt = DWORD()
    try:
        _raise_if(not _CredEnumerate(Filter, Flags, _ref(cnt), _ref(pptr)))
        return tuple(_ns_from_cred(pptr[n].contents) for n in range(cnt.value))
    finally:
        _CredFree(pptr)

################################################################################

def CredWrite(Credential, Flags=0):

    ################################ std fields ################################

    std_fields = (
        "Flags",
        "Type",
        "TargetName",
        "Comment",
        "LastWritten",
        "Persist",
        "TargetAlias",
        "UserName",
        )
    cred = CREDENTIAL()
    for f in std_fields:
        val = getattr(Credential, f, None)
        if val is not None:
            setattr(cred, f, val)

    ################################### blob ###################################

    val = getattr(Credential, "CredentialBlob", None)
    if val is not None:
        cred.CredentialBlobSize = len(val)
        cred.CredentialBlob = (BYTE * len(val))(*tuple(map(int, val)))

    ################################ attributes ################################

    ns_attr = getattr(Credential, "Attributes", None)
    if ns_attr:
        attr = (CREDENTIAL_ATTRIBUTE * len(ns_attr))()
        for i, a in enumerate(ns_attr):
            for f in ("Keyword", "Flags"):
                val = getattr(a, f, None)
                if val is not None:
                    setattr(attr[i], f, val)
            val = getattr(a, "Value", None)
            if val:
                attr[i].ValueSize = len(val)
                attr[i].Value = (BYTE * len(val))(*tuple(map(int, val)))
        cred.AttributeCount = len(ns_attr)
        cred.Attributes = _ct.cast(attr, PCREDENTIAL_ATTRIBUTE)

    _raise_if(not _CredWrite(_ref(cred), Flags))

################################################################################

_CloseEventLog = _fun_fact(_a32.CloseEventLog, (BOOL, HANDLE))

def CloseEventLog(hdl):
    _raise_if(not _CloseEventLog(hdl))

################################################################################

class EHANDLE(ScdToBeClosed, HANDLE, close_func=CloseEventLog, invalid=0):
    pass

################################################################################

_OpenEventLog = _fun_fact(
    _a32.OpenEventLogW, (HANDLE, PWSTR, PWSTR,)
    )

def OpenEventLog(source, server=None):
    hdl = EHANDLE(_OpenEventLog(server, source))
    _raise_if(not hdl.is_valid())
    return hdl

################################################################################

class EVENTLOGRECORD(_ct.Structure):
    _fields_ = (
        ("Length", DWORD),
        ("Reserved", DWORD),
        ("RecordNumber", DWORD),
        ("TimeGenerated", DWORD),
        ("TimeWritten", DWORD),
        ("EventID", DWORD),
        ("EventType", WORD),
        ("NumStrings", WORD),
        ("EventCategory", WORD),
        ("ReservedFlags", WORD),
        ("ClosingRecordNumber", DWORD),
        ("StringOffset", DWORD),
        ("UserSidLength", DWORD),
        ("UserSidOffset", DWORD),
        ("DataLength", DWORD),
        ("DataOffset", DWORD),
        #
        # followed by:
        #
        # WCHAR SourceName[]
        # WCHAR Computername[]
        # SID   UserSid
        # WCHAR Strings[]
        # BYTE  Data[]
        # CHAR  Pad[]
        # DWORD Length;
        )

PEVENTLOGRECORD = _ct.POINTER(EVENTLOGRECORD)

################################################################################

def _evt_from_void_p(vpelr):
    # vpelr is _ct.c_void_p for simpler address calculations
    strins = []
    elr = _ct.cast(vpelr, PEVENTLOGRECORD).contents
    if elr.NumStrings:
        stroffs = elr.StringOffset
        for i in range(elr.NumStrings):
            nxt = _ct.wstring_at(vpelr.value + stroffs)
            stroffs += (len(nxt) + 1) * _ct.sizeof(WCHAR)
            strins.append(nxt)
    sid = ""
    if elr.UserSidLength:
        sid = ConvertSidToStringSid(
            _ct.string_at(vpelr.value + elr.UserSidOffset)
            )
    data = _ct.string_at(vpelr.value + elr.DataOffset, elr.DataLength)
    p_str = vpelr.value + _ct.sizeof(EVENTLOGRECORD);
    src_name = _ct.wstring_at(p_str)
    p_str += (len(src_name) + 1) * _ct.sizeof(WCHAR)
    computer_name = _ct.wstring_at(p_str)

    return elr.Length, _namespace(
        ClosingRecordNumber=elr.ClosingRecordNumber,
        ComputerName=computer_name,
        Data=data,
        EventCategory=elr.EventCategory,
        EventID=elr.EventID,
        EventType=elr.EventType,
        RecordNumber=elr.RecordNumber,
        Reserved=elr.Reserved,
        ReservedFlags=elr.ReservedFlags,
        Sid=sid,
        SourceName=src_name,
        StringInserts=strins,
        TimeGenerated=_dt.fromtimestamp(elr.TimeGenerated),
        TimeWritten=_dt.fromtimestamp(elr.TimeWritten),
        )

################################################################################

_ReadEventLog = _fun_fact(
    _a32.ReadEventLogW, (
        BOOL,
        HANDLE,
        DWORD,
        DWORD,
        PVOID,
        DWORD,
        PDWORD,
        PDWORD,
        )
    )

def ReadEventLog(hdl, flags=None, offs=0, size=16384):
    if flags is None:
        flags = EVENTLOG_SEQUENTIAL_READ | EVENTLOG_BACKWARDS_READ
    want = DWORD(size)
    while True:
        got = DWORD()
        buf = _ct.create_string_buffer(want.value)
        ok = _ReadEventLog(hdl, flags, offs, buf, want, _ref(got), _ref(want))
        got = got.value
        if not ok:
            err = GetLastError()
            if err == ERROR_HANDLE_EOF:
                got = 0
                break
            elif err == ERROR_INSUFFICIENT_BUFFER:
                continue
            else:
                raise _ct.WinError(err)
        else:
            break

    res = []
    addr = _ct.addressof(buf)
    while got > 0:
        elen, evt = _evt_from_void_p(_ct.c_void_p(addr))
        res.append(evt)
        addr += elen
        got -= elen
    return res

################################################################################
