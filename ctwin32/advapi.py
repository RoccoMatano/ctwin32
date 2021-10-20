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
from types import SimpleNamespace as _namespace

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
    CRED_TYPE_GENERIC,
    )
from .kernel import LocalFree, GetLastError, FILETIME

_a32 = _ct.windll.advapi32
_ref = _ct.byref

################################################################################

# Do NOT wrap the following predefined keys in a CT_HKEY (see below), since
# these cannot be closed (ERROR_INVALID_HANDLE).
HKEY_CLASSES_ROOT        = _wt.HKEY(0x80000000)
HKEY_CURRENT_USER        = _wt.HKEY(0x80000001)
HKEY_LOCAL_MACHINE       = _wt.HKEY(0x80000002)
HKEY_USERS               = _wt.HKEY(0x80000003)
HKEY_PERFORMANCE_DATA    = _wt.HKEY(0x80000004)
HKEY_PERFORMANCE_TEXT    = _wt.HKEY(0x80000050)
HKEY_PERFORMANCE_NLSTEXT = _wt.HKEY(0x80000060)
HKEY_CURRENT_CONFIG      = _wt.HKEY(0x80000005)
HKEY_DYN_DATA            = _wt.HKEY(0x80000006)

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

class CT_HKEY(_wt.HKEY):

    ############################################################################

    def __init__(self, x):
        if (isinstance(x, _ct._SimpleCData)):
            self.value = x.value
        else:
            self.value = x

    ############################################################################

    # support for ctypes
    @classmethod
    def from_param(cls, obj):
        if isinstance(obj, cls) or isinstance(obj, _wt.HKEY):
            return obj
        elif isinstance(obj, int):
            return _wt.HKEY(obj)
        else:
            msg = (
                "Don't know how to convert from " +
                f"{type(obj).__name__} to {cls.__name__}"
                )
            raise TypeError(msg)

    ############################################################################

    def close(self):
        if self.value:
            RegCloseKey(self.value)
            self.value = 0

    Close = close

    ############################################################################

    def __enter__(self):
        return self

    ############################################################################

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()

    ############################################################################

    def __int__(self):
        return self.value

_PCT_HKEY = _ct.POINTER(CT_HKEY)

################################################################################

_RegCloseKey = _fun_fact(_a32.RegCloseKey, (_wt.LONG, CT_HKEY))

def RegCloseKey(key):
    _raise_on_err(_RegCloseKey(key))

################################################################################

_RegOpenKeyEx = _fun_fact(
    _a32.RegOpenKeyExW,
    (_wt.LONG, CT_HKEY, _wt.LPWSTR, _wt.DWORD, _wt.DWORD,_PCT_HKEY)
    )

def RegOpenKeyEx(parent, name, access=KEY_READ):
    key = CT_HKEY(0)
    _raise_on_err(_RegOpenKeyEx(parent, name, 0, access, _ref(key)))
    return key

################################################################################

_RegQueryInfoKey = _fun_fact(
    _a32.RegQueryInfoKeyW, (
        _wt.LONG,
        CT_HKEY,
        _wt.LPWSTR,
        _wt.PDWORD,
        _wt.PDWORD,
        _wt.PDWORD,
        _wt.PDWORD,
        _wt.PDWORD,
        _wt.PDWORD,
        _wt.PDWORD,
        _wt.PDWORD,
        _wt.PDWORD,
        _ct.POINTER(FILETIME)
        )
    )

def RegQueryInfoKey(key):
    num_sub_keys = _wt.DWORD()
    max_sub_key_len = _wt.DWORD()
    num_values = _wt.DWORD()
    max_value_name_len = _wt.DWORD()
    max_value_len = _wt.DWORD()
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
        _wt.LONG,
        CT_HKEY,
        _wt.LPWSTR,
        _wt.DWORD,
        _wt.LPWSTR,
        _wt.DWORD,
        _wt.DWORD,
        _wt.LPVOID,
        _PCT_HKEY,
        _wt.PDWORD,
        )
    )

def RegCreateKeyEx(parent, name, access=KEY_ALL_ACCESS):
    key = CT_HKEY(0)
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
    _a32.RegDeleteKeyExW, (_wt.LONG, CT_HKEY, _wt.LPWSTR, _wt.DWORD, _wt.DWORD)
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

_RegDeleteKeyValue = _fun_fact(
    _a32.RegDeleteKeyValueW, (_wt.LONG, CT_HKEY, _wt.LPWSTR, _wt.LPWSTR)
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
        _wt.LONG,
        CT_HKEY,
        _wt.DWORD,
        _wt.LPWSTR,
        _wt.PDWORD,
        _wt.PDWORD,
        _wt.PDWORD,
        _wt.PDWORD,
        _ct.POINTER(FILETIME)
        )
    )

def RegEnumKeyEx(key, index):
    name_len = _wt.DWORD(_MAX_KEY_LEN)
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

_RegEnumValue = _fun_fact(
    _a32.RegEnumValueW, (
        _wt.LONG,
        CT_HKEY,
        _wt.DWORD,
        _wt.LPWSTR,
        _wt.PDWORD,
        _wt.PDWORD,
        _wt.PDWORD,
        _wt.PBYTE,
        _wt.PDWORD,
        )
    )

def RegEnumValue(key, index):
    info = RegQueryInfoKey(key)
    nlen = _wt.DWORD(info.max_value_name_len + 1)
    vlen = _wt.DWORD(info.max_value_len + 1)
    name = _ct.create_unicode_buffer(nlen.value)
    value = _ct.create_string_buffer(vlen.value)
    typ = _wt.DWORD()
    while True:
        err = _RegEnumValue(
            key,
            index,
            name,
            _ref(nlen),
            None,
            _ref(typ),
            _ct.cast(value, _wt.PBYTE),
            _ref(vlen)
            )
        if err == 0:
            break
        elif err == ERROR_MORE_DATA:
            vlen = _wt.DWORD(vlen.value * 2)
            value = _ct.create_string_buffer(vlen.value)
        else:
            raise _ct.WinError(err)

    return (name.value,) + registry_to_py(typ.value, value.raw[:vlen.value])

################################################################################

_RegQueryValueEx = _fun_fact(
    _a32.RegQueryValueExW, (
        _wt.LONG,
        CT_HKEY,
        _wt.LPWSTR,
        _wt.PDWORD,
        _wt.PDWORD,
        _wt.PBYTE,
        _wt.PDWORD
        )
    )

def RegQueryValueEx(key, name):
    vlen = _wt.DWORD(256)
    value = _ct.create_string_buffer(vlen.value)
    typ = _wt.DWORD()
    while True:
        err = _RegQueryValueEx(
            key,
            name,
            None,
            _ref(typ),
            _ct.cast(value, _wt.PBYTE),
            _ref(vlen)
            )
        if err == 0:
            break
        elif err == ERROR_MORE_DATA:
            vlen = _wt.DWORD(vlen.value * 2)
            value = _ct.create_string_buffer(vlen.value)
        else:
            raise _ct.WinError(err)

    return registry_to_py(typ.value, value[:vlen.value])

################################################################################

_RegSetValueEx = _fun_fact(
    _a32.RegSetValueExW, (
        _wt.LONG,
        CT_HKEY,
        _wt.LPWSTR,
        _wt.DWORD,
        _wt.DWORD,
        _wt.PBYTE,
        _wt.DWORD,
        )
    )

def RegSetValueEx(key, name, typ, data):
    _raise_on_err(
        _RegSetValueEx(
            key,
            name,
            0,
            typ,
            _ref(data),
            len(data)
            )
        )

################################################################################

_IsValidSid = _fun_fact(_a32.IsValidSid, (_wt.BOOL, _wt.LPVOID))

def IsValidSid(psid):
    return _IsValidSid(psid) != 0

################################################################################

_GetLengthSid = _fun_fact(_a32.GetLengthSid, (_wt.DWORD, _wt.LPVOID))

def GetLengthSid(psid):
    if not IsValidSid(psid):
        raise ValueError(f"invalid SID: {psid}")
    return _GetLengthSid(psid)

################################################################################

_ConvertStringSidToSid = _fun_fact(
    _a32.ConvertStringSidToSidW, (_wt.BOOL, _wt.LPCWSTR, _wt.LPVOID)
    )

def ConvertStringSidToSid(string_sid):
    sid = _wt.LPVOID()
    try:
        _raise_if(not _ConvertStringSidToSid(string_sid, _ref(sid)))
        return _ct.string_at(sid, GetLengthSid(sid))
    finally:
        LocalFree(sid)

################################################################################

_ConvertSidToStringSid = _fun_fact(
    _a32.ConvertSidToStringSidW, (_wt.BOOL, _wt.LPVOID, _ct.POINTER(_wt.LPWSTR))
    )

def ConvertSidToStringSid(sid):
    bin_sid = _ct.create_string_buffer(sid)
    str_sid = _wt.LPWSTR()
    try:
        _raise_if(not _ConvertSidToStringSid(_ref(bin_sid), _ref(str_sid)))
        return _ct.wstring_at(str_sid)
    finally:
        LocalFree(str_sid)

################################################################################

_CheckTokenMembership = _fun_fact(
    _a32.CheckTokenMembership, (
        _wt.BOOL,
        _wt.HANDLE,
        _wt.LPVOID,
        _ct.POINTER(_wt.BOOL)
        )
    )

def CheckTokenMembership(token_handle, sid_to_check):
    res = _wt.BOOL()
    sid = _ct.create_string_buffer(sid_to_check)
    _raise_if(not _CheckTokenMembership(token_handle, _ref(sid), _ref(res)))
    return res.value != 0

################################################################################

def running_as_admin():
    # well known sid of aministrators group
    return CheckTokenMembership(None, ConvertStringSidToSid("S-1-5-32-544"))

################################################################################

_OpenProcessToken = _fun_fact(
    _a32.OpenProcessToken, (_wt.BOOL, _wt.HANDLE, _wt.DWORD, _wt.PHANDLE)
    )

def OpenProcessToken(proc_handle, desired_acc):
    token = _wt.HANDLE()
    _raise_if(not _OpenProcessToken(proc_handle, desired_acc, _ref(token)))
    return token

################################################################################

class LUID(_ct.Structure):
    _fields_ = (
        ("LowPart", _wt.DWORD),
        ("HighPart", _wt.LONG)
        )

_LookupPrivilegeValue = _fun_fact(
    _a32.LookupPrivilegeValueW, (
        _wt.BOOL,
        _wt.LPCWSTR,
        _wt.LPCWSTR,
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
        ("Attributes", _wt.DWORD)
        )

_AdjustTokenPrivileges = _a32.AdjustTokenPrivileges
_AdjustTokenPrivileges.restype = _wt.BOOL

def AdjustTokenPrivileges(token, luids_and_attributes, disable_all=False):
    num_la = len(luids_and_attributes)
    if not num_la:
        return

    class TOKEN_PRIVILEGES(_ct.Structure):
        _fields_ = (
            ("PrivilegeCount", _wt.DWORD),
            ("Privileges", LUID_AND_ATTRIBUTES * num_la)
            )
    _AdjustTokenPrivileges = _fun_fact(
        _a32.AdjustTokenPrivileges, (
            _wt.BOOL,
            _wt.HANDLE,
            _wt.BOOL,
            _ct.POINTER(TOKEN_PRIVILEGES),
            _wt.DWORD,
            _ct.POINTER(TOKEN_PRIVILEGES),
            _ct.POINTER(_wt.DWORD),
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

_CloseServiceHandle = _fun_fact(_a32.CloseServiceHandle, (_wt.BOOL, _wt.HANDLE))

def CloseServiceHandle(handle):
    _raise_if(not _CloseServiceHandle(handle))

################################################################################

_OpenSCManager = _fun_fact(
    _a32.OpenSCManagerW, (_wt.HANDLE, _wt.LPCWSTR, _wt.LPCWSTR, _wt.DWORD)
    )

def OpenSCManager(machine_name, database_name, desired_acc):
    res = _OpenSCManager(machine_name, database_name, desired_acc)
    _raise_if(not res)
    return res

################################################################################

_OpenService = _fun_fact(
    _a32.OpenServiceW, (_wt.HANDLE, _wt.HANDLE, _wt.LPCWSTR, _wt.DWORD)
    )

def OpenService(scm, name, desired_acc):
    res = _OpenService(scm, name, desired_acc)
    _raise_if(not res)
    return res

################################################################################

_CreateService = _fun_fact(
    _a32.CreateServiceW, (
        _wt.HANDLE,
        _wt.HANDLE,
        _wt.LPCWSTR,
        _wt.LPCWSTR,
        _wt.DWORD,
        _wt.DWORD,
        _wt.DWORD,
        _wt.DWORD,
        _wt.LPCWSTR,
        _wt.LPCWSTR,
        _wt.LPDWORD,
        _wt.LPCWSTR,
        _wt.LPCWSTR,
        _wt.LPCWSTR,
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
        _wt.BOOL,
        _wt.HANDLE,
        _wt.DWORD,
        _ct.POINTER(_wt.LPCWSTR)
        )
    )

def StartService(handle, args):
    if args:
        alen = len(args)
        argv = (_wt.LPCWSTR * alen)()
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
        ("ServiceType", _wt.DWORD),
        ("CurrentState", _wt.DWORD),
        ("ControlsAccepted", _wt.DWORD),
        ("Win32ExitCode", _wt.DWORD),
        ("ServiceSpecificExitCode", _wt.DWORD),
        ("CheckPoint", _wt.DWORD),
        ("WaitHint", _wt.DWORD),
        )

_ControlService = _fun_fact(
    _a32.ControlService, (
        _wt.BOOL,
        _wt.HANDLE,
        _wt.DWORD,
        _ct.POINTER(SERVICE_STATUS)
        )
    )

def ControlService(service, control):
    status = SERVICE_STATUS()
    _raise_if(not _ControlService(service, control, _ref(status)))
    return status

################################################################################

_DeleteService = _fun_fact(_a32.DeleteService, (_wt.BOOL, _wt.HANDLE))

def DeleteService(service):
    _raise_if(not _DeleteService(service))

################################################################################

class SERVICE_STATUS_PROCESS(_ct.Structure):
    _fields_ = (
        ("ServiceType", _wt.DWORD),
        ("CurrentState", _wt.DWORD),
        ("ControlsAccepted", _wt.DWORD),
        ("Win32ExitCode", _wt.DWORD),
        ("ServiceSpecificExitCode", _wt.DWORD),
        ("CheckPoint", _wt.DWORD),
        ("WaitHint", _wt.DWORD),
        ("ProcessId", _wt.DWORD),
        ("ServiceFlags", _wt.DWORD),
        )

_QueryServiceStatusEx = _fun_fact(
    _a32.QueryServiceStatusEx, (
        _wt.BOOL,
        _wt.HANDLE,
        _wt.INT,
        _ct.POINTER(SERVICE_STATUS_PROCESS),
        _wt.DWORD,
        _wt.LPDWORD
        )
    )

def QueryServiceStatusEx(service):
    status = SERVICE_STATUS_PROCESS()
    needed = _wt.DWORD()
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
        ("ServiceName", _wt.LPWSTR),
        ("DisplayName", _wt.LPWSTR),
        ("ServiceStatusProcess", SERVICE_STATUS_PROCESS),
        )

_EnumServicesStatusEx = _fun_fact(
    _a32.EnumServicesStatusExW, (
        _wt.BOOL,
        _wt.HANDLE,
        _wt.INT,
        _wt.DWORD,
        _wt.DWORD,
        _wt.LPBYTE,
        _wt.DWORD,
        _wt.LPDWORD,
        _wt.LPDWORD,
        _wt.LPDWORD,
        _wt.LPCWSTR
        )
    )

def EnumServicesStatusEx(scm, stype, sstate, group_name=None):
    esize = _ct.sizeof(ENUM_SERVICE_STATUS_PROCESS)
    ptr_type = _ct.POINTER(ENUM_SERVICE_STATUS_PROCESS)

    res = []
    buf = _ct.create_string_buffer(0)
    buf_len = 0
    needed = _wt.DWORD()
    num_ret = _wt.DWORD()
    resume = _wt.DWORD()

    while True:
        buf_addr = _ct.addressof(buf)
        suc = _EnumServicesStatusEx(
            scm,
            SC_ENUM_PROCESS_INFO,
            stype,
            sstate,
            _ct.cast(buf_addr, _wt.LPBYTE),
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
        ("Keyword", _wt.LPWSTR),
        ("Flags", _wt.DWORD),
        ("ValueSize", _wt.DWORD),
        ("Value", _wt.LPBYTE),
        )
PCREDENTIAL_ATTRIBUTE = _ct.POINTER(CREDENTIAL_ATTRIBUTE)

class CREDENTIAL(_ct.Structure):
    _fields_ = (
        ("Flags", _wt.DWORD),
        ("Type", _wt.DWORD),
        ("TargetName", _wt.LPWSTR),
        ("Comment", _wt.LPWSTR),
        ("LastWritten", FILETIME),
        ("CredentialBlobSize", _wt.DWORD),
        ("CredentialBlob", _wt.LPBYTE),
        ("Persist", _wt.DWORD),
        ("AttributeCount", _wt.DWORD),
        ("Attributes", PCREDENTIAL_ATTRIBUTE),
        ("TargetAlias", _wt.LPWSTR),
        ("UserName", _wt.LPWSTR),
        )
PCREDENTIAL = _ct.POINTER(CREDENTIAL)
PPCREDENTIAL = _ct.POINTER(PCREDENTIAL)
PPPCREDENTIAL = _ct.POINTER(PPCREDENTIAL)

_CredRead = _fun_fact(
    _a32.CredReadW, (
        _wt.BOOL,
        _wt.LPCWSTR,
        _wt.DWORD,
        _wt.DWORD,
        PPCREDENTIAL
        )
    )
_CredEnumerate = _fun_fact(
    _a32.CredEnumerateW, (
        _wt.BOOL,
        _wt.LPCWSTR,
        _wt.DWORD,
        _wt.PDWORD,
        PPPCREDENTIAL
        )
    )
_CredWrite = _fun_fact(_a32.CredWriteW, (_wt.BOOL, PCREDENTIAL, _wt.DWORD))
_CredFree = _fun_fact(_a32.CredFree, (None, _wt.LPVOID))

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
    cnt = _wt.DWORD()
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
        cred.CredentialBlob = (_wt.BYTE * len(val))(*tuple(map(int, val)))

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
                attr[i].Value = (_wt.BYTE * len(val))(*tuple(map(int, val)))
        cred.AttributeCount = len(ns_attr)
        cred.Attributes = _ct.cast(attr, PCREDENTIAL_ATTRIBUTE)

    _raise_if(not _CredWrite(_ref(cred), Flags))

################################################################################
