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

from types import SimpleNamespace as _namespace
from datetime import datetime as _dt

from .wtypes import *
from . import (
    ref,
    raise_if,
    raise_on_zero,
    raise_on_err,
    fun_fact,
    ns_from_struct,
    REG_DWORD,
    REG_QWORD,
    REG_BINARY,
    REG_SZ,
    REG_EXPAND_SZ,
    REG_MULTI_SZ,
    KEY_READ,
    KEY_ALL_ACCESS,
    KEY_WOW64_64KEY,
    OWNER_SECURITY_INFORMATION,
    GROUP_SECURITY_INFORMATION,
    DACL_SECURITY_INFORMATION,
    SACL_SECURITY_INFORMATION,
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
from .kernel import LocalFree, GetLastError, KHANDLE

_adv = ctypes.WinDLL("advapi32.dll")

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

_RegCloseKey = fun_fact(_adv.RegCloseKey, (LONG, HANDLE))

def RegCloseKey(key):
    raise_on_err(_RegCloseKey(key))

################################################################################

class HKEY(ScdToBeClosed, HANDLE, close_func=RegCloseKey, invalid=0):

    def close(self):
        # predefined keys cannot be closed (ERROR_INVALID_HANDLE)
        if self.value not in _PREDEFINED_KEYS:
            super().close()

PHKEY = POINTER(HKEY)

################################################################################

# predefined keys as instances of HKEY
globals().update((n, HKEY(v)) for v, n in _PREDEFINED_KEYS.items())

HKCR = HKEY_CLASSES_ROOT
HKCU = HKEY_CURRENT_USER
HKLM = HKEY_LOCAL_MACHINE

################################################################################

def is_registry_string(reg_type):
    return reg_type in (REG_SZ, REG_EXPAND_SZ, REG_MULTI_SZ)

################################################################################

def registry_to_py(reg_type, data):
    if is_registry_string(reg_type):
        if len(data) <= 1:
            result = [] if reg_type == REG_MULTI_SZ else ""
        else:
            if (len(data) & 1) != 0 and data[-1] == 0:
                data = data[:-1]
            result = data.decode("utf-16").strip("\0")
            if reg_type == REG_MULTI_SZ:
                result = result.split("\0")
    elif reg_type in (REG_DWORD, REG_QWORD) :
        result = int.from_bytes(data, byteorder=ENDIANNESS, signed=False)
    else:
        result = data

    return result, reg_type

################################################################################

_RegOpenKeyEx = fun_fact(
    _adv.RegOpenKeyExW,
    (LONG, HKEY, PWSTR, DWORD, DWORD, PHKEY)
    )

def RegOpenKeyEx(parent, name, access=KEY_READ):
    key = HKEY()
    raise_on_err(_RegOpenKeyEx(parent, name, 0, access, ref(key)))
    return key

################################################################################

_RegQueryInfoKey = fun_fact(
    _adv.RegQueryInfoKeyW, (
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
    raise_on_err(
        _RegQueryInfoKey(
            key,
            None,
            None,
            None,
            ref(num_sub_keys),
            ref(max_sub_key_len),
            None,
            ref(num_values),
            ref(max_value_name_len),
            ref(max_value_len),
            None,
            ref(last_written)
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

_RegCreateKeyEx = fun_fact(
    _adv.RegCreateKeyExW, (
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
    raise_on_err(
        _RegCreateKeyEx(
            parent,
            name,
            0,
            0,
            access,
            None,
            ref(key),
            None
            )
        )
    return key

################################################################################

_RegDeleteKeyEx = fun_fact(
    _adv.RegDeleteKeyExW, (LONG, HKEY, PWSTR, DWORD, DWORD)
    )

def RegDeleteKeyEx(parent, name, access=KEY_WOW64_64KEY):
    raise_on_err(
        _RegDeleteKeyEx(
            parent,
            name,
            assess,
            0
            )
        )

################################################################################

_RegDeleteValue = fun_fact(
    _adv.RegDeleteValueW, (LONG, HKEY, PWSTR)
    )

def RegDeleteValue(key, name):
    raise_on_err(_RegDeleteValue(key, name))

################################################################################

_RegDeleteKeyValue = fun_fact(
    _adv.RegDeleteKeyValueW, (LONG, HKEY, PWSTR, PWSTR)
    )

def RegDeleteKeyValue(parent, key_name, value_name):
    raise_on_err(
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

_RegEnumKeyEx = fun_fact(
    _adv.RegEnumKeyExW, (
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
    name = ctypes.create_unicode_buffer(_MAX_KEY_LEN)
    raise_on_err(
        _RegEnumKeyEx(
            key,
            index,
            name,
            ref(name_len),
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

_RegEnumValue = fun_fact(
    _adv.RegEnumValueW, (
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
    name = ctypes.create_unicode_buffer(nlen.value)
    value = ctypes.create_string_buffer(vlen.value)
    typ = DWORD()
    while True:
        err = _RegEnumValue(
            key,
            index,
            name,
            ref(nlen),
            None,
            ref(typ),
            ctypes.cast(value, PBYTE),
            ref(vlen)
            )
        if err == 0:
            break
        elif err == ERROR_MORE_DATA:
            vlen = DWORD(vlen.value * 2)
            value = ctypes.create_string_buffer(vlen.value)
        else:
            raise ctypes.WinError(err)

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

_RegQueryValueEx = fun_fact(
    _adv.RegQueryValueExW, (
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
    value = ctypes.create_string_buffer(vlen.value)
    typ = DWORD()
    while True:
        err = _RegQueryValueEx(
            key,
            name,
            None,
            ref(typ),
            ctypes.cast(value, PBYTE),
            ref(vlen)
            )
        if err == 0:
            break
        elif err == ERROR_MORE_DATA:
            vlen = DWORD(vlen.value * 2)
            value = ctypes.create_string_buffer(vlen.value)
        else:
            raise ctypes.WinError(err)

    return registry_to_py(typ.value, value[:vlen.value])

################################################################################

_RegSetValueEx = fun_fact(
    _adv.RegSetValueExW, (
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
    dta = ctypes.create_string_buffer(data)
    raise_on_err(
        _RegSetValueEx(
            key,
            name,
            0,
            typ,
            ref(dta),
            len(data)
            )
        )

################################################################################

_RegSetKeyValue = fun_fact(
    _adv.RegSetKeyValueW, (
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
    dta = ctypes.create_string_buffer(data)
    raise_on_err(
        _RegSetKeyValue(
            parent,
            key_name,
            value_name,
            typ,
            ref(dta),
            len(data)
            )
        )

################################################################################

def reg_set_str(key, name, string, typ=None):
    typ = REG_SZ if typ is None else typ
    if not is_registry_string(typ):
        raise ValueError(f"invalid registry type: {typ}")
    value = ctypes.create_unicode_buffer(string, len(string))
    raise_on_err(
        _RegSetValueEx(
            key,
            name,
            0,
            typ,
            ref(value),
            ctypes.sizeof(value)
            )
        )

################################################################################

def reg_set_dword(key, name, dword):
    size = ctypes.sizeof(DWORD)
    data = dword.to_bytes(size, ENDIANNESS)
    raise_on_err(
        _RegSetValueEx(
            key,
            name,
            0,
            REG_DWORD,
            ref(data),
            size
            )
        )

################################################################################

_IsValidSid = fun_fact(_adv.IsValidSid, (BOOL, PVOID))

def IsValidSid(psid):
    return _IsValidSid(psid) != 0

################################################################################

_GetLengthSid = fun_fact(_adv.GetLengthSid, (DWORD, PVOID))

def GetLengthSid(psid):
    if not IsValidSid(psid):
        raise ValueError(f"invalid SID: {psid:x}")
    return _GetLengthSid(psid)

################################################################################

_ConvertStringSidToSid = fun_fact(
    _adv.ConvertStringSidToSidW, (BOOL, PWSTR, PVOID)
    )

def ConvertStringSidToSid(string_sid):
    sid = PVOID()
    try:
        raise_on_zero(_ConvertStringSidToSid(string_sid, ref(sid)))
        return ctypes.string_at(sid, GetLengthSid(sid))
    finally:
        LocalFree(sid)

################################################################################

_ConvertSidToStringSid = fun_fact(
    _adv.ConvertSidToStringSidW, (BOOL, PVOID, PPWSTR)
    )

def ConvertSidToStringSid(sid):
    bin_sid = ctypes.create_string_buffer(sid)
    str_sid = PWSTR()
    try:
        raise_on_zero(_ConvertSidToStringSid(ref(bin_sid), ref(str_sid)))
        return ctypes.wstring_at(str_sid)
    finally:
        LocalFree(str_sid)

################################################################################

_CheckTokenMembership = fun_fact(
    _adv.CheckTokenMembership, (
        BOOL,
        HANDLE,
        PVOID,
        PBOOL
        )
    )

def CheckTokenMembership(token_handle, sid_to_check):
    res = BOOL()
    sid = ctypes.create_string_buffer(sid_to_check)
    raise_on_zero(_CheckTokenMembership(token_handle, ref(sid), ref(res)))
    return res.value != 0

################################################################################

def running_as_admin():
    # well known sid of aministrators group
    return CheckTokenMembership(None, ConvertStringSidToSid("S-1-5-32-544"))

################################################################################

_OpenProcessToken = fun_fact(
    _adv.OpenProcessToken, (BOOL, HANDLE, DWORD, PHANDLE)
    )

def OpenProcessToken(proc_handle, desired_acc):
    token = KHANDLE()
    raise_on_zero(_OpenProcessToken(proc_handle, desired_acc, ref(token)))
    return token

################################################################################

_LookupPrivilegeValue = fun_fact(
    _adv.LookupPrivilegeValueW, (BOOL, PWSTR, PWSTR, PLUID)
    )

def LookupPrivilegeValue(sys_name, name):
    luid = LUID()
    raise_on_zero(_LookupPrivilegeValue(sys_name, name, ref(luid)))
    return luid

################################################################################

class LUID_AND_ATTRIBUTES(ctypes.Structure):
    _fields_ = (
        ("Luid", LUID),
        ("Attributes", DWORD)
        )

_AdjustTokenPrivileges = _adv.AdjustTokenPrivileges
_AdjustTokenPrivileges.restype = BOOL

def AdjustTokenPrivileges(token, luids_and_attributes, disable_all=False):
    num_la = len(luids_and_attributes)
    if not num_la:
        return

    class TOKEN_PRIVILEGES(ctypes.Structure):
        _fields_ = (
            ("PrivilegeCount", DWORD),
            ("Privileges", LUID_AND_ATTRIBUTES * num_la)
            )
    PTOKEN_PRIVILEGES = POINTER(TOKEN_PRIVILEGES)
    _AdjustTokenPrivileges = fun_fact(
        _adv.AdjustTokenPrivileges, (
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
        ref(privs),
        0,
        None,
        None
        )
    raise_if(not suc or ctypes.GetLastError())

################################################################################

_LookupAccountSid = fun_fact(
    _adv.LookupAccountSidW,
    (BOOL, PWSTR, PVOID, PWSTR, PDWORD, PWSTR, PDWORD, PDWORD)
    )

def LookupAccountSid(sid, system_name=None):
    name_size = DWORD(0)
    domain_size = DWORD(0)
    sid_use = DWORD()
    ok = _LookupAccountSid(
        system_name,
        sid,
        None,
        ref(name_size),
        None,
        ref(domain_size),
        ref(sid_use)
        )
    err = GetLastError()
    if ok:
        raise AssertionError("logic error in LookupAccountSid")
    if err != ERROR_INSUFFICIENT_BUFFER:
        raise ctypes.WinError(err)

    name = ctypes.create_unicode_buffer(name_size.value)
    domain = ctypes.create_unicode_buffer(domain_size.value)
    raise_on_zero(
        _LookupAccountSid(
            system_name,
            sid,
            name,
            ref(name_size),
            domain,
            ref(domain_size),
            ref(sid_use)
            )
        )
    return name.value, domain.value, sid_use.value

################################################################################

class ACL(ctypes.Structure):
    _fields_ = (
        ("AclRevision", BYTE),
        ("Sbz1", BYTE),
        ("AclSize", WORD),
        ("AceCount", WORD),
        ("Sbz2", WORD),
        )
PACL = POINTER(ACL)
PPACL = POINTER(PACL)

class ACE_HEADER(ctypes.Structure):
    _fields_ = (
        ("AceType", BYTE),
        ("AceFlags", BYTE),
        ("AceSize", WORD),
        )

class ACE(ctypes.Structure):
    _fields_ = (
        ("Header", ACE_HEADER),
        ("Mask", DWORD),

        # first DWORD of SID, remaining bytes of the SID are stored in
        # contiguous memory after SidStart
        ("SidStart", DWORD),
        )
PACE = POINTER(ACE)
PPACE = POINTER(PACE)

class ACL_SIZE_INFORMATION(ctypes.Structure):
    _fields_ = (
        ("AceCount", DWORD),
        ("AclBytesInUse", DWORD),
        ("AclBytesFree", DWORD),
        )

################################################################################

_GetAce = fun_fact(
    _adv.GetAce,
    (BOOL, PACL, DWORD, PPACE)
    )

def GetAce(pacl, idx):
    pace = PACE()
    raise_on_zero(_GetAce(pacl, idx, ref(pace)))
    return pace

################################################################################

_GetSecurityDescriptorDacl = fun_fact(
    _adv.GetSecurityDescriptorDacl,
    (BOOL, PVOID, PBOOL, PPACL, PBOOL)
    )

def GetSecurityDescriptorDacl(sd):
    present = BOOL()
    pacl = PACL()
    defaulted = BOOL()
    raise_on_zero(
        _GetSecurityDescriptorDacl(
            sd,
            ref(present),
            ref(pacl),
            ref(defaulted)
            )
        )
    return present, pacl, defaulted

################################################################################

_GetSecurityDescriptorOwner = fun_fact(
    _adv.GetSecurityDescriptorOwner,
    (BOOL, PVOID, PVOID, PBOOL)
    )

def GetSecurityDescriptorOwner(sd):
    psid = PVOID()
    defaulted = BOOL()
    raise_on_zero(
        _GetSecurityDescriptorOwner(
            sd,
            ref(psid),
            ref(defaulted)
            )
        )
    return ctypes.string_at(psid, GetLengthSid(psid)), defaulted

################################################################################

_GetSecurityDescriptorGroup = fun_fact(
    _adv.GetSecurityDescriptorGroup,
    (BOOL, PVOID, PVOID, PBOOL)
    )

def GetSecurityDescriptorGroup(sd):
    psid = PVOID()
    defaulted = BOOL()
    raise_on_zero(
        _GetSecurityDescriptorGroup(
            sd,
            ref(psid),
            ref(defaulted)
            )
        )
    return ctypes.string_at(psid, GetLengthSid(psid)), defaulted

################################################################################

GetSecurityDescriptorLength = fun_fact(
    _adv.GetSecurityDescriptorLength, (DWORD, PVOID)
    )

################################################################################

_GetNamedSecurityInfo = fun_fact(
    _adv.GetNamedSecurityInfoW,
    (DWORD, PWSTR, DWORD, DWORD, PPVOID, PPVOID, PPVOID, PPVOID, PPVOID)
    )

NEARLY_ALL_SECURITY_INFORMATION = (
    OWNER_SECURITY_INFORMATION |
    GROUP_SECURITY_INFORMATION |
    DACL_SECURITY_INFORMATION
    )

def GetNamedSecurityInfo(name, otype, req_info=NEARLY_ALL_SECURITY_INFORMATION):
    pOwner = PVOID()
    pGroup = PVOID()
    pDacl = PVOID()
    pSacl = PVOID()
    pSD = PVOID()
    raise_on_err(
        _GetNamedSecurityInfo(
            name,
            otype,
            req_info,
            ref(pOwner),
            ref(pGroup),
            ref(pDacl),
            ref(pSacl),
            ref(pSD)
            )
        )
    try:
        return ctypes.string_at(pSD.value, GetSecurityDescriptorLength(pSD))
    finally:
        LocalFree(pSD)

################################################################################

_SetNamedSecurityInfo = fun_fact(
    _adv.SetNamedSecurityInfoW,
    (DWORD, PWSTR, DWORD, DWORD, PVOID, PVOID, PVOID, PVOID)
    )

def SetNamedSecurityInfo(
    name,
    otype,
    *,
    owner=None,
    group=None,
    dacl=None,
    sacl=None
    ):
    set_info = 0
    if owner is not None:
        set_info |= OWNER_SECURITY_INFORMATION
    if group is not None:
        set_info |= GROUP_SECURITY_INFORMATION
    if dacl is not None:
        set_info |= DACL_SECURITY_INFORMATION
    if sacl is not None:
        set_info |= SACL_SECURITY_INFORMATION
    raise_on_err(
        _SetNamedSecurityInfo(
            name,
            otype,
            set_info,
            owner,
            group,
            dacl,
            sacl
            )
        )

################################################################################

_CloseServiceHandle = fun_fact(_adv.CloseServiceHandle, (BOOL, HANDLE))

def CloseServiceHandle(handle):
    raise_on_zero(_CloseServiceHandle(handle))

################################################################################

class SC_HANDLE(ScdToBeClosed, HANDLE, close_func=CloseServiceHandle, invalid=0):
    pass

################################################################################

_OpenSCManager = fun_fact(
    _adv.OpenSCManagerW, (HANDLE, PWSTR, PWSTR, DWORD)
    )

def OpenSCManager(machine_name, database_name, desired_acc):
    res = SC_HANDLE(_OpenSCManager(machine_name, database_name, desired_acc))
    res.raise_on_invalid()
    return res

################################################################################

_OpenService = fun_fact(
    _adv.OpenServiceW, (HANDLE, HANDLE, PWSTR, DWORD)
    )

def OpenService(scm, name, desired_acc):
    res = SC_HANDLE(_OpenService(scm, name, desired_acc))
    res.raise_on_invalid()
    return res

################################################################################

_CreateService = fun_fact(
    _adv.CreateServiceW, (
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
    res = SC_HANDLE(
        _CreateService(
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
            ctypes.create_unicode_buffer("\x00".join(dependencies)),
            service_start_name,
            password
            )
        )
    res.raise_on_invalid()
    return res

################################################################################

_StartService = fun_fact(
    _adv.StartServiceW, (
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
        pargv = ref(argv)
    else:
        alen = 0
        pargv = None

    raise_on_zero(_StartService(handle, alen, pargv))

################################################################################

class SERVICE_STATUS(ctypes.Structure):
    _fields_ = (
        ("ServiceType", DWORD),
        ("CurrentState", DWORD),
        ("ControlsAccepted", DWORD),
        ("Win32ExitCode", DWORD),
        ("ServiceSpecificExitCode", DWORD),
        ("CheckPoint", DWORD),
        ("WaitHint", DWORD),
        )

_ControlService = fun_fact(
    _adv.ControlService, (
        BOOL,
        HANDLE,
        DWORD,
        POINTER(SERVICE_STATUS)
        )
    )

def ControlService(service, control):
    status = SERVICE_STATUS()
    raise_on_zero(_ControlService(service, control, ref(status)))
    return status

################################################################################

_DeleteService = fun_fact(_adv.DeleteService, (BOOL, HANDLE))

def DeleteService(service):
    raise_on_zero(_DeleteService(service))

################################################################################

class SERVICE_STATUS_PROCESS(ctypes.Structure):
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

_QueryServiceStatusEx = fun_fact(
    _adv.QueryServiceStatusEx, (
        BOOL,
        HANDLE,
        INT,
        POINTER(SERVICE_STATUS_PROCESS),
        DWORD,
        PDWORD
        )
    )

def QueryServiceStatusEx(service):
    status = SERVICE_STATUS_PROCESS()
    needed = DWORD()
    raise_on_zero(
        _QueryServiceStatusEx(
            service,
            SC_STATUS_PROCESS_INFO,
            ref(status),
            ctypes.sizeof(status),
            ref(needed)
            )
        )
    return status

################################################################################

class ENUM_SERVICE_STATUS_PROCESS(ctypes.Structure):
    _fields_ = (
        ("ServiceName", PWSTR),
        ("DisplayName", PWSTR),
        ("ServiceStatusProcess", SERVICE_STATUS_PROCESS),
        )

_EnumServicesStatusEx = fun_fact(
    _adv.EnumServicesStatusExW, (
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
    esize = ctypes.sizeof(ENUM_SERVICE_STATUS_PROCESS)

    res = []
    buf = ctypes.create_string_buffer(0)
    buf_len = 0
    needed = DWORD()
    num_ret = DWORD()
    resume = DWORD()

    while True:
        buf_addr = ctypes.addressof(buf)
        suc = _EnumServicesStatusEx(
            scm,
            SC_ENUM_PROCESS_INFO,
            stype,
            sstate,
            ctypes.cast(buf_addr, PBYTE),
            buf_len,
            ref(needed),
            ref(num_ret),
            ref(resume),
            group_name
            )
        raise_if(not suc and GetLastError() != ERROR_MORE_DATA)

        for n in range(num_ret.value):
            essp = ENUM_SERVICE_STATUS_PROCESS.from_address(
                buf_addr + n * esize
                )
            res.append(ns_from_struct(essp))

        if suc:
            break
        buf = ctypes.create_string_buffer(needed.value)
        buf_len = needed

    return res

################################################################################

class QUERY_SERVICE_CONFIG(ctypes.Structure):
    _fields_ = (
        ("ServiceType", DWORD),
        ("StartType", DWORD),
        ("ErrorControl", DWORD),
        ("BinaryPathName", DWORD),
        ("LoadOrderGroup", DWORD),
        ("TagId", DWORD),
        ("Dependencies", DWORD),
        ("ServiceStartName", DWORD),
        ("DisplayName", DWORD),
        )
PQUERY_SERVICE_CONFIG = POINTER(QUERY_SERVICE_CONFIG)

_QueryServiceConfig = fun_fact(
    _adv.QueryServiceConfigW, (
        BOOL,
        HANDLE,
        PQUERY_SERVICE_CONFIG,
        DWORD,
        PDWORD,
        )
    )

def QueryServiceConfig(svc):
    needed = DWORD()
    ok = _QueryServiceConfig(svc, None, 0, ref(needed))
    err = GetLastError()
    if ok:
        raise AssertionError("logic error in QueryServiceConfig")
    if err != ERROR_INSUFFICIENT_BUFFER:
        raise ctypes.WinError(err)
    buf = ctypes.create_string_buffer(needed.value)
    pqsc = ctypes.cast(buf, PQUERY_SERVICE_CONFIG)
    raise_on_zero(_QueryServiceConfig(svc, pqsc, needed.value, ref(needed)))
    return ns_from_struct(pqsc.contents)

################################################################################

class CREDENTIAL_ATTRIBUTE(ctypes.Structure):
    _fields_ = (
        ("Keyword", PWSTR),
        ("Flags", DWORD),
        ("ValueSize", DWORD),
        ("Value", PBYTE),
        )
PCREDENTIAL_ATTRIBUTE = POINTER(CREDENTIAL_ATTRIBUTE)

class CREDENTIAL(ctypes.Structure):
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
PCREDENTIAL = POINTER(CREDENTIAL)
PPCREDENTIAL = POINTER(PCREDENTIAL)
PPPCREDENTIAL = POINTER(PPCREDENTIAL)

_CredRead = fun_fact(
    _adv.CredReadW, (
        BOOL,
        PWSTR,
        DWORD,
        DWORD,
        PPCREDENTIAL
        )
    )
_CredEnumerate = fun_fact(
    _adv.CredEnumerateW, (
        BOOL,
        PWSTR,
        DWORD,
        PDWORD,
        PPPCREDENTIAL
        )
    )
_CredWrite = fun_fact(_adv.CredWriteW, (BOOL, PCREDENTIAL, DWORD))
_CredFree = fun_fact(_adv.CredFree, (None, PVOID))

################################################################################

def _ns_from_cred(cred):
    def a2ns(attr):
        return _namespace(
            Keyword=attr.Keyword,
            Flags=attr.Flags,
            Value=ctypes.string_at(attr.Value, attr.ValueSize),
            )
    attr = tuple(a2ns(cred.Attributes[n]) for n in range(cred.AttributeCount))
    blob = ctypes.string_at(cred.CredentialBlob, cred.CredentialBlobSize)
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
        raise_on_zero(_CredRead(TargetName, Type, Flags, ref(ptr)))
        return _ns_from_cred(ptr.contents)
    finally:
        _CredFree(ptr)

################################################################################

def CredEnumerate(Filter=None, Flags=0):
    pptr = PPCREDENTIAL()
    cnt = DWORD()
    try:
        raise_on_zero(_CredEnumerate(Filter, Flags, ref(cnt), ref(pptr)))
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
        cred.Attributes = ctypes.cast(attr, PCREDENTIAL_ATTRIBUTE)

    raise_on_zero(_CredWrite(ref(cred), Flags))

################################################################################

_CloseEventLog = fun_fact(_adv.CloseEventLog, (BOOL, HANDLE))

def CloseEventLog(hdl):
    raise_on_zero(_CloseEventLog(hdl))

################################################################################

class EHANDLE(ScdToBeClosed, HANDLE, close_func=CloseEventLog, invalid=0):
    pass

################################################################################

_OpenEventLog = fun_fact(
    _adv.OpenEventLogW, (HANDLE, PWSTR, PWSTR,)
    )

def OpenEventLog(source, server=None):
    hdl = EHANDLE(_OpenEventLog(server, source))
    hdl.raise_on_invalid()
    return hdl

################################################################################

class EVENTLOGRECORD(ctypes.Structure):
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

PEVENTLOGRECORD = POINTER(EVENTLOGRECORD)

################################################################################

def _evt_from_void_p(vpelr):
    # vpelr is PVOID for simpler address calculations
    strins = []
    elr = ctypes.cast(vpelr, PEVENTLOGRECORD).contents
    if elr.NumStrings:
        stroffs = elr.StringOffset
        for i in range(elr.NumStrings):
            nxt = ctypes.wstring_at(vpelr.value + stroffs)
            stroffs += (len(nxt) + 1) * ctypes.sizeof(WCHAR)
            strins.append(nxt)
    sid = ""
    if elr.UserSidLength:
        sid = ConvertSidToStringSid(
            ctypes.string_at(vpelr.value + elr.UserSidOffset)
            )
    data = ctypes.string_at(vpelr.value + elr.DataOffset, elr.DataLength)
    p_str = vpelr.value + ctypes.sizeof(EVENTLOGRECORD);
    src_name = ctypes.wstring_at(p_str)
    p_str += (len(src_name) + 1) * ctypes.sizeof(WCHAR)
    computer_name = ctypes.wstring_at(p_str)

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

_ReadEventLog = fun_fact(
    _adv.ReadEventLogW, (
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
        buf = ctypes.create_string_buffer(want.value)
        ok = _ReadEventLog(hdl, flags, offs, buf, want, ref(got), ref(want))
        got = got.value
        if not ok:
            err = GetLastError()
            if err == ERROR_HANDLE_EOF:
                got = 0
                break
            elif err == ERROR_INSUFFICIENT_BUFFER:
                continue
            else:
                raise ctypes.WinError(err)
        else:
            break

    res = []
    addr = ctypes.addressof(buf)
    while got > 0:
        elen, evt = _evt_from_void_p(PVOID(addr))
        res.append(evt)
        addr += elen
        got -= elen
    return res

################################################################################
