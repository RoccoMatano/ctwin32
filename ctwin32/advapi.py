################################################################################
#
# Copyright 2021-2024 Rocco Matano
# SPDX-License-Identifier: MIT
#
################################################################################

from types import SimpleNamespace as _namespace
from datetime import datetime as _dt
from datetime import UTC as _UTC
import ctypes

from .wtypes import (
    byte_buffer,
    string_buffer,
    ArgcArgvFromArgs,
    BOOL,
    BYTE,
    DWORD,
    ENDIANNESS,
    FILETIME,
    HANDLE,
    INT,
    LARGE_INTEGER,
    LONG,
    LUID,
    PBOOL,
    PBYTE,
    PDWORD,
    PFILETIME,
    PHANDLE,
    PLUID,
    POINTER,
    PPWSTR,
    PPVOID,
    PVOID,
    PWSTR,
    ScdToBeClosed,
    WCHAR_SIZE,
    WinError,
    WORD,
    )
from . import (
    cmdline_from_args,
    CRED_TYPE_GENERIC,
    DACL_SECURITY_INFORMATION,
    ERROR_HANDLE_EOF,
    ERROR_INSUFFICIENT_BUFFER,
    ERROR_MORE_DATA,
    ERROR_NOT_ALL_ASSIGNED,
    ERROR_NO_MORE_ITEMS,
    EVENTLOG_BACKWARDS_READ,
    EVENTLOG_SEQUENTIAL_READ,
    fun_fact,
    GROUP_SECURITY_INFORMATION,
    KEY_ALL_ACCESS,
    KEY_READ,
    KEY_WOW64_64KEY,
    ns_from_struct,
    MAXIMUM_ALLOWED,
    OWNER_SECURITY_INFORMATION,
    raise_if,
    raise_on_err,
    raise_on_zero,
    ref,
    REG_DWORD,
    REG_EXPAND_SZ,
    REG_MULTI_SZ,
    REG_QWORD,
    REG_SZ,
    SACL_SECURITY_INFORMATION,
    SC_ENUM_PROCESS_INFO,
    SC_STATUS_PROCESS_INFO,
    SE_PRIVILEGE_ENABLED,
    suppress_winerr,
    TokenElevationType,
    TokenElevationTypeFull,
    TokenUser,
    TokenGroups,
    WinBuiltinAdministratorsSid,
    WinLocalSystemSid,
    )
from .kernel import (
    LocalFree,
    GetCurrentProcess,
    GetLastError,
    get_local_tzinfo,
    KHANDLE,
    PSECURITY_ATTRIBUTES,
    PSTARTUPINFO,
    PPROCESS_INFORMATION,
    PROCESS_INFORMATION,
    STARTUPINFO,
    )

_adv = ctypes.WinDLL("advapi32.dll", use_last_error=True)

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

# linters won't recognize 'globals().update()' -> noqa
HKCR = HKEY_CLASSES_ROOT    # noqa: F821
HKCU = HKEY_CURRENT_USER    # noqa: F821
HKLM = HKEY_LOCAL_MACHINE   # noqa: F821

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
    elif reg_type in (REG_DWORD, REG_QWORD):
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
            access,
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
    name = string_buffer(_MAX_KEY_LEN)
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
    with suppress_winerr(ERROR_NO_MORE_ITEMS):
        while True:
            sub_key_name = RegEnumKeyEx(key, index)
            index += 1
            yield sub_key_name

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
    name = string_buffer(nlen.value)
    value = byte_buffer(vlen.value)
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
            value = byte_buffer(vlen.value)
        else:
            raise WinError(err)

    return (name.value, *registry_to_py(typ.value, value.raw[:vlen.value]))

################################################################################

def reg_enum_values(key):
    index = 0
    with suppress_winerr(ERROR_NO_MORE_ITEMS):
        while True:
            tpl = RegEnumValue(key, index)
            index += 1
            yield tpl

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
    value = byte_buffer(vlen.value)
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
            value = byte_buffer(vlen.value)
        else:
            raise WinError(err)

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
    dta = byte_buffer(data)
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
    dta = byte_buffer(data)
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
    value = string_buffer(string, len(string))
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

_RegFlushKey = fun_fact(_adv.RegFlushKey, (LONG, HKEY))

def RegFlushKey(key):
    raise_on_err(_RegFlushKey(key))

################################################################################

_RegLoadAppKey = fun_fact(
    _adv.RegLoadAppKeyW,
    (LONG, PWSTR, PHKEY, DWORD, DWORD, DWORD)
    )

REG_PROCESS_APPKEY = 1

def RegLoadAppKey(hive_name, acc=KEY_ALL_ACCESS, opt=REG_PROCESS_APPKEY):
    key = HKEY()
    raise_on_err(_RegLoadAppKey(hive_name, ref(key), acc, opt, 0))
    key.raise_on_invalid()
    return key

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
    bin_sid = byte_buffer(sid)
    str_sid = PWSTR()
    try:
        raise_on_zero(_ConvertSidToStringSid(ref(bin_sid), ref(str_sid)))
        return ctypes.wstring_at(str_sid)
    finally:
        LocalFree(str_sid)

################################################################################

_CreateWellKnownSid = fun_fact(
    _adv.CreateWellKnownSid, (BOOL, INT, PVOID, PVOID, PDWORD)
    )

def CreateWellKnownSid(sid_type, domain=None):
    if domain is not None:
       domain = byte_buffer(domain)
    size = DWORD(0)
    _CreateWellKnownSid(sid_type, domain, None, ref(size))
    wks = byte_buffer(size.value)
    raise_on_zero(_CreateWellKnownSid(sid_type, domain, wks, ref(size)))
    return wks.raw[:size.value]

################################################################################

_IsWellKnownSid = fun_fact(
    _adv.IsWellKnownSid, (BOOL, PVOID, INT)
    )

def IsWellKnownSid(sid, sid_type):
    bin_sid = byte_buffer(sid)
    return _IsWellKnownSid(ref(bin_sid), sid_type) != 0

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
    sid = byte_buffer(sid_to_check)
    raise_on_zero(_CheckTokenMembership(token_handle, ref(sid), ref(res)))
    return res.value != 0

################################################################################

def running_as_admin():
    return CheckTokenMembership(
        None,
        CreateWellKnownSid(WinBuiltinAdministratorsSid)
        )

################################################################################

_OpenProcessToken = fun_fact(
    _adv.OpenProcessToken, (BOOL, HANDLE, DWORD, PHANDLE)
    )

def OpenProcessToken(proc_handle, desired_acc):
    token = KHANDLE()
    raise_on_zero(_OpenProcessToken(proc_handle, desired_acc, ref(token)))
    return token

################################################################################

_OpenThreadToken = fun_fact(
    _adv.OpenThreadToken, (BOOL, HANDLE, DWORD, BOOL, PHANDLE)
    )

def OpenThreadToken(proc_handle, desired_acc, as_self):
    token = KHANDLE()
    raise_on_zero(
        _OpenThreadToken(proc_handle, desired_acc, as_self, ref(token))
        )
    return token

################################################################################

def GetCurrentProcessToken():
    return HANDLE(-4)

def GetCurrentThreadToken():
    return HANDLE(-5)

def GetCurrentThreadEffectiveToken():
    return HANDLE(-6)

################################################################################

_DuplicateTokenEx = fun_fact(
    _adv.DuplicateTokenEx,
    (BOOL, HANDLE, DWORD, PSECURITY_ATTRIBUTES, INT, INT, PHANDLE)
    )

def DuplicateTokenEx(tok, acc, sattr, imp, typ):
    dup = KHANDLE()
    raise_on_zero(_DuplicateTokenEx(tok, acc, ref(sattr), imp, typ, ref(dup)))
    return dup

################################################################################

_AllocateLocallyUniqueId = fun_fact(
    _adv.AllocateLocallyUniqueId, (BOOL, PLUID)
    )

def AllocateLocallyUniqueId():
    luid = LUID()
    raise_on_zero(_AllocateLocallyUniqueId(ref(luid)))
    return int(luid)

################################################################################

class SID_AND_ATTRIBUTES(ctypes.Structure):
    _fields_ = (
        ("Sid", PVOID),
        ("Attributes", DWORD),
        )

class TOKEN_STATISTICS(ctypes.Structure):
    _fields_ = (
        ("TokenId", LUID),
        ("AuthenticationId", LUID),
        ("ExpirationTime", LARGE_INTEGER),
        ("TokenType", INT),
        ("ImpersonationLevel", INT),
        ("DynamicCharged", DWORD),
        ("DynamicAvailable", DWORD),
        ("GroupCount", DWORD),
        ("PrivilegeCount", DWORD),
        ("ModifiedId", LUID),
        )

################################################################################

_GetTokenInformation = fun_fact(
    _adv.GetTokenInformation, (BOOL, HANDLE, INT, PVOID, DWORD, PDWORD)
    )

def GetTokenInformation(hdl, cls):
    rlen = DWORD(256)
    while True:
        size = rlen.value
        buf = byte_buffer(size)
        if _GetTokenInformation(hdl, cls, buf, size, ref(rlen)):
            return buf.raw[:rlen.value]
        elif (err := GetLastError()) != ERROR_INSUFFICIENT_BUFFER:
            raise WinError(err)

################################################################################

_SetTokenInformation = fun_fact(
    _adv.SetTokenInformation, (BOOL, HANDLE, INT, PVOID, DWORD)
    )

def SetTokenInformation(hdl, cls, info):
    raise_on_zero(
        _SetTokenInformation(hdl, cls, ref(info), ctypes.sizeof(info))
        )

################################################################################

def _xform_saa(saa):
    return (ctypes.string_at(saa.Sid, GetLengthSid(saa.Sid)), saa.Attributes)

def get_token_user(hdl):
    saa = SID_AND_ATTRIBUTES.from_buffer_copy(
        GetTokenInformation(hdl, TokenUser)
        )
    return _xform_saa(saa)

################################################################################

def get_token_groups(hdl):
    buf = GetTokenInformation(hdl, TokenGroups)
    num_groups = DWORD.from_buffer_copy(buf).value
    class TOKEN_GROUPS(ctypes.Structure):
        _fields_ = (
            ("GroupCount", DWORD),
            ("Groups", SID_AND_ATTRIBUTES * num_groups),
            )
    tgroups = TOKEN_GROUPS.from_buffer_copy(buf)
    return (_xform_saa(saa) for saa in tgroups.Groups)

################################################################################

def make_token_groups(sids_and_attrs):
    num_groups = len(sids_and_attrs)
    class TOKEN_GROUPS(ctypes.Structure):
        _fields_ = (
            ("GroupCount", DWORD),
            ("Groups", SID_AND_ATTRIBUTES * num_groups),
            ("sid_bufs", ctypes.py_object),
            )
    tgroups = TOKEN_GROUPS(num_groups, sid_bufs=[None] * num_groups)
    for i, (s, a) in enumerate(sids_and_attrs):
        tgroups.sid_bufs[i] = byte_buffer(s)
        tgroups.Groups[i].Sid = ctypes.addressof(tgroups.sid_bufs[i])
        tgroups.Groups[i].Attributes = a
    return tgroups

################################################################################

def running_as_system(consider_impersonation=False):
    token = (
        GetCurrentThreadEffectiveToken() if consider_impersonation
        else GetCurrentProcessToken()
        )
    sid, _ = get_token_user(token)
    return IsWellKnownSid(sid, WinLocalSystemSid)

################################################################################

def get_token_elevation_type(hdl):
    return int.from_bytes(
        GetTokenInformation(hdl, TokenElevationType),
        "little"
        )

################################################################################

def is_elevated_via_uac():
    ele_type = get_token_elevation_type(GetCurrentProcessToken())
    return ele_type == TokenElevationTypeFull

################################################################################

_CreateProcessAsUser = fun_fact(
    _adv.CreateProcessAsUserW, (
        BOOL,
        HANDLE,
        PWSTR,
        PWSTR,
        PSECURITY_ATTRIBUTES,
        PSECURITY_ATTRIBUTES,
        BOOL,
        DWORD,
        PVOID,
        PWSTR,
        PSTARTUPINFO,
        PPROCESS_INFORMATION,
        )
    )

def CreateProcessAsUser(
        token,
        app_name,
        cmd_line,
        proc_attr,
        thread_attr,
        inherit,
        cflags,
        env,
        curdir,
        startup_info
        ):
    proc_info = PROCESS_INFORMATION()
    raise_on_zero(
        _CreateProcessAsUser(
            token,
            app_name,
            cmd_line,
            ref(proc_attr) if proc_attr is not None else None,
            ref(thread_attr) if thread_attr is not None else None,
            inherit,
            cflags,
            env,
            curdir,
            ref(startup_info),
            ref(proc_info)
            )
        )
    return proc_info

################################################################################

def create_process_as_user(
        token,
        arglist,
        cflags=0,
        startup_info=None,
        inherit=False,
        env=None,
        curdir=None,
        proc_attr=None,
        thread_attr=None,
        ):
    if startup_info is None:
        startup_info = STARTUPINFO()
    return CreateProcessAsUser(
        token,
        None,
        cmdline_from_args(arglist),
        proc_attr,
        thread_attr,
        inherit,
        cflags,
        env,
        curdir,
        startup_info
        )

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

    raise_on_zero(
        _AdjustTokenPrivileges(
            token,
            disable_all,
            ref(privs),
            0,
            None,
            None
            )
        )
    if (err := GetLastError()) == ERROR_NOT_ALL_ASSIGNED:
        raise WinError(err)

################################################################################

def enable_token_privileges(token, privileges):
    laa = [
        LUID_AND_ATTRIBUTES(LUID(p), SE_PRIVILEGE_ENABLED) for p in privileges
    ]
    AdjustTokenPrivileges(token, laa)

################################################################################

def enable_privileges(privileges):
    with OpenProcessToken(GetCurrentProcess(), MAXIMUM_ALLOWED) as tok:
        enable_token_privileges(tok, privileges)

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
        raise WinError(err)

    name = string_buffer(name_size.value)
    domain = string_buffer(domain_size.value)
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

_SetThreadToken = fun_fact(_adv.SetThreadToken, (BOOL, PHANDLE, HANDLE))

def SetThreadToken(tok, thrd=None):
    pht = None if thrd is None else ref(thrd)
    raise_on_zero(_SetThreadToken(pht, tok))

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
    return ctypes.string_at(psid, GetLengthSid(psid)), bool(defaulted)

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

class SC_HANDLE(
        ScdToBeClosed,
        HANDLE,
        close_func=CloseServiceHandle,
        invalid=0
        ):
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
        load_order_group=None,
        dependencies=None,
        service_start_name=None,
        password=None
        ):
    if dependencies is not None:
        dependencies = string_buffer("\x00".join(dependencies))
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
            dependencies,
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
        PVOID
        )
    )

def StartService(handle, arglist):
    aa = ArgcArgvFromArgs(arglist)
    raise_on_zero(_StartService(handle, aa.argc, aa.argv))

################################################################################

class SERVICE_STATUS(ctypes.Structure):
    _fields_ = (
        ("dwServiceType", DWORD),
        ("dwCurrentState", DWORD),
        ("dwControlsAccepted", DWORD),
        ("dwWin32ExitCode", DWORD),
        ("dwServiceSpecificExitCode", DWORD),
        ("dwCheckPoint", DWORD),
        ("dwWaitHint", DWORD),
        )
PSERVICE_STATUS = POINTER(SERVICE_STATUS)

_ControlService = fun_fact(
    _adv.ControlService, (
        BOOL,
        HANDLE,
        DWORD,
        PSERVICE_STATUS
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
        ("dwServiceType", DWORD),
        ("dwCurrentState", DWORD),
        ("dwControlsAccepted", DWORD),
        ("dwWin32ExitCode", DWORD),
        ("dwServiceSpecificExitCode", DWORD),
        ("dwCheckPoint", DWORD),
        ("dwWaitHint", DWORD),
        ("dwProcessId", DWORD),
        ("dwServiceFlags", DWORD),
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
        ("lpServiceName", PWSTR),
        ("lpDisplayName", PWSTR),
        ("ServiceStatusProcess", SERVICE_STATUS_PROCESS),
        )

_EnumServicesStatusEx = fun_fact(
    _adv.EnumServicesStatusExW, (
        BOOL,
        HANDLE,
        INT,
        DWORD,
        DWORD,
        PVOID,
        DWORD,
        PDWORD,
        PDWORD,
        PDWORD,
        PWSTR
        )
    )

def EnumServicesStatusEx(scm, stype, sstate, group_name=None):
    stat_size = ctypes.sizeof(ENUM_SERVICE_STATUS_PROCESS)
    buf = byte_buffer(16 * 1024)
    needed = DWORD()
    num_ret = DWORD()
    resume = DWORD()
    result = []
    success = False

    while not success:
        success = _EnumServicesStatusEx(
            scm,
            SC_ENUM_PROCESS_INFO,
            stype,
            sstate,
            buf,
            ctypes.sizeof(buf),
            ref(needed),
            ref(num_ret),
            ref(resume),
            group_name
            )
        raise_if(not success and GetLastError() != ERROR_MORE_DATA)

        for offs in range(0, num_ret.value * stat_size, stat_size):
            status = ENUM_SERVICE_STATUS_PROCESS.from_buffer(buf, offs)
            result.append(ns_from_struct(status))

        if success:
            break
        buf = byte_buffer(needed.value)

    return result

################################################################################

class QUERY_SERVICE_CONFIG(ctypes.Structure):
    _fields_ = (
        ("dwServiceType", DWORD),
        ("dwStartType", DWORD),
        ("dwErrorControl", DWORD),
        ("lpBinaryPathName", PWSTR),
        ("lpLoadOrderGroup", PWSTR),
        ("dwTagId", DWORD),
        ("lpDependencies", PWSTR),
        ("lpServiceStartName", PWSTR),
        ("lpDisplayName", PWSTR),
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
        raise WinError(err)
    buf = byte_buffer(needed.value)
    pqsc = ctypes.cast(buf, PQUERY_SERVICE_CONFIG)
    raise_on_zero(_QueryServiceConfig(svc, pqsc, needed.value, ref(needed)))
    return ns_from_struct(pqsc.contents)

################################################################################

SERVICE_MAIN_FUNCTION = ctypes.WINFUNCTYPE(None, DWORD, PPWSTR)

class SERVICE_TABLE_ENTRY(ctypes.Structure):
    _fields_ = (
        ("lpServiceName", PWSTR),
        ("lpServiceProc", SERVICE_MAIN_FUNCTION),
        )
PSERVICE_TABLE_ENTRY = POINTER(SERVICE_TABLE_ENTRY)

_StartServiceCtrlDispatcher = fun_fact(
    _adv.StartServiceCtrlDispatcherW, (BOOL, PSERVICE_TABLE_ENTRY)
    )

def StartServiceCtrlDispatcher(table):
    raise_on_zero(_StartServiceCtrlDispatcher(ref(table[0])))

################################################################################

HANDLER_FUNCTION = ctypes.WINFUNCTYPE(None, DWORD)

_RegisterServiceCtrlHandler = fun_fact(
    _adv.RegisterServiceCtrlHandlerW, (HANDLE, PWSTR, HANDLER_FUNCTION)
    )

def RegisterServiceCtrlHandler(name, handler):
    res = _RegisterServiceCtrlHandler(name, handler)
    raise_on_zero(res)
    return res

################################################################################

_SetServiceStatus = fun_fact(
    _adv.SetServiceStatus, (BOOL, HANDLE, PSERVICE_STATUS)
    )

def SetServiceStatus(hdl, status):
    raise_on_zero(_SetServiceStatus(hdl, ref(status)))

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

def CredRead(target_name, typ=CRED_TYPE_GENERIC, flags=0):
    ptr = PCREDENTIAL()
    try:
        raise_on_zero(_CredRead(target_name, typ, flags, ref(ptr)))
        return _ns_from_cred(ptr.contents)
    finally:
        _CredFree(ptr)

################################################################################

def CredEnumerate(filter=None, flags=0):
    pptr = PPCREDENTIAL()
    cnt = DWORD()
    try:
        raise_on_zero(_CredEnumerate(filter, flags, ref(cnt), ref(pptr)))
        return tuple(_ns_from_cred(pptr[n].contents) for n in range(cnt.value))
    finally:
        _CredFree(pptr)

################################################################################

def CredWrite(credential, flags=0):

    # ============================== std fields ================================

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
        if (val := getattr(credential, f, None)) is not None:
            setattr(cred, f, val)

    # ================================= blob ===================================

    if (val := getattr(credential, "CredentialBlob", None)) is not None:
        cred.CredentialBlobSize = len(val)
        cred.CredentialBlob = (BYTE * len(val))(*tuple(map(int, val)))

    # ============================== attributes ================================

    if ns_attr := getattr(credential, "Attributes", None):
        attr = (CREDENTIAL_ATTRIBUTE * len(ns_attr))()
        for i, a in enumerate(ns_attr):
            for f in ("Keyword", "Flags"):
                if (val := getattr(a, f, None)) is not None:
                    setattr(attr[i], f, val)
            if val := getattr(a, "Value", None):
                attr[i].ValueSize = len(val)
                attr[i].Value = (BYTE * len(val))(*tuple(map(int, val)))
        cred.AttributeCount = len(ns_attr)
        cred.Attributes = ctypes.cast(attr, PCREDENTIAL_ATTRIBUTE)

    raise_on_zero(_CredWrite(ref(cred), flags))

################################################################################

_CloseEventLog = fun_fact(_adv.CloseEventLog, (BOOL, HANDLE))

def CloseEventLog(hdl):
    raise_on_zero(_CloseEventLog(hdl))

################################################################################

class EHANDLE(ScdToBeClosed, HANDLE, close_func=CloseEventLog, invalid=0):
    pass

################################################################################

_OpenEventLog = fun_fact(
    _adv.OpenEventLogW, (HANDLE, PWSTR, PWSTR)
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

def _evt_from_buf(buf, offs):
    addr = ctypes.addressof(buf) + offs
    elr = EVENTLOGRECORD.from_buffer(buf, offs)

    str_ins = []
    if elr.NumStrings:
        stroffs = elr.StringOffset
        for _ in range(elr.NumStrings):
            nxt = ctypes.wstring_at(addr + stroffs)
            stroffs += (len(nxt) + 1) * WCHAR_SIZE
            str_ins.append(nxt)
    sid = ""
    if elr.UserSidLength:
        sid = ConvertSidToStringSid(
            ctypes.string_at(addr + elr.UserSidOffset, elr.UserSidLength)
            )
    data = ctypes.string_at(addr + elr.DataOffset, elr.DataLength)
    p_str = addr + ctypes.sizeof(EVENTLOGRECORD)
    src_name = ctypes.wstring_at(p_str)
    p_str += (len(src_name) + 1) * WCHAR_SIZE
    computer_name = ctypes.wstring_at(p_str)
    ltz = get_local_tzinfo()
    tgen = _dt.fromtimestamp(elr.TimeGenerated, tz=_UTC).astimezone(ltz)
    twri = _dt.fromtimestamp(elr.TimeWritten, tz=_UTC).astimezone(ltz)

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
        StringInserts=str_ins,
        TimeGenerated=tgen,
        TimeWritten=twri,
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
        buf = byte_buffer(want.value)
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
                raise WinError(err)
        else:
            break

    res = []
    offs = 0
    while offs < got:
        elen, evt = _evt_from_buf(buf, offs)
        res.append(evt)
        offs += elen
    return res

################################################################################

def enum_event_log(name, flags=None, server=None):
    with OpenEventLog(name, server) as log:
        while some_events := ReadEventLog(log, flags):
            yield from some_events

################################################################################

_EncryptFile = fun_fact(_adv.EncryptFileW, (BOOL, PWSTR))

def EncryptFile(file_or_dir_name):
    raise_on_zero(_EncryptFile(file_or_dir_name))

################################################################################

_DecryptFile = fun_fact(_adv.DecryptFileW, (BOOL, PWSTR, DWORD))

def DecryptFile(file_or_dir_name):
    raise_on_zero(_DecryptFile(file_or_dir_name, 0))

################################################################################
