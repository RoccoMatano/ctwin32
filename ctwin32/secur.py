################################################################################
#
# Copyright 2021-2024 Rocco Matano
# SPDX-License-Identifier: MIT
#
################################################################################

from types import SimpleNamespace as _namespace
import ctypes
from . import (
    ERROR_INVALID_PARAMETER,
    fun_fact,
    ns_from_struct,
    ref,
    suppress_winerr,
    )
from .wtypes import (
    CHAR,
    FILETIME,
    HANDLE,
    INT,
    LARGE_INTEGER,
    LONG,
    LUID,
    NTSTATUS,
    PHANDLE,
    PLONG,
    PLUID,
    POINTER,
    PPLUID,
    PPVOID,
    PSTR,
    PVOID,
    PULONG,
    SIZE_T,
    ULONG,
    UNICODE_STRING,
    WORD,
    )
from .ntdll import raise_failed_status
from .kernel import (
    FileTimeToLocalFileTime,
    FileTimeToSystemTime,
    KHANDLE,
    get_ansi_encoding,
    get_local_tzinfo,
    )
from .advapi import (
    AllocateLocallyUniqueId,
    GetLengthSid,
    ConvertSidToStringSid,
    )

_sec = ctypes.WinDLL("secur32.dll", use_last_error=True)

################################################################################

class LSA_LAST_INTER_LOGON_INFO(ctypes.Structure):
    _fields_ = (
        ("LastSuccessfulLogon", LARGE_INTEGER),
        ("LastFailedLogon", LARGE_INTEGER),
        ("FailedAttemptCountSinceLastSuccessfulLogon", ULONG),
        )

class SECURITY_LOGON_SESSION_DATA(ctypes.Structure):
    _fields_ = (
        ("Size", ULONG),
        ("LogonId", LUID),
        ("UserName", UNICODE_STRING),
        ("LogonDomain", UNICODE_STRING),
        ("AuthenticationPackage", UNICODE_STRING),
        ("LogonType", ULONG),
        ("Session", ULONG),
        ("Sid", PVOID),
        ("LogonTime", LARGE_INTEGER),
        ("LogonServer", UNICODE_STRING),
        ("DnsDomainName", UNICODE_STRING),
        ("Upn", UNICODE_STRING),
        ("UserFlags", ULONG),
        ("LastLogonInfo", LSA_LAST_INTER_LOGON_INFO),
        ("LogonScript", UNICODE_STRING),
        ("ProfilePath", UNICODE_STRING),
        ("HomeDirectory", UNICODE_STRING),
        ("HomeDirectoryDrive", UNICODE_STRING),
        ("LogoffTime", LARGE_INTEGER),
        ("KickOffTime", LARGE_INTEGER),
        ("PasswordLastSet", LARGE_INTEGER),
        ("PasswordCanChange", LARGE_INTEGER),
        ("PasswordMustChange", LARGE_INTEGER),
        )
PSECURITY_LOGON_SESSION_DATA = POINTER(SECURITY_LOGON_SESSION_DATA)
PPSECURITY_LOGON_SESSION_DATA = POINTER(PSECURITY_LOGON_SESSION_DATA)

################################################################################

_LsaFreeReturnBuffer = fun_fact(
    _sec.LsaFreeReturnBuffer, (NTSTATUS, PVOID)
    )

def LsaFreeReturnBuffer(ptr):
    raise_failed_status(_LsaFreeReturnBuffer(ptr))

################################################################################

_LsaGetLogonSessionData = fun_fact(
    _sec.LsaGetLogonSessionData,
    (NTSTATUS, PLUID, PPSECURITY_LOGON_SESSION_DATA)
    )

def LsaGetLogonSessionData(luid):
    ltz = get_local_tzinfo()
    ptr = PSECURITY_LOGON_SESSION_DATA()
    raise_failed_status(_LsaGetLogonSessionData(ref(luid), ref(ptr)))
    try:
        lsd = ptr.contents
        lli = lsd.LastLogonInfo

        def la2dt(la):
            st = FileTimeToSystemTime(FILETIME(0))
            with suppress_winerr(ERROR_INVALID_PARAMETER):
                #convert utc to local time
                st = FileTimeToSystemTime(FileTimeToLocalFileTime(FILETIME(la)))
            return st.to_datetime(tzinfo=ltz)

        return _namespace(
            LogonId=int(lsd.LogonId),
            UserName=str(lsd.UserName),
            LogonDomain=str(lsd.LogonDomain),
            AuthenticationPackage=str(lsd.AuthenticationPackage),
            LogonType=lsd.LogonType,
            Session=lsd.Session,
            Sid=ConvertSidToStringSid(
                ctypes.string_at(lsd.Sid, GetLengthSid(lsd.Sid))
                ) if lsd.Sid else None,
            LogonTime=la2dt(lsd.LogonTime),
            LogonServer=str(lsd.LogonServer),
            DnsDomainName=str(lsd.DnsDomainName),
            Upn=str(lsd.Upn),
            UserFlags=lsd.UserFlags,
            LastLogonInfo=_namespace(
                LastSuccessfulLogon=la2dt(lli.LastSuccessfulLogon),
                LastFailedLogon=la2dt(lli.LastFailedLogon),
                FailedAttemptCountSinceLastSuccessfulLogon=(
                    lli.FailedAttemptCountSinceLastSuccessfulLogon
                    )
                ),
            LogonScript=str(lsd.LogonScript),
            ProfilePath=str(lsd.ProfilePath),
            HomeDirectory=str(lsd.HomeDirectory),
            HomeDirectoryDrive=str(lsd.HomeDirectoryDrive),
            LogoffTime=la2dt(lsd.LogoffTime),
            KickOffTime=la2dt(lsd.KickOffTime),
            PasswordLastSet=la2dt(lsd.PasswordLastSet),
            PasswordCanChange=la2dt(lsd.PasswordCanChange),
            PasswordMustChange=la2dt(lsd.PasswordMustChange)
            )
    finally:
        LsaFreeReturnBuffer(ptr)

################################################################################

_LsaEnumerateLogonSessions = fun_fact(
    _sec.LsaEnumerateLogonSessions, (NTSTATUS, PULONG, PPLUID)
    )

def LsaEnumerateLogonSessions():
    count = ULONG()
    pluid = PLUID()
    raise_failed_status(_LsaEnumerateLogonSessions(ref(count), ref(pluid)))
    try:
        return [
            LsaGetLogonSessionData(pluid[idx])
            for idx in reversed(range(count.value))
            ]
    finally:
        LsaFreeReturnBuffer(pluid)

################################################################################

_LsaDeregisterLogonProcess = fun_fact(
    _sec.LsaDeregisterLogonProcess, (NTSTATUS, HANDLE)
    )

def LsaDeregisterLogonProcess(hdl):
    raise_failed_status(_LsaDeregisterLogonProcess(hdl))

################################################################################

_LsaConnectUntrusted = fun_fact(_sec.LsaConnectUntrusted, (NTSTATUS, PHANDLE))

def LsaConnectUntrusted():
    hdl = HANDLE()
    raise_failed_status(_LsaConnectUntrusted(ref(hdl)))
    return hdl

################################################################################

class LSA_STRING(ctypes.Structure):
    _fields_ = (
        ("Length", WORD),
        ("MaximumLength", WORD),
        ("Buffer", PSTR),
        )

    def __str__(self):
        return ctypes.string_at(
            self.Buffer,
            self.Length
            ).decode(get_ansi_encoding())

PLSA_STRING = POINTER(LSA_STRING)

def LsaStrFromStr(init):
    if isinstance(init, str):
        init = init.encode(get_ansi_encoding())

    class SELF_CONTAINED_LSAS(ctypes.Structure):
        _fields_ = (
            ("ls", LSA_STRING),
            ("buf", CHAR * (1 + len(init))),
            )

        def __init__(self, init):
            li = len(init)
            baddr = ctypes.addressof(self) + __class__.buf.offset
            super().__init__((li, 1 + li, baddr), init)

        @property
        def ptr(self):
            return PLSA_STRING(self.ls)

    return SELF_CONTAINED_LSAS(init)

################################################################################

_LsaLookupAuthenticationPackage = fun_fact(
    _sec.LsaLookupAuthenticationPackage, (NTSTATUS, HANDLE, PLSA_STRING, PULONG)
    )

def LsaLookupAuthenticationPackage(hlsa, name):
    name = LsaStrFromStr(name.encode(get_ansi_encoding()))
    auth_pkg = ULONG()
    raise_failed_status(
        _LsaLookupAuthenticationPackage(
            hlsa,
            name.ptr,
            ref(auth_pkg)
            )
        )
    return auth_pkg.value

################################################################################

TOKEN_SOURCE_LENGTH = 8

class TOKEN_SOURCE(ctypes.Structure):
    _fields_ = (
        ("SourceName", CHAR * TOKEN_SOURCE_LENGTH),
        ("SourceIdentifier", LUID),
        )

PTOKEN_SOURCE = POINTER(TOKEN_SOURCE)

################################################################################

class QUOTA_LIMITS(ctypes.Structure):
    _fields_ = (
        ("PagedPoolLimit", SIZE_T),
        ("NonPagedPoolLimit", SIZE_T),
        ("MinimumWorkingSetSize", SIZE_T),
        ("MaximumWorkingSetSize", SIZE_T),
        ("PagefileLimit", SIZE_T),
        ("TimeLimit", LARGE_INTEGER),
        )

PQUOTA_LIMITS = POINTER(QUOTA_LIMITS)

################################################################################

_LsaLogonUser = fun_fact(
    _sec.LsaLogonUser, (
        NTSTATUS,
        HANDLE,
        PLSA_STRING,
        INT,
        ULONG,
        PVOID,
        ULONG,
        PVOID,
        PTOKEN_SOURCE,
        PPVOID,
        PULONG,
        PLUID,
        PHANDLE,
        PQUOTA_LIMITS,
        PLONG
        )
    )

def LsaLogonUser(
        lsa_hdl,
        origin_name,
        logon_type,
        auth_pkg,
        auth_info,
        local_groups=None,
        src_name=None,
        ):

    origin_name = LsaStrFromStr(origin_name)
    pgroups = None
    if local_groups is not None:
        pgroups = ref(local_groups)
    if src_name is None:
        src_name = "ctwin32"
    token_src = TOKEN_SOURCE(
        src_name.encode(get_ansi_encoding()),
        LUID(AllocateLocallyUniqueId())
        )

    profile = PVOID()
    plen = ULONG()
    lid = LUID()
    tok = KHANDLE()
    qlim = QUOTA_LIMITS()
    subs = LONG(0)

    status = _LsaLogonUser(
        lsa_hdl,
        origin_name.ptr,
        logon_type,
        auth_pkg,
        ref(auth_info),
        ctypes.sizeof(auth_info),
        pgroups,
        ref(token_src),
        ref(profile),
        ref(plen),
        ref(lid),
        ref(tok),
        ref(qlim),
        ref(subs)
        )
    if status < 0:
        raise_failed_status(subs if subs.value < 0 else status)

    try:
        sundries = _namespace(
            ProfileBuffer=ctypes.string_at(profile.value, plen.value),
            LogonId=int(lid),
            Quotas=ns_from_struct(qlim)
            )
        return tok, sundries
    finally:
        LsaFreeReturnBuffer(profile)

################################################################################
