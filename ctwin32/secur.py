################################################################################
#
# Copyright 2021-2024 Rocco Matano
# SPDX-License-Identifier: MIT
#
################################################################################

from types import SimpleNamespace as _namespace
import ctypes
from .wtypes import (
    FILETIME,
    LARGE_INTEGER,
    LUID,
    NTSTATUS,
    PLUID,
    POINTER,
    PPLUID,
    PVOID,
    PULONG,
    UNICODE_STRING,
    ULONG,
    )
from .kernel import (
    FileTimeToLocalFileTime,
    FileTimeToSystemTime,
    get_local_tzinfo,
    )
from . import ref, fun_fact, suppress_winerr, ERROR_INVALID_PARAMETER
from .ntdll import raise_failed_status
from .advapi import GetLengthSid, ConvertSidToStringSid

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
