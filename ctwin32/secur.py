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
from .wtypes import *
from . import ref, fun_fact
from .ntdll import raise_failed_status
from .kernel import FileTimeToLocalFileTime, FileTimeToSystemTime
from .advapi import GetLengthSid, ConvertSidToStringSid

_sec = ctypes.WinDLL("secur32.dll")

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
    _sec.LsaGetLogonSessionData, (NTSTATUS, PLUID, PPSECURITY_LOGON_SESSION_DATA)
    )

def LsaGetLogonSessionData(luid):
    ptr = PSECURITY_LOGON_SESSION_DATA()
    raise_failed_status(_LsaGetLogonSessionData(ref(luid), ref(ptr)))
    try:
        lsd = ptr.contents
        lli = lsd.LastLogonInfo
        def us2s(us):
            return ctypes.wstring_at(
                us.Buffer,
                us.Length // ctypes.sizeof(WCHAR)
                )
        def la2dt(la):
            st = FileTimeToSystemTime(FILETIME(la))
            if st.Year > 9999:
                # datetime cannot handle years > 9999
                st = SYSTEMTIME(9999, 12, 0, 31)
            else:
                st = FileTimeToSystemTime(FileTimeToLocalFileTime(FILETIME(la)))
            return st.to_datetime()
        return _namespace(
            LogonId=int(lsd.LogonId),
            UserName=us2s(lsd.UserName),
            LogonDomain=us2s(lsd.LogonDomain),
            AuthenticationPackage=us2s(lsd.AuthenticationPackage),
            LogonType=lsd.LogonType,
            Session=lsd.Session,
            Sid=ConvertSidToStringSid(
                ctypes.string_at(lsd.Sid, GetLengthSid(lsd.Sid))
                ) if lsd.Sid else None,
            LogonTime=la2dt(lsd.LogonTime),
            LogonServer=us2s(lsd.LogonServer),
            DnsDomainName=us2s(lsd.DnsDomainName),
            Upn=us2s(lsd.Upn),
            UserFlags=lsd.UserFlags,
            LastLogonInfo=_namespace(
                LastSuccessfulLogon=la2dt(lli.LastSuccessfulLogon),
                LastFailedLogon=la2dt(lli.LastFailedLogon),
                FailedAttemptCountSinceLastSuccessfulLogon=(
                    lli.FailedAttemptCountSinceLastSuccessfulLogon
                    )
                ),
            LogonScript=us2s(lsd.LogonScript),
            ProfilePath=us2s(lsd.ProfilePath),
            HomeDirectory=us2s(lsd.HomeDirectory),
            HomeDirectoryDrive=us2s(lsd.HomeDirectoryDrive),
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
        result = []
        for idx in reversed(range(count.value)):
            result.append(LsaGetLogonSessionData(pluid[idx]))
        return result
    finally:
        LsaFreeReturnBuffer(pluid)

################################################################################