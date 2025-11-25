################################################################################
#
# Copyright 2021-2025 Rocco Matano
# SPDX-License-Identifier: MIT
#
################################################################################

from .wtypes import (
    BOOL,
    Struct,
    DWORD,
    HANDLE,
    LONG,
    PDWORD,
    POINTER,
    PVOID,
    PWSTR,
    )
from . import (
    ApiDll,
    ref,
    raise_on_zero,
    ns_from_struct,
    )

################################################################################

_wts = ApiDll("wtsapi32.dll")

class WTS_SESSION_INFO(Struct):
    _fields_ = (
        ("SessionId", DWORD),
        ("pWinStationName", PWSTR),
        ("State", LONG),
        )
P_SESSION_INFO = POINTER(WTS_SESSION_INFO)
PP_SESSION_INFO = POINTER(P_SESSION_INFO)

################################################################################

_WTSFreeMemory = _wts.fun_fact("WTSFreeMemory", (None, PVOID))

################################################################################

_WTSEnumerateSessions = _wts.fun_fact(
    "WTSEnumerateSessionsW",
    (BOOL, HANDLE, DWORD, DWORD, PP_SESSION_INFO, PDWORD)
    )

def WTSEnumerateSessions(server=None):
    info = P_SESSION_INFO()
    count = DWORD()
    raise_on_zero(_WTSEnumerateSessions(server, 0, 1, ref(info), ref(count)))
    try:
        return tuple(ns_from_struct(info[i]) for i in range(count.value))
    finally:
        _WTSFreeMemory(info)

################################################################################

_WTSDisconnectSession = _wts.fun_fact(
    "WTSDisconnectSession",
    (BOOL, HANDLE, DWORD, BOOL)
    )

def WTSDisconnectSession(session_id, server=None, wait=True):
    raise_on_zero(_WTSDisconnectSession(server, session_id, wait))

################################################################################

