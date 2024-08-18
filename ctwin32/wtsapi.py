################################################################################
#
# Copyright 2021-2024 Rocco Matano
# SPDX-License-Identifier: MIT
#
################################################################################

import ctypes
from .wtypes import (
    BOOL,
    DWORD,
    HANDLE,
    LONG,
    PDWORD,
    POINTER,
    PVOID,
    PWSTR,
    )
from . import (
    ref,
    fun_fact,
    raise_on_zero,
    ns_from_struct,
    )

################################################################################

_wts = ctypes.WinDLL("wtsapi32.dll", use_last_error=True)

class WTS_SESSION_INFO(ctypes.Structure):
    _fields_ = (
        ("SessionId", DWORD),
        ("pWinStationName", PWSTR),
        ("State", LONG),
        )
P_SESSION_INFO = POINTER(WTS_SESSION_INFO)
PP_SESSION_INFO = POINTER(P_SESSION_INFO)

################################################################################

_WTSFreeMemory = fun_fact(_wts.WTSFreeMemory, (None, PVOID))

################################################################################

_WTSEnumerateSessions = fun_fact(
    _wts.WTSEnumerateSessionsW,
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

_WTSDisconnectSession = fun_fact(
    _wts.WTSDisconnectSession, (BOOL, HANDLE, DWORD, BOOL)
    )

def WTSDisconnectSession(session_id, server=None, wait=True):
    raise_on_zero(_WTSDisconnectSession(server, session_id, wait))

################################################################################

