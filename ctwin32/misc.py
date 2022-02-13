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
from .ntdll import _raise_failed_status
from . import (
    ctypes,
    ref,
    fun_fact,
    raise_if,
    multi_str_from_addr,
    SystemExecutionState,
    TOKEN_READ,
    kernel,
    advapi,
    )

################################################################################

_popro = ctypes.windll.powrprof

_CallNtPowerInformation = fun_fact(
    _popro.CallNtPowerInformation,
    (LONG, LONG, PVOID, ULONG, PVOID, ULONG),
    )

def CallNtPowerInformation(level, outsize=0, input=None):
    src, slen = (None, 0) if not input else (ref(input), ULONG(len(input)))
    dst, dlen = ctypes.create_string_buffer(outsize), ULONG(outsize)
    _raise_failed_status(_CallNtPowerInformation(level, src, slen, dst, dlen))
    return dst.value

################################################################################

def get_system_execution_state():
    bts = CallNtPowerInformation(SystemExecutionState, ctypes.sizeof(ULONG))
    # result is a combination of ES_SYSTEM_REQUIRED, ES_DISPLAY_REQUIRED,
    # ES_USER_PRESENT, ES_AWAYMODE_REQUIRED and ES_CONTINUOUS
    return int.from_bytes(bts, byteorder='little', signed=False)

################################################################################

_SetSuspendState = fun_fact(
    _popro.SetSuspendState,
    (BOOLEAN, BOOLEAN, BOOLEAN, BOOLEAN)
    )

def SetSuspendState(hibernate, force, wakeup_events_disabled):
    raise_if(not _SetSuspendState(hibernate, force, wakeup_events_disabled))

################################################################################

_wts = ctypes.windll.wtsapi32

class WTS_SESSION_INFO(ctypes.Structure):
    _fields_ = (
        ("SessionId", DWORD),
        ("WinStationName", PWSTR),
        ("State", LONG),
        )
P_SESSION_INFO = ctypes.POINTER(WTS_SESSION_INFO)
PP_SESSION_INFO = ctypes.POINTER(P_SESSION_INFO)

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
    raise_if(not _WTSEnumerateSessions(server, 0, 1, ref(info), ref(count)))
    try:
        res = tuple(
            _namespace(
                session_id=info[i].SessionId,
                win_station_name=info[i].WinStationName,
                state=info[i].State
                )
            for i in range(count.value)
            )
        return res
    finally:
        _WTSFreeMemory(info)

################################################################################

_WTSDisconnectSession = fun_fact(
    _wts.WTSDisconnectSession, (BOOL, HANDLE, DWORD, BOOL)
    )

def WTSDisconnectSession(session_id, server=None, wait=True):
    raise_if(not _WTSDisconnectSession(server, session_id, wait))

################################################################################

_ue = ctypes.windll.userenv

_DestroyEnvironmentBlock = fun_fact(
    _ue.DestroyEnvironmentBlock, (BOOL, PVOID)
    )

_CreateEnvironmentBlock = fun_fact(
    _ue.CreateEnvironmentBlock, (BOOL, PPVOID, HANDLE, BOOL)
    )

def _env_block_from_token(token):
    ptr = PVOID()
    raise_if(not _CreateEnvironmentBlock(ref(ptr), token, False))
    try:
        return multi_str_from_addr(ptr.value)
    finally:
        raise_if(not _DestroyEnvironmentBlock(ptr))

def CreateEnvironmentBlock(token=None):
    if token is None:
        with advapi.OpenProcessToken(kernel.GetCurrentProcess(), TOKEN_READ) as t:
            return _env_block_from_token(t)
    else:
        return _env_block_from_token(token)

def create_env_block_as_dict(token=None):
    return kernel.env_str_to_dict(CreateEnvironmentBlock(token))

################################################################################
