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

from .wtypes import *
from .ntdll import raise_failed_status
from . import (
    ref,
    fun_fact,
    raise_on_zero,
    multi_str_from_addr,
    ns_from_struct,
    SystemExecutionState,
    ProcessorInformation,
    TOKEN_READ,
    kernel,
    advapi,
    )

################################################################################

_popro = ctypes.WinDLL("powrprof.dll")

_CallNtPowerInformation = fun_fact(
    _popro.CallNtPowerInformation,
    (LONG, LONG, PVOID, ULONG, PVOID, ULONG),
    )

def CallNtPowerInformation(level, outsize=0, input=None):
    src, slen = (None, 0) if not input else (ref(input), ULONG(len(input)))
    dst, dlen = ctypes.create_string_buffer(outsize), ULONG(outsize)
    raise_failed_status(_CallNtPowerInformation(level, src, slen, dst, dlen))
    return dst.raw

################################################################################

def get_system_execution_state():
    bts = CallNtPowerInformation(SystemExecutionState, ctypes.sizeof(ULONG))
    # result is a combination of ES_SYSTEM_REQUIRED, ES_DISPLAY_REQUIRED,
    # ES_USER_PRESENT, ES_AWAYMODE_REQUIRED and ES_CONTINUOUS
    return int.from_bytes(bts, byteorder=ENDIANNESS, signed=False)

################################################################################

class PROCESSOR_POWER_INFORMATION(ctypes.Structure):
    _fields_ = (
        ("Number", ULONG),
        ("MaxMhz", ULONG),
        ("CurrentMhz", ULONG),
        ("MhzLimit", ULONG),
        ("MaxIdleState", ULONG),
        ("CurrentIdleState", ULONG),
        )

def get_system_processor_power_info():
    nump = kernel.GetSystemInfo().dwNumberOfProcessors
    PPIN = PROCESSOR_POWER_INFORMATION * nump
    bts = CallNtPowerInformation(ProcessorInformation, ctypes.sizeof(PPIN))
    return [ns_from_struct(i) for i in PPIN.from_buffer_copy(bts)]

################################################################################

_SetSuspendState = fun_fact(
    _popro.SetSuspendState,
    (BOOLEAN, BOOLEAN, BOOLEAN, BOOLEAN)
    )

def SetSuspendState(hibernate, force, wakeup_events_disabled):
    raise_on_zero(_SetSuspendState(hibernate, force, wakeup_events_disabled))

################################################################################

_wts = ctypes.WinDLL("wtsapi32.dll")

class WTS_SESSION_INFO(ctypes.Structure):
    _fields_ = (
        ("SessionId", DWORD),
        ("WinStationName", PWSTR),
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

_ue = ctypes.WinDLL("userenv.dll")

_DestroyEnvironmentBlock = fun_fact(
    _ue.DestroyEnvironmentBlock, (BOOL, PVOID)
    )

_CreateEnvironmentBlock = fun_fact(
    _ue.CreateEnvironmentBlock, (BOOL, PPVOID, HANDLE, BOOL)
    )

def _env_block_from_token(token):
    ptr = PVOID()
    raise_on_zero(_CreateEnvironmentBlock(ref(ptr), token, False))
    try:
        return multi_str_from_addr(ptr.value)
    finally:
        raise_on_zero(_DestroyEnvironmentBlock(ptr))

def CreateEnvironmentBlock(token=None):
    if token is None:
        with advapi.OpenProcessToken(kernel.GetCurrentProcess(), TOKEN_READ) as t:
            return _env_block_from_token(t)
    else:
        return _env_block_from_token(token)

def create_env_block_as_dict(token=None):
    return kernel.env_str_to_dict(CreateEnvironmentBlock(token))

################################################################################
