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

from . import _fun_fact, _raise_if, SystemExecutionState
from .ntdll import _raise_failed_status

_ref = _ct.byref
_popro = _ct.windll.powrprof

################################################################################

_CallNtPowerInformation = _fun_fact(
    _popro.CallNtPowerInformation,
    (_wt.LONG, _wt.LONG, _wt.LPVOID, _wt.ULONG, _wt.LPVOID, _wt.ULONG),
    )

def CallNtPowerInformation(level, outsize=0, input=None):
    src, slen = (None, 0) if not input else (_ref(input), _wt.ULONG(len(input)))
    dst, dlen = _ct.create_string_buffer(outsize), _wt.ULONG(outsize)
    _raise_failed_status(_CallNtPowerInformation(level, src, slen, dst, dlen))
    return dst.value

################################################################################

def get_system_execution_state():
    bts = CallNtPowerInformation(SystemExecutionState, _ct.sizeof(_wt.ULONG))
    # result is a combination of ES_SYSTEM_REQUIRED, ES_DISPLAY_REQUIRED,
    # ES_USER_PRESENT, ES_AWAYMODE_REQUIRED and ES_CONTINUOUS
    return int.from_bytes(bts, byteorder='little', signed=False)

################################################################################

_SetSuspendState = _fun_fact(
    _popro.SetSuspendState,
    (_wt.BOOLEAN, _wt.BOOLEAN, _wt.BOOLEAN, _wt.BOOLEAN)
    )

def SetSuspendState(hibernate, force, wakeup_events_disabled):
    _raise_if(not _SetSuspendState(hibernate, force, wakeup_events_disabled))

################################################################################

_wts = _ct.windll.wtsapi32

class WTS_SESSION_INFO(_ct.Structure):
    _fields_ = (
        ("SessionId", _wt.DWORD),
        ("WinStationName", _wt.LPCWSTR),
        ("State", _wt.LONG),
        )
_P_SESSION_INFO = _ct.POINTER(WTS_SESSION_INFO)
_PP_SESSION_INFO = _ct.POINTER(_P_SESSION_INFO)

################################################################################

_WTSFreeMemory = _fun_fact(_wts.WTSFreeMemory, (None, _wt.LPVOID))

################################################################################

_WTSEnumerateSessions = _fun_fact(
    _wts.WTSEnumerateSessionsW,
    (_wt.BOOL, _wt.HANDLE, _wt.DWORD, _wt.DWORD, _PP_SESSION_INFO, _wt.PDWORD)
    )

def WTSEnumerateSessions(server=None):
    info = _P_SESSION_INFO()
    count = _wt.DWORD()
    _raise_if(not _WTSEnumerateSessions(server, 0, 1, _ref(info), _ref(count)))
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

_WTSDisconnectSession = _fun_fact(
    _wts.WTSDisconnectSession, (_wt.BOOL, _wt.HANDLE, _wt.DWORD, _wt.BOOL)
    )

def WTSDisconnectSession(session_id, server=None, wait=True):
    _raise_if(not _WTSDisconnectSession(server, session_id, wait))

################################################################################
