################################################################################
#
# Copyright 2021-2024 Rocco Matano
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

import ctypes
from .wtypes import (
    byte_buffer,
    BOOLEAN,
    ENDIANNESS,
    LONG,
    PVOID,
    ULONG,
    )
from .ntdll import raise_failed_status
from . import (
    ref,
    fun_fact,
    raise_on_zero,
    ns_from_struct,
    SystemExecutionState,
    ProcessorInformation,
    kernel,
    )

################################################################################

_popro = ctypes.WinDLL("powrprof.dll", use_last_error=True)

_CallNtPowerInformation = fun_fact(
    _popro.CallNtPowerInformation,
    (LONG, LONG, PVOID, ULONG, PVOID, ULONG),
    )

def CallNtPowerInformation(level, outsize=0, input=None):
    src, slen = (None, 0) if not input else (ref(input), ULONG(len(input)))
    dst, dlen = byte_buffer(outsize), ULONG(outsize)
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

