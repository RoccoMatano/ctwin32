################################################################################
#
# Copyright 2021-2025 Rocco Matano
# SPDX-License-Identifier: MIT
#
################################################################################

import ctypes
from .wtypes import (
    byte_buffer,
    BOOLEAN,
    Struct,
    ENDIANNESS,
    LONG,
    PVOID,
    ULONG,
    )
from .ntdll import raise_failed_status
from . import (
    ApiDll,
    ref,
    raise_on_zero,
    ns_from_struct,
    SystemExecutionState,
    ProcessorInformation,
    kernel,
    )

################################################################################

_popro = ApiDll("powrprof.dll")

_CallNtPowerInformation = _popro.fun_fact(
    "CallNtPowerInformation",
    (LONG, LONG, PVOID, ULONG, PVOID, ULONG),
    )

def CallNtPowerInformation(level, outsize=0, input=None):
    src, slen = (None, 0) if not input else (ref(input), ULONG(len(input)))
    dst, dlen = byte_buffer(outsize), ULONG(outsize)
    raise_failed_status(_CallNtPowerInformation(level, src, slen, dst, dlen))
    return dst.raw

################################################################################

_PowerInformationWithPrivileges = _popro.fun_fact(
    "PowerInformationWithPrivileges",
    (LONG, LONG, PVOID, ULONG, PVOID, ULONG),
    )

def PowerInformationWithPrivileges(level, outsize=0, input=None):
    src, slen = (None, 0) if not input else (ref(input), ULONG(len(input)))
    dst, dlen = byte_buffer(outsize), ULONG(outsize)
    raise_failed_status(
        _PowerInformationWithPrivileges(level, src, slen, dst, dlen)
        )
    return dst

################################################################################

def get_system_execution_state():
    bts = CallNtPowerInformation(SystemExecutionState, ctypes.sizeof(ULONG))
    # result is a combination of ES_SYSTEM_REQUIRED, ES_DISPLAY_REQUIRED,
    # ES_USER_PRESENT, ES_AWAYMODE_REQUIRED and ES_CONTINUOUS
    return int.from_bytes(bts, byteorder=ENDIANNESS, signed=False)

################################################################################

class PROCESSOR_POWER_INFORMATION(Struct):
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
    bts = CallNtPowerInformation(ProcessorInformation, PPIN._size_)
    return [ns_from_struct(i) for i in PPIN.from_buffer_copy(bts)]

################################################################################

_SetSuspendState = _popro.fun_fact(
    "SetSuspendState",
    (BOOLEAN, BOOLEAN, BOOLEAN, BOOLEAN)
    )

def SetSuspendState(hibernate, force, wakeup_events_disabled):
    raise_on_zero(_SetSuspendState(hibernate, force, wakeup_events_disabled))

################################################################################

