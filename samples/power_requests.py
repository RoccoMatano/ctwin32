################################################################################
#
# Copyright 2021-2024 Rocco Matano
# SPDX-License-Identifier: MIT
#
################################################################################

# This sample retrieves and prints power request. This is similar to what
# `powercfg.exe /requests` does.

import ctypes
from ctwin32 import (
    advapi,
    kernel,
    powrprof,
    user,
    suppress_winerr,
    ERROR_INSUFFICIENT_BUFFER,
    LOAD_LIBRARY_AS_DATAFILE,
    LOAD_LIBRARY_AS_IMAGE_RESOURCE,
    )
from ctwin32.wtypes import (
    INT,
    SIZE_T,
    ULONG,
    ULONG_PTR,
    USHORT,
    )

################################################################################

# flags for COUNTED_REASON_CONTEXT_RELATIVE.Flags
DIAGNOSTIC_REASON_SIMPLE_STRING = 0x00000001
DIAGNOSTIC_REASON_DETAILED_STRING = 0x00000002
DIAGNOSTIC_REASON_NOT_SPECIFIED = 0x80000000
DIAGNOSTIC_REASON_INVALID_FLAGS = ~ 0x80000007

class _COUNTED_REASON_CTXT1(ctypes.Structure):
    _fields_ = (
        ("ResourceFileNameOffset", ULONG_PTR),
        ("ResourceReasonId", USHORT),
        ("StringCount", ULONG),
        ("SubstitutionStringsOffset", ULONG),
        )

class _COUNTED_REASON_CTXT2(ctypes.Union):
    _anonymous_ = ("_anon1",)
    _fields_ = (
        ("_anon1", _COUNTED_REASON_CTXT1),
        ("SimpleStringOffset", ULONG_PTR),
        )

class COUNTED_REASON_CONTEXT_RELATIVE(ctypes.Structure):
    _anonymous_ = ("_anon1",)
    _fields_ = (
        ("Flags", ULONG),
        ("_anon1", _COUNTED_REASON_CTXT2),
        )

# caller types for DIAGNOSTIC_BUFFER.CallerType
KERNEL_REQUESTER = 0
PROCESS_REQUESTER = 1
SERVICE_REQUESTER = 2

class _DIAG_BUFF1(ctypes.Structure):
    _fields_ = (
        ("ProcessImageNameOffset", ULONG_PTR),
        ("ProcessId", ULONG),
        ("ServiceTag", ULONG),
        )

class _DIAG_BUFF2(ctypes.Structure):
    _fields_ = (
        ("DeviceDescriptionOffset", ULONG_PTR),
        ("DevicePathOffset", ULONG_PTR),
        )

class _DIAG_BUFF3(ctypes.Union):
    _anonymous_ = ("_anon1", "_anon2")
    _fields_ = (
        ("_anon1", _DIAG_BUFF1),
        ("_anon2", _DIAG_BUFF2),
        )

class DIAGNOSTIC_BUFFER(ctypes.Structure):
    _anonymous_ = ("_anon3",)
    _fields_ = (
        ("Size", SIZE_T),
        ("CallerType", INT),
        ("_anon3", _DIAG_BUFF3),
        ("ReasonOffset", ULONG_PTR),
        )

# !! for simplicity we ignore all the definitions older than Windows 10 RS1+ !!

POWER_REQUEST_SUPPORTED_TYPES = 6

class POWER_REQUEST(ctypes.Structure):
    _fields_ = (
        ("SupportedRequestMask", ULONG),
        ("PowerRequestCount", ULONG * POWER_REQUEST_SUPPORTED_TYPES),
        ("DiagnosticBuffer", DIAGNOSTIC_BUFFER),
        )

################################################################################

def load_res_str(mod_name, msg_id):
    LOLI_FLAGS = LOAD_LIBRARY_AS_DATAFILE | LOAD_LIBRARY_AS_IMAGE_RESOURCE
    with kernel.LoadLibraryEx(mod_name, LOLI_FLAGS) as hmod:
        return user.LoadString(hmod, msg_id)

################################################################################

request_types = {
    0: "DISPLAY",
    1: "SYSTEM",
    2: "AWAYMODE",
    3: "EXECUTION",
    4: "PERFBOOST",
    5: "ACTIVELOCKSCREEN",
    }

requester_types = {
    KERNEL_REQUESTER:  "[DRIVER]",
    PROCESS_REQUESTER: "[PROCESS]",
    SERVICE_REQUESTER: "[SERVICE]",
    }

################################################################################

def get_power_requests():
    GetPowerRequestList = 45
    size = 2048
    buf = None
    while buf is None:
        size *= 2
        with suppress_winerr(ERROR_INSUFFICIENT_BUFFER):
            buf = powrprof.PowerInformationWithPrivileges(
                GetPowerRequestList,
                size
                )

    count = ULONG.from_buffer(buf).value

    class POWER_REQUEST_LIST(ctypes.Structure):
        _fields_ = (
            ("Count", ULONG),
            ("PowerRequestOffsets", ULONG_PTR * count),
            )
    prl = POWER_REQUEST_LIST.from_buffer(buf)

    requests = {k: [] for k in request_types}
    for ri in range(prl.Count):
        pr = POWER_REQUEST.from_buffer(buf, prl.PowerRequestOffsets[ri])

        for rt in request_types:
            # Must not access elements of `PowerRequestCount` that are not
            # approved by `SupportedRequestMask`. Furthermore only requests
            # that have `PowerRequestCount[rt]` != 0 are active.
            add_this = (
                ((1 << rt) & pr.SupportedRequestMask) and
                pr.PowerRequestCount[rt]
                )
            if not add_this:
                continue

            calltype = pr.DiagnosticBuffer.CallerType
            callt_str = requester_types[calltype]
            db = pr.DiagnosticBuffer
            db_addr = ctypes.addressof(db)
            if calltype == KERNEL_REQUESTER:
                callid = [
                    ctypes.wstring_at(db_addr + db.DeviceDescriptionOffset),
                    ctypes.wstring_at(db_addr + db.DevicePathOffset)
                    ]
            else:
                callid = [
                    ctypes.wstring_at(db_addr + db.ProcessImageNameOffset),
                    f"pid:{db.ProcessId}"
                    ]
            reason = ""
            if pr.DiagnosticBuffer.ReasonOffset:
                ro = COUNTED_REASON_CONTEXT_RELATIVE.from_address(
                    db_addr + pr.DiagnosticBuffer.ReasonOffset
                    )
                ro_addr = ctypes.addressof(ro)
                if ro.Flags & DIAGNOSTIC_REASON_SIMPLE_STRING:
                    reason = ctypes.wstring_at(ro_addr + ro.SimpleStringOffset)
                elif ro.Flags & DIAGNOSTIC_REASON_DETAILED_STRING:
                    mod_name = ctypes.wstring_at(
                        ro_addr + ro.ResourceFileNameOffset
                        )
                    reason = load_res_str(mod_name, ro.ResourceReasonId)

            requests[rt].append((callt_str, callid, reason))

    return requests

################################################################################

def print_power_requests():
    requests = get_power_requests()
    print()
    for req_type in sorted(request_types):
        requesters = requests[req_type]
        tstr = request_types[req_type]
        print(f"{tstr}:\n{(len(tstr) + 1) * '-'}")
        if not requesters:
            print("None\n")
            continue
        for ct, cid, reason in requesters:
            print(f"{ct} ", end="")
            for element in cid:
                print(element)
            print(f"{reason}\n")

################################################################################

if __name__ == "__main__":

    if advapi.running_as_admin():
        print("initial:")
        print(80 * "-")
        print_power_requests()

        # create and activate a SystemRequired request
        print("with self created 'SystemRequired' request:")
        print(80 * "-")
        reason = "demonstrating power requests"
        req = kernel.PowerRequest.SystemRequired
        with kernel.create_power_request(reason, req) as hdl:
            print_power_requests()

        print("final:")
        print(80 * "-")
        print_power_requests()
    else:
        print("Inquiring power request requires administrative privileges.")

################################################################################
