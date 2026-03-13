################################################################################
#
# Copyright 2021-2026 Rocco Matano
# SPDX-License-Identifier: MIT
#
################################################################################
#
# This sample demonstrates how to use VirtualQuery to enumerate the modules of
# the current process and VirtualQueryEx to enumerate the modules of another
# process. For easier enumeration the calls to VirtualQuery(Ex) are wrapped
# inside enum_memory_info(_ex).

import sys
from ctwin32 import kernel, psapi
from ctwin32 import MEM_IMAGE, PROCESS_QUERY_INFORMATION, PROCESS_VM_READ

print("current process:")
addr = 0
for info in kernel.enum_memory_info():
    hmod = info.AllocationBase
    if hmod == info.BaseAddress and info.Type == MEM_IMAGE:
        name = kernel.GetModuleFileName(hmod)
        print(f"0x{hmod:016x} : {name}")

if len(sys.argv) > 1:
    try:
        pid = int(sys.argv[1], 0)
    except ValueError:
        sys.exit(1)

    print(f"\nprocess with PID {pid}:")
    acc = PROCESS_QUERY_INFORMATION | PROCESS_VM_READ
    with kernel.OpenProcess(acc, False, pid) as hproc:
        for info in kernel.enum_memory_info_ex(hproc):
            hmod = info.AllocationBase
            if hmod == info.BaseAddress and info.Type == MEM_IMAGE:
                name = psapi.GetModuleFileNameEx(hproc, hmod)
                print(f"0x{hmod:016x} : {name}")
