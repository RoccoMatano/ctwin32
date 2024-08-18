################################################################################
#
# Copyright 2021-2024 Rocco Matano
# SPDX-License-Identifier: MIT
#
################################################################################

# This sample prints all the environments, that are available. When run with
# administrative privileges the number of accessible environments will be a
# little higher.

from ctwin32 import (
    kernel,
    ntdll,
    PROCESS_VM_READ,
    PROCESS_QUERY_LIMITED_INFORMATION,
    SE_DEBUG_PRIVILEGE,
    )

try:
    ntdll.RtlAdjustPrivilege(SE_DEBUG_PRIVILEGE, True)
except OSError:
    print("\nFailed to enable debug privilege.")
    print("Several environments will be not be available.\n")

oflg = PROCESS_VM_READ | PROCESS_QUERY_LIMITED_INFORMATION

for np in ntdll.enum_processes():
    print(f"{np.pid:5} {np.name}:")
    try:
        with kernel.OpenProcess(oflg, False, np.pid) as hdl:
            for k,v in sorted(kernel.get_proc_env_as_dict(hdl).items()):
                print(f"    {k} = {v}")
    except OSError as e:
        print(f"    {e}")
    print()
