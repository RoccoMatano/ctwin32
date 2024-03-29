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
