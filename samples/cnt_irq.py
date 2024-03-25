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

import time
import ctypes
import msvcrt
from ctwin32 import (
    ntdll,
    ref,
    SystemBasicInformation,
    SystemProcessorPerformanceInformation,
    )

################################################################################

if __name__ == "__main__":
    print(
        "Interrupts per second for the "
        "individual cores and the sum of these:"
        )

    sbi = ntdll.SYSTEM_BASIC_INFORMATION()
    ntdll.raise_failed_status(
        ntdll.NtQuerySystemInformation(
            SystemBasicInformation,
            ref(sbi),
            ctypes.sizeof(sbi),
            None
            )
        )
    num_proc = sbi.NumberOfProcessors

    # last entries are for sums
    last_cnt = (num_proc + 1) * [0]
    cur_cnt = (num_proc + 1) * [0]
    sppi = (ntdll.SYSTEM_PROCESSOR_PERFORMANCE_INFORMATION * num_proc)()

    done_first = False
    while not msvcrt.kbhit():
        ntdll.raise_failed_status(
            ntdll.NtQuerySystemInformation(
                SystemProcessorPerformanceInformation,
                ref(sppi),
                ctypes.sizeof(sppi),
                None
                )
            )
        cur_cnt[num_proc] = 0
        for i in range(num_proc):
            cur_cnt[i] = sppi[i].InterruptCount
            cur_cnt[num_proc] += cur_cnt[i]

        if done_first:
            for i in range(num_proc + 1):
                print(f"{cur_cnt[i] - last_cnt[i]:5} ", end="")
            print("                \r", end="")

        for i in range(num_proc + 1):
            last_cnt[i] = cur_cnt[i]
        done_first = True
        time.sleep(1)

    while msvcrt.kbhit():
        msvcrt.getch()

################################################################################
