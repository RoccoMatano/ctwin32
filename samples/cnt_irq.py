################################################################################
#
# Copyright 2021-2024 Rocco Matano
# SPDX-License-Identifier: MIT
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
