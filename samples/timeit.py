################################################################################
#
# Copyright 2021-2024 Rocco Matano
# SPDX-License-Identifier: MIT
#
################################################################################

# This example shows how you can use a job object to collect information
# about a process.

import sys
from ctwin32 import (
    kernel,
    CREATE_SUSPENDED,
    INFINITE,
    JobObjectBasicAccountingInformation,
    )

################################################################################

def fmt_ft(ft):
    q, _ = divmod(int(ft), 10000)
    q, ms = divmod(q, 1000)
    q, s = divmod(q, 60)
    h, m = divmod(q, 60)
    return f"{h}:{m:02}:{s:02}.{ms:03}"

################################################################################

if __name__ == "__main__":

    arglist = ["cmd", "/c", *sys.argv[1:]]
    job = kernel.CreateJobObject()
    with kernel.create_process(arglist, CREATE_SUSPENDED) as pi:
        kernel.AssignProcessToJobObject(job, pi.hProcess)
        create_time = kernel.GetSystemTimeAsFileTime()
        kernel.ResumeThread(pi.hThread)
        kernel.WaitForSingleObject(pi.hProcess, INFINITE)
        exit_time = kernel.GetSystemTimeAsFileTime()

    info_cls = JobObjectBasicAccountingInformation
    info = kernel.JOBOBJECT_BASIC_ACCOUNTING_INFORMATION()
    kernel.QueryInformationJobObject(job, info_cls, info)
    print(f"\n\nduration  : {fmt_ft(exit_time - create_time)}")
    print(f"kernel    : {fmt_ft(info.TotalKernelTime)}")
    print(f"user      : {fmt_ft(info.TotalUserTime)}")
    print(f"processes : {info.TotalProcesses - 1}")

    kernel.CloseHandle(job)

################################################################################
