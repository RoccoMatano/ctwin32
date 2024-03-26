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
    pi = kernel.create_process(arglist, CREATE_SUSPENDED)
    kernel.AssignProcessToJobObject(job, pi.hProcess)

    create_time = kernel.GetSystemTimeAsFileTime()
    kernel.ResumeThread(pi.hThread)
    kernel.WaitForSingleObject(pi.hProcess, INFINITE)
    exit_time = kernel.GetSystemTimeAsFileTime()
    kernel.CloseHandle(pi.hThread)
    kernel.CloseHandle(pi.hProcess)

    info_cls = JobObjectBasicAccountingInformation
    info = kernel.JOBOBJECT_BASIC_ACCOUNTING_INFORMATION()
    kernel.QueryInformationJobObject(job, info_cls, info)
    print(f"\n\nduration  : {fmt_ft(exit_time - create_time)}")
    print(f"kernel    : {fmt_ft(info.TotalKernelTime)}")
    print(f"user      : {fmt_ft(info.TotalUserTime)}")
    print(f"processes : {info.TotalProcesses - 1}")

    kernel.CloseHandle(job)

################################################################################
