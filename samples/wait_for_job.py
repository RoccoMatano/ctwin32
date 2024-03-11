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

import sys
from ctwin32 import (
    kernel,
    CREATE_SUSPENDED,
    INFINITE,
    INVALID_HANDLE_VALUE,
    JobObjectAssociateCompletionPortInformation,
    JOB_OBJECT_MSG_ACTIVE_PROCESS_ZERO
    )

################################################################################

def create_job(arglist):
    arglist = ["cmd", "/c", *arglist] if sys.stdout is not None else arglist
    print(f"{arglist=}")
    job = kernel.CreateJobObject()
    with kernel.create_process(arglist, CREATE_SUSPENDED) as proc_info:
        kernel.AssignProcessToJobObject(job, proc_info.hProcess)
        io_port = kernel.create_io_completion_port(INVALID_HANDLE_VALUE, 0)
        joacp = kernel.JOBOBJECT_ASSOCIATE_COMPLETION_PORT(job, io_port)
        kernel.SetInformationJobObject(
            job,
            JobObjectAssociateCompletionPortInformation,
            joacp
            )
        kernel.ResumeThread(proc_info.hThread)
    return job, io_port

################################################################################

def job_is_still_alive(job, io_port, timeout=INFINITE):
    code, key, ovrl = kernel.GetQueuedCompletionStatus(io_port, timeout)
    return key != job or code != JOB_OBJECT_MSG_ACTIVE_PROCESS_ZERO

################################################################################

if __name__ == "__main__":
    job, io_port = create_job(sys.argv[1:])
    while (job_is_still_alive(job.value, io_port)):
        pass

################################################################################
