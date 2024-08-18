################################################################################
#
# Copyright 2021-2024 Rocco Matano
# SPDX-License-Identifier: MIT
#
################################################################################

# This example shows how to wait for a job object. I.e. waiting until all
# processes in this job stopped executing.

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
