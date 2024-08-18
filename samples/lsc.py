################################################################################
#
# Copyright 2021-2024 Rocco Matano
# SPDX-License-Identifier: MIT
#
################################################################################
#
# This sample demonstrates how to open a console window where `cmd.exe` is
# running under the local system account (this requires administrative
# privileges). Hence the name: `local system console` -> `lsc`. If you examine
# this code more closely, you will find that it can do even more than that.
#
################################################################################

import sys
from pathlib import Path
from ctwin32 import kernel, advapi, svc_util

################################################################################

def to_be_run_as_system(*args):
    kernel.dbg_print(f"in to_be_run_as_system: {kernel.GetCurrentThreadId()}")

    # 1st arg: directory where to run
    # 2nd arg: session where to run
    #
    # possible arg structures
    # a) cwd session InitialCommandForCmdExe...
    # b) cwd session 'cpy_tok' ProcessId CommandLineToBeExecuted...

    if len(args) > 1:
        kernel.SetCurrentDirectory(args[0])
        session = int(args[1])
        if len(args) > 4 and args[2] == "cpy_tok":
            pid = int(args[3])
            arglist = args[4:]
        else:
            pid = kernel.GetCurrentProcessId()
            arglist = ["cmd.exe", "/K", "title", "LocalSystem", "&"]
            arglist.extend(args[2:])

        svc_util.create_process_in_session_copy_token(session, pid, arglist)
        kernel.dbg_print("process was created")

################################################################################

if __name__ == "__main__":
    if advapi.running_as_admin():
        session = kernel.ProcessIdToSessionId(kernel.GetCurrentProcessId())
        arglist = [Path.cwd(), session, *sys.argv[1:]]
        kernel.dbg_print("trying to run as system")
        svc_util.func_as_system(__file__, to_be_run_as_system.__name__, arglist)
    else:
        print("Running as system requires administrative privileges.")

################################################################################
