################################################################################
#
# Copyright 2021-2023 Rocco Matano
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
#
# This sample demonstrates how to open a console window where `cmd.exe` is
# running under the local system account (this requires administrative
# privileges). Hence the name: `local system console` -> `lsc`. If you examine
# this code more closely, you will find that it can do even more than that.
#
################################################################################

import sys
import traceback
from pathlib import Path
from ctwin32 import (
    kernel,
    advapi,
    wtypes,
    cmdline_from_args,
    SC_MANAGER_CREATE_SERVICE,
    SERVICE_START,
    SERVICE_QUERY_STATUS,
    DELETE,
    SERVICE_WIN32_OWN_PROCESS,
    SERVICE_DEMAND_START,
    SERVICE_ERROR_NORMAL,
    SERVICE_RUNNING,
    SERVICE_ACCEPT_STOP,
    SERVICE_STOPPED,
    ERROR_SERVICE_EXISTS,
    ERROR_FAILED_SERVICE_CONTROLLER_CONNECT,
    MAXIMUM_ALLOWED,
    TOKEN_DUPLICATE,
    NORMAL_PRIORITY_CLASS,
    CREATE_NEW_CONSOLE,
    SecurityIdentification,
    TokenPrimary,
    TokenSessionId,
    )

################################################################################

THIS = Path(__file__).resolve()
LOGFILE_NAME = THIS.with_suffix(".err")
LOGFILE = None

################################################################################

def _log_and_exit(err_str):
    if LOGFILE is not None:
        LOGFILE.write(err_str)
        LOGFILE.close()
    else:
        sys.stderr.write(err_str)

    kernel.ExitProcess(1)

################################################################################

def _file_except_hook(typ, value, tb):
    _log_and_exit("".join(traceback.format_exception(typ, value, tb)))

################################################################################

def detour_fatal_to_file(path=None):
    global LOGFILE    # noqa: using intentionally a quick and dirty global
    if path is None:
        path = LOGFILE_NAME
    if LOGFILE is not None:
        LOGFILE.close()
    LOGFILE = open(path, "w") # noqa: context handler inappropriate here
    sys.excepthook = _file_except_hook

################################################################################

def dbg_print(*args, end="\n"):
    kernel.OutputDebugString(f"{' '.join(map(str, args))}{end}")

################################################################################

def start_as_service(service_name, arglist):
    with advapi.OpenSCManager(None, None, SC_MANAGER_CREATE_SERVICE) as scm:
        create_args = (
            scm,
            service_name,
            service_name,
            SERVICE_START | SERVICE_QUERY_STATUS | DELETE,
            SERVICE_WIN32_OWN_PROCESS,
            SERVICE_DEMAND_START,
            SERVICE_ERROR_NORMAL,
            cmdline_from_args([sys.executable, THIS])
            )
        for _ in range(2):
            try:
                with advapi.CreateService(*create_args) as svc:
                    advapi.StartService(svc, arglist)
                    advapi.DeleteService(svc)
                break
            except OSError as e:
                dbg_print(f"create/start err: {e}")
                if e.winerror == ERROR_SERVICE_EXISTS:
                    with advapi.OpenService(scm, service_name, DELETE) as svc:
                        advapi.DeleteService(svc)
                else:
                    raise

################################################################################

def create_process_in_session_copy_token(session, pid, arglist):
    with kernel.OpenProcess(MAXIMUM_ALLOWED, False, pid) as hproc:
        with advapi.OpenProcessToken(hproc, TOKEN_DUPLICATE) as htok:
            # Cannot set the session ID of a token that is in use by a process.
            # Therefore we have to duplicate the token.
            dte_args = (
                htok,
                MAXIMUM_ALLOWED,
                kernel.SECURITY_ATTRIBUTES(),
                SecurityIdentification,
                TokenPrimary,
                )
            with advapi.DuplicateTokenEx(*dte_args) as hdup:
                # set the session
                session = wtypes.ULONG(session)
                advapi.SetTokenInformation(hdup, TokenSessionId, session)

                # the main purpose of this program
                si = kernel.STARTUPINFO()
                si.lpDesktop = "WinSta0\\default"
                flags = NORMAL_PRIORITY_CLASS | CREATE_NEW_CONSOLE
                with advapi.create_process_as_user(hdup, arglist, flags, si):
                    pass

################################################################################

@advapi.SERVICE_MAIN_FUNCTION
def service_main(argc, argv):
    # Since this is a python callback that ctypes calls when requested
    # by foreign C code, ctypes has no way of propagating any exception
    # back to the python interpreter - those would simply be ignored.
    # Therefore we have to catch all unhandled exceptions here.
    try:
        dbg_print("in service_main", kernel.GetCurrentThreadId())

        # 1st arg: service name
        # 2nd arg: directory where to run
        # 3rd arg: session where to run
        #
        # possible arg structures
        # a) name cwd session InitialCommandForCmdExe...
        # b) name cwd session 'copy' ProcessId CommandLineToBeExecuted...

        # convert PPWSTR to list of strings
        argv = [argv[i] for i in range(argc)]
        for i, arg in enumerate(argv):
            dbg_print(f"service arg[{i}]: {arg}")

        @advapi.HANDLER_FUNCTION
        def handler(control):
            pass

        hdl = advapi.RegisterServiceCtrlHandler(argv[0], handler)

        svc_stat = advapi.SERVICE_STATUS(
            SERVICE_WIN32_OWN_PROCESS,
            SERVICE_RUNNING,
            SERVICE_ACCEPT_STOP
            )
        advapi.SetServiceStatus(hdl, svc_stat)

        if argc > 2:
            kernel.SetCurrentDirectory(argv[1])
            session = int(argv[2])
            do_copy = len(argv) > 5 and argv[3] == "copy"
            if not do_copy:
                pid = kernel.GetCurrentProcessId()
                arglist = ["cmd.exe", "/K", "title", "LocalSystem", "&"]
                arglist.extend(argv[3:])
            else:
                pid = int(argv[4])
                arglist = argv[5:]
            create_process_in_session_copy_token(session, pid, arglist)
            dbg_print("process was created")

        svc_stat.dwCurrentState = SERVICE_STOPPED
        advapi.SetServiceStatus(hdl, svc_stat)
        dbg_print("sevice was stopped")

    except BaseException:
        _log_and_exit(traceback.format_exc())
    dbg_print("returning from service main", kernel.GetCurrentThreadId())

################################################################################

def main():
    service_name = "ctwin32_lsc"    # lsc -> "Local System" console

    table = (advapi.SERVICE_TABLE_ENTRY * 2)()
    table[0].lpServiceName = service_name
    table[0].lpServiceProc = service_main
    # table[1] will be zero initialized by default, which is exactly
    # what we need

    # AFAIK the only way to be certain that this process was started by the
    # SCM and is supposed to run as a service, is to try to run as a service,
    # i.e. to call StartServiceCtrlDispatcher
    try:
        dbg_print("trying to start dispatcher", kernel.GetCurrentThreadId())
        advapi.StartServiceCtrlDispatcher(table)
        need_to_start = False
        dbg_print("returned from dispatcher", kernel.GetCurrentThreadId())
    except OSError as e:
        if e.winerror == ERROR_FAILED_SERVICE_CONTROLLER_CONNECT:
            need_to_start = True
        else:
            raise
    if need_to_start:
        dbg_print("trying to start svc")
        session = kernel.ProcessIdToSessionId(kernel.GetCurrentProcessId())
        arglist = [str(Path.cwd()), str(session)] + sys.argv[1:]
        start_as_service(service_name, arglist)


################################################################################

if __name__ == "__main__":
    detour_fatal_to_file()
    dbg_print(f"starting lsc: {kernel.GetCurrentProcessId()}")
    main()

################################################################################
