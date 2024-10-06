################################################################################
#
# Copyright 2021-2024 Rocco Matano
# SPDX-License-Identifier: MIT
#
################################################################################

import sys
import time
import uuid
from pathlib import Path
from importlib.util import spec_from_file_location, module_from_spec

# Note: Since this file will not only serve as a module of its parent package
#       but also as a standalone script, we cannot use 'from . import ('.
from ctwin32 import (
    advapi,
    cmdline_from_args,
    kernel,
    wtypes,
    CREATE_NEW_CONSOLE,
    DELETE,
    ERROR_SERVICE_EXISTS,
    MAXIMUM_ALLOWED,
    NORMAL_PRIORITY_CLASS,
    PROCESS_QUERY_LIMITED_INFORMATION,
    SC_MANAGER_CONNECT,
    SC_MANAGER_CREATE_SERVICE,
    SecurityIdentification,
    SERVICE_ACCEPT_STOP,
    SERVICE_DEMAND_START,
    SERVICE_ERROR_NORMAL,
    SERVICE_QUERY_STATUS,
    SERVICE_RUNNING,
    SERVICE_START,
    SERVICE_STOPPED,
    SERVICE_WIN32_OWN_PROCESS,
    TokenPrimary,
    TokenSessionId,
    TOKEN_DUPLICATE,
    )

################################################################################

_FILE = Path(__file__).resolve()

################################################################################

def _load_func(file_name, func_name):
    dont_write_bytecode = sys.dont_write_bytecode
    sys.dont_write_bytecode = True

    file_path = Path(file_name)
    module_name = file_path.stem
    if module_name in sys.modules:
        raise ImportError(f"already a module: {module_name}")
    spec = spec_from_file_location(module_name, file_path)
    module = module_from_spec(spec)
    sys.modules[module_name] = module
    spec.loader.exec_module(module)

    sys.dont_write_bytecode = dont_write_bytecode
    return getattr(module, func_name)

################################################################################

@advapi.SERVICE_MAIN_FUNCTION
def _service_main(argc, argv):
    # Since this is a python callback that ctypes calls when requested
    # by foreign C code, ctypes has no way of propagating any exception
    # back to the python interpreter - those would simply be ignored.
    # Therefore any exception has to terminate the process.
    with kernel.terminate_on_exception():
        tid = kernel.GetCurrentThreadId()
        kernel.dbg_print(f"in service_main: {tid}")

        # convert PPWSTR to list of strings
        arglist = [argv[i] for i in range(argc)]

        # arguments for service_main will be:
        #   0       service name
        #   1       path to module implementing the function to be run
        #   2       name of the function to be run
        #   3 ...   string arguments for function

        for i, arg in enumerate(arglist):
            kernel.dbg_print(f"service arg[{i}]: {arg}")

        @advapi.HANDLER_FUNCTION
        def handler(control):
            # Since this service is expected to be very short-lived, we simply
            # ignore control requests.
            pass

        hdl = advapi.RegisterServiceCtrlHandler(arglist[0], handler)
        svc_stat = advapi.SERVICE_STATUS(
            SERVICE_WIN32_OWN_PROCESS,
            SERVICE_RUNNING,
            SERVICE_ACCEPT_STOP
            )
        advapi.SetServiceStatus(hdl, svc_stat)

        func = _load_func(arglist[1], arglist[2])
        fargs = arglist[3:]
        str_args = f"*{fargs}" if fargs else ""
        kernel.dbg_print(f"calling '{arglist[2]}({str_args})'")
        func(*fargs)

        svc_stat.dwCurrentState = SERVICE_STOPPED
        advapi.SetServiceStatus(hdl, svc_stat)
        kernel.dbg_print(f"returning from _service main: {tid}")

################################################################################

def _run_service():
    tid = kernel.GetCurrentThreadId()
    kernel.dbg_print(f"trying to start dispatcher: {tid}")

    # For a service with SERVICE_WIN32_OWN_PROCESS set, windows will ignore
    # the service name in the dispatch table.
    table = (advapi.SERVICE_TABLE_ENTRY * 2)()
    table[0].lpServiceName = ""
    table[0].lpServiceProc = _service_main
    # table[1] will be zero initialized by default, which is exactly
    # what we need

    # Calling StartServiceCtrlDispatcher will fail if this process was not
    # started by the SCM and is not supposed to run as a service.
    advapi.StartServiceCtrlDispatcher(table)
    kernel.dbg_print(f"returned from dispatcher: {tid}")

################################################################################

def _start_as_service(arglist):
    # Arguments for _start_as_service will be:
    #   0       path to module implementing the function to be run
    #   1       name of the function to be run
    #   2 ...   string arguments for function
    #
    # But _start_as_service doesn't really care. However, _service_main will
    # very well take this into account.

    service_name = str(uuid.uuid4())
    with advapi.OpenSCManager(None, None, SC_MANAGER_CREATE_SERVICE) as scm:
        create_args = (
            scm,
            service_name,
            service_name,
            SERVICE_START | SERVICE_QUERY_STATUS | DELETE,
            SERVICE_WIN32_OWN_PROCESS,
            SERVICE_DEMAND_START,
            SERVICE_ERROR_NORMAL,
            cmdline_from_args([sys.executable, _FILE, "_run_service"])
            )
        for _ in range(2):
            try:
                with advapi.CreateService(*create_args) as svc:
                    advapi.StartService(svc, arglist)
                    advapi.DeleteService(svc)
                break
            except OSError as e:
                kernel.dbg_print(f"create/start err: {e}")
                if e.winerror == ERROR_SERVICE_EXISTS:
                    with advapi.OpenService(scm, service_name, DELETE) as svc:
                        advapi.DeleteService(svc)
                else:
                    raise

################################################################################

def _prepare_service_args(file_name, func_name, arglist):
    if arglist is None:
        arglist = []
    service_args = []
    for arg in [file_name, func_name, *arglist]:
        if isinstance(arg, (int, Path)):
            service_args.append(str(arg))
        elif not isinstance(arg, str):
            raise TypeError("need str, got '{arg}' ({type(arg).__name__})")
        else:
            service_args.append(arg)

    # ensure import will not raise an exception
    func = _load_func(service_args[0], service_args[1])
    if not callable(func):
        raise TypeError(f"'{func_name}' must be callable")

    return service_args

################################################################################

def func_as_system(file_name, func_name, arglist=None):
    # `func_name` must be defined in the toplevel namespace of `file_name`
    service_args = _prepare_service_args(file_name, func_name, arglist)
    _start_as_service(service_args)

################################################################################

def create_process_in_session_copy_token(session, pid, arglist, flags=None):
    pqli = PROCESS_QUERY_LIMITED_INFORMATION
    with kernel.OpenProcess(pqli, False, pid) as hproc:
        with advapi.OpenProcessToken(hproc, TOKEN_DUPLICATE) as htok:
            # Cannot set the session ID of a token that is in use by a process.
            # Therefore we have to duplicate the token.
            duplicate_token_args = (
                htok,
                MAXIMUM_ALLOWED,
                kernel.SECURITY_ATTRIBUTES(),
                SecurityIdentification,
                TokenPrimary,
                )
            with advapi.DuplicateTokenEx(*duplicate_token_args) as hdup:
                # set the session
                session = wtypes.ULONG(session)
                advapi.SetTokenInformation(hdup, TokenSessionId, session)

                si = kernel.STARTUPINFO()
                si.lpDesktop = r"WinSta0\default"
                if flags is None:
                    flags = NORMAL_PRIORITY_CLASS | CREATE_NEW_CONSOLE
                with advapi.create_process_as_user(hdup, arglist, flags, si):
                    pass

################################################################################

def _call_func_as_svc_acc(*args):
    # args[0] : name of file defining function name to be called
    # args[1] : function name to be called
    # args[2:]: arguments for function
    kernel.dbg_print("in _call_func_as_svc_acc")
    for i, arg in enumerate(args):
        kernel.dbg_print(f"arg[{i}]: {arg}")

    func = _load_func(args[0], args[1])
    fargs = args[2:]
    str_args = f"*{fargs}" if fargs else ""
    kernel.dbg_print(f"calling '{args[1]}({str_args})'")
    func(*fargs)

################################################################################

def get_service_pid(name):
    with advapi.OpenSCManager(None, None, SC_MANAGER_CONNECT) as scm:
        flags = SERVICE_START | SERVICE_QUERY_STATUS
        with advapi.OpenService(scm, name, flags) as svc:
            status = advapi.QueryServiceStatusEx(svc)
            if status.dwProcessId:
                return status.dwProcessId
            else:
                advapi.StartService(svc, [])
                deadline = time.time() + 2
                status = advapi.QueryServiceStatusEx(svc)
                while not status.dwProcessId:
                    if time.time() >= deadline:
                        raise OSError("timeout waiting for service to start")
                    status = advapi.QueryServiceStatusEx(svc)
                return status.dwProcessId

################################################################################

def _service_account_from_system(*args):
    kernel.dbg_print("in _service_account_from_system")
    for i, arg in enumerate(args):
        kernel.dbg_print(f"arg[{i}]: {arg}")

    # possible arg structures
    # a) service_name cwd session file_name func_name *func_args
    # b) service_name 'command' cwd session *command_line_args
    pid = get_service_pid(args[0])
    if args[1] == "command":
        directory = args[2]
        session = int(args[3])
        arglist = args[4:]
    else:
        directory = args[1]
        session = int(args[2])
        arglist = [sys.executable, str(_FILE), "_call_func_as_svc_acc"]
        arglist.extend(args[3:])

    kernel.SetCurrentDirectory(directory)
    create_process_in_session_copy_token(session, pid, arglist)
    kernel.dbg_print("process was created")

################################################################################

def func_as_trusted_installer(file_name, func_name, arglist=None):
    # `func_name` must be defined in the toplevel namespace of `file_name`
    arglist = _prepare_service_args(file_name, func_name, arglist)
    ti_args = [
        "TrustedInstaller",
        Path.cwd(),
        kernel.ProcessIdToSessionId(kernel.GetCurrentProcessId()),
        *arglist
        ]
    ti_args = _prepare_service_args(
        _FILE,
        _service_account_from_system.__name__,
        ti_args
        )
    _start_as_service(ti_args)

################################################################################

def proc_as_trusted_installer(*command_line_args):
    arglist = [
        "TrustedInstaller",
        "command",
        Path.cwd(),
        kernel.ProcessIdToSessionId(kernel.GetCurrentProcessId()),
        *command_line_args
        ]
    _start_as_service(
        _prepare_service_args(
            _FILE,
            _service_account_from_system.__name__,
            arglist
            )
        )

################################################################################

def running_as_trusted_installer():
    ti_sid = "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464"
    return advapi.CheckTokenMembership(
        None,
        advapi.ConvertStringSidToSid(ti_sid)
        )

################################################################################

def _main():
    kernel.dbg_print("svc_util in main")
    with kernel.terminate_on_exception():
        kernel.dbg_print(f"starting {_FILE.name}: {sys.argv}")
        available_tasks = (
            # argv[1]/func          min len(argv)
            (_run_service,          2),
            (_call_func_as_svc_acc, 4),
            )
        for func, length in available_tasks:
            if len(sys.argv) >= length and sys.argv[1] == func.__name__:
                func(*sys.argv[2:])
                break
        else:
            raise RuntimeError(f"invalid args: {sys.argv}")

################################################################################

if __name__ == "__main__":
    _main()

################################################################################
