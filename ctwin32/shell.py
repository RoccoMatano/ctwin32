################################################################################
#
# Copyright 2021-2022 Rocco Matano
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

from .wtypes import *
from . import (
    INFINITE,
    SW_SHOW,
    SEE_MASK_NOCLOSEPROCESS,
    PROCESS_CREATE_PROCESS,
    PROC_THREAD_ATTRIBUTE_PARENT_PROCESS,
    CREATE_NEW_CONSOLE,
    EXTENDED_STARTUPINFO_PRESENT,
    raise_if,
    fun_fact,
    kernel,
    user,
    ref,
    ctypes,
    )

from .kernel import WaitForSingleObject, CloseHandle, LocalFree

################################################################################

class SHELLEXECUTEINFOW(ctypes.Structure):
    _fields_ = (
        ("cbSize", DWORD),
        ("fMask", DWORD),
        ("hwnd", HWND),
        ("lpVerb", PWSTR),
        ("lpFile", PWSTR),
        ("lpParameters", PWSTR),
        ("lpDirectory", PWSTR),
        ("nShow", INT),
        ("hInstApp", HINSTANCE),
        ("lpIDList", PVOID),
        ("lpClass", PWSTR),
        ("hkeyClass", HANDLE),
        ("dwHotKey", DWORD),
        ("hMonitor", HANDLE),
        ("hProcess", HANDLE),
        )
    def __init__(self, file, verb, param, direc, wait, show):
        self.cbSize = ctypes.sizeof(self)
        self.lpVerb = verb
        self.lpFile = file
        self.lpParameters = param
        self.lpDirectory = direc
        self.nShow = show
        self.fMask = SEE_MASK_NOCLOSEPROCESS if wait else 0

################################################################################

_ShellExecuteExW = fun_fact(
    ctypes.windll.shell32.ShellExecuteExW,
    (BOOL, ctypes.POINTER(SHELLEXECUTEINFOW))
    )

################################################################################

def ShellExecuteEx(
    file,
    verb=None,
    param=None,
    direc=None,
    wait=False,
    show=SW_SHOW
    ):
    sei = SHELLEXECUTEINFOW(file, verb, param, direc, wait, show)

    raise_if(not _ShellExecuteExW(ref(sei)))

    if sei.hProcess is not None:
        kernel.WaitForSingleObject(sei.hProcess, INFINITE);
        kernel.CloseHandle(sei.hProcess);

################################################################################

def elevate(*args, direc=None, wait=False, show=SW_SHOW):
    ShellExecuteEx(args[0], "runas", " ".join(args[1:]), direc, wait, show)

################################################################################

def relegate(*args, wait=False):
    tid, pid, = user.GetWindowThreadProcessId(user.GetShellWindow())
    with kernel.OpenProcess(PROCESS_CREATE_PROCESS, False, pid) as shell_proc:
        attr = ((PROC_THREAD_ATTRIBUTE_PARENT_PROCESS, shell_proc),)
        with kernel.ProcThreadAttributeList(attr) as ptal:
            si = kernel.STARTUPINFOEX(ptal.address())
            cflags = CREATE_NEW_CONSOLE | EXTENDED_STARTUPINFO_PRESENT
            with kernel.create_process(args, cflags, si) as pi:
                if wait:
                    kernel.WaitForSingleObject(pi.hProcess, INFINITE);

################################################################################

_CommandLineToArgv = fun_fact(
    ctypes.windll.shell32.CommandLineToArgvW,
    (PPWSTR, PWSTR, PINT),
    )

def CommandLineToArgv(cmdline):
    # CommandLineToArgv gets leading white space wrong
    cmdline = cmdline.lstrip(" \t")
    if not cmdline:
        return []

    argc = INT()
    pargs = _CommandLineToArgv(cmdline, ref(argc))
    raise_if(not pargs)
    try:
        return [pargs[i] for i in range(argc.value)]
    finally:
        LocalFree(pargs)

################################################################################
