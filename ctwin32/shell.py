################################################################################
#
# Copyright 2021-2024 Rocco Matano
# SPDX-License-Identifier: MIT
#
################################################################################

import ctypes
from .wtypes import (
    string_buffer,
    BOOL,
    DWORD,
    HANDLE,
    HINSTANCE,
    HRESULT,
    HWND,
    INT,
    PINT,
    POINTER,
    PPWSTR,
    PVOID,
    PWSTR,
    )
from . import (
    INFINITE,
    SW_SHOW,
    MAX_PATH,
    SEE_MASK_NOCLOSEPROCESS,
    PROCESS_CREATE_PROCESS,
    PROC_THREAD_ATTRIBUTE_PARENT_PROCESS,
    CREATE_NEW_CONSOLE,
    EXTENDED_STARTUPINFO_PRESENT,
    cmdline_from_args,
    raise_on_zero,
    raise_on_hr,
    fun_fact,
    kernel,
    user,
    ref,
    )

_sh = ctypes.WinDLL("shell32.dll", use_last_error=True)

################################################################################

CSIDL_DESKTOP                 = 0x0000
CSIDL_INTERNET                = 0x0001
CSIDL_PROGRAMS                = 0x0002
CSIDL_CONTROLS                = 0x0003
CSIDL_PRINTERS                = 0x0004
CSIDL_PERSONAL                = 0x0005
CSIDL_FAVORITES               = 0x0006
CSIDL_STARTUP                 = 0x0007
CSIDL_RECENT                  = 0x0008
CSIDL_SENDTO                  = 0x0009
CSIDL_BITBUCKET               = 0x000a
CSIDL_STARTMENU               = 0x000b
CSIDL_MYDOCUMENTS             = CSIDL_PERSONAL
CSIDL_MYMUSIC                 = 0x000d
CSIDL_MYVIDEO                 = 0x000e
CSIDL_DESKTOPDIRECTORY        = 0x0010
CSIDL_DRIVES                  = 0x0011
CSIDL_NETWORK                 = 0x0012
CSIDL_NETHOOD                 = 0x0013
CSIDL_FONTS                   = 0x0014
CSIDL_TEMPLATES               = 0x0015
CSIDL_COMMON_STARTMENU        = 0x0016
CSIDL_COMMON_PROGRAMS         = 0X0017
CSIDL_COMMON_STARTUP          = 0x0018
CSIDL_COMMON_DESKTOPDIRECTORY = 0x0019
CSIDL_APPDATA                 = 0x001a
CSIDL_PRINTHOOD               = 0x001b
CSIDL_LOCAL_APPDATA           = 0x001c
CSIDL_ALTSTARTUP              = 0x001d
CSIDL_COMMON_ALTSTARTUP       = 0x001e
CSIDL_COMMON_FAVORITES        = 0x001f
CSIDL_INTERNET_CACHE          = 0x0020
CSIDL_COOKIES                 = 0x0021
CSIDL_HISTORY                 = 0x0022
CSIDL_COMMON_APPDATA          = 0x0023
CSIDL_WINDOWS                 = 0x0024
CSIDL_SYSTEM                  = 0x0025
CSIDL_PROGRAM_FILES           = 0x0026
CSIDL_MYPICTURES              = 0x0027
CSIDL_PROFILE                 = 0x0028
CSIDL_SYSTEMX86               = 0x0029
CSIDL_PROGRAM_FILESX86        = 0x002a
CSIDL_PROGRAM_FILES_COMMON    = 0x002b
CSIDL_PROGRAM_FILES_COMMONX86 = 0x002c
CSIDL_COMMON_TEMPLATES        = 0x002d
CSIDL_COMMON_DOCUMENTS        = 0x002e
CSIDL_COMMON_ADMINTOOLS       = 0x002f
CSIDL_ADMINTOOLS              = 0x0030
CSIDL_CONNECTIONS             = 0x0031
CSIDL_COMMON_MUSIC            = 0x0035
CSIDL_COMMON_PICTURES         = 0x0036
CSIDL_COMMON_VIDEO            = 0x0037
CSIDL_RESOURCES               = 0x0038
CSIDL_RESOURCES_LOCALIZED     = 0x0039
CSIDL_COMMON_OEM_LINKS        = 0x003a
CSIDL_CDBURN_AREA             = 0x003b
CSIDL_COMPUTERSNEARME         = 0x003d
CSIDL_FLAG_PER_USER_INIT      = 0x0800
CSIDL_FLAG_NO_ALIAS           = 0x1000
CSIDL_FLAG_DONT_UNEXPAND      = 0x2000
CSIDL_FLAG_DONT_VERIFY        = 0x4000
CSIDL_FLAG_CREATE             = 0x8000
CSIDL_FLAG_MASK               = 0xFF00

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

PSHELLEXECUTEINFOW = POINTER(SHELLEXECUTEINFOW)

################################################################################

_ShellExecuteExW = fun_fact(_sh.ShellExecuteExW, (BOOL, PSHELLEXECUTEINFOW))

################################################################################

def ShellExecuteEx(
        file,
        verb=None,
        param=None,
        direc=None,
        wait=False,
        show=SW_SHOW
        ):
    sei = SHELLEXECUTEINFOW(str(file), verb, param, direc, wait, show)

    raise_on_zero(_ShellExecuteExW(ref(sei)))

    rc = None
    if sei.hProcess is not None:
        kernel.WaitForSingleObject(sei.hProcess, INFINITE)
        rc = kernel.GetExitCodeProcess(sei.hProcess)
        kernel.CloseHandle(sei.hProcess)
    return rc

################################################################################

def elevate(*args, direc=None, wait=False, show=SW_SHOW):
    file, param = args[0], cmdline_from_args(args[1:])
    ShellExecuteEx(file, "runas", param, direc, wait, show)

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
                    kernel.WaitForSingleObject(pi.hProcess, INFINITE)

################################################################################

_CommandLineToArgv = fun_fact(_sh.CommandLineToArgvW, (PPWSTR, PWSTR, PINT))

def CommandLineToArgv(cmdline):
    # CommandLineToArgv gets leading white space wrong
    cmdline = cmdline.lstrip(" \t")
    if not cmdline:
        return []

    argc = INT()
    pargs = _CommandLineToArgv(cmdline, ref(argc))
    raise_on_zero(pargs)
    try:
        return [pargs[i] for i in range(argc.value)]
    finally:
        kernel.LocalFree(pargs)

################################################################################

_SHGetFolderPath = fun_fact(
    _sh.SHGetFolderPathW, (HRESULT, HWND, INT, HANDLE, DWORD, PWSTR)
    )

def SHGetFolderPath(csidl, flags=0, token=None):
    buf = string_buffer(MAX_PATH)
    raise_on_hr(_SHGetFolderPath(None, csidl, token, flags, buf))
    return buf.value

################################################################################
