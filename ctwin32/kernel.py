################################################################################
#
# Copyright 2021 Rocco Matano
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

import ctypes as _ct
import collections as _collections

from .wtypes import *
from . import (
    _raise_if,
    _fun_fact,
    ERROR_INSUFFICIENT_BUFFER,
    INVALID_FILE_ATTRIBUTES,
    INVALID_HANDLE_VALUE,
    multi_str_from_addr,
    cmdline_from_args,
    )

_k32 = _ct.windll.kernel32
_ref = _ct.byref

################################################################################

GetLastError = _ct.GetLastError

################################################################################

_LocalFree = _fun_fact(_k32.LocalFree, (HANDLE, HANDLE))

def LocalFree(hmem):
    _raise_if(_LocalFree(hmem))

################################################################################

_CloseHandle = _fun_fact(_k32.CloseHandle, (BOOL, HANDLE))

def CloseHandle(handle):
    _raise_if(not _CloseHandle(handle))

################################################################################

class KHANDLE(ScdToBeClosed, HANDLE, close_func=CloseHandle, invalid=0):
    pass

################################################################################

class FHANDLE(
    ScdToBeClosed,
    HANDLE,
    close_func=CloseHandle,
    invalid=INVALID_HANDLE_VALUE
    ):
    pass

################################################################################

class SECURITY_ATTRIBUTES(_ct.Structure):
    _fields_ = (
        ("lpSecurityDescriptor", PVOID),
        ("nLength", DWORD),
        ("bInheritHandle", BOOL),
    )
PSECURITY_ATTRIBUTES = _ct.POINTER(SECURITY_ATTRIBUTES)

################################################################################

_CreateFile = _fun_fact(
    _k32.CreateFileW, (
        HANDLE,
        PWSTR,
        DWORD,
        DWORD,
        PSECURITY_ATTRIBUTES,
        DWORD,
        DWORD,
        HANDLE
        )
    )

def CreateFile(file_name, access, share_mode, sec_attr, dispo, flags, template):
    hdl = FHANDLE(
        _CreateFile(
            file_name,
            access,
            share_mode,
            sec_attr,
            dispo,
            flags,
            template
            )
        )
    _raise_if(not hdl.is_valid())
    return hdl

################################################################################

class _DUMMY_OVRLPD_STRUCT(_ct.Structure):
    _fields_ = (
        ("Offset", DWORD),
        ("OffsetHigh", DWORD),
        )

class _DUMMY_OVRLPD_UNION(_ct.Structure):
    _anonymous_ = ("anon",)
    _fields_ = (
        ("anon", _DUMMY_OVRLPD_STRUCT),
        ("Pointer", PVOID),
        )

class OVERLAPPED(_ct.Structure):
    _anonymous_ = ("anon",)
    _fields_ = (
        ("Internal", ULONG_PTR),
        ("InternalHigh", ULONG_PTR),
        ("anon", _DUMMY_OVRLPD_UNION),
        ("hEvent", HANDLE)
        )

POVERLAPPED = _ct.POINTER(OVERLAPPED)

################################################################################

_DeviceIoControl = _fun_fact(
    _k32.DeviceIoControl, (
        BOOL,
        HANDLE,
        DWORD,
        PVOID,
        DWORD,
        PVOID,
        DWORD,
        PDWORD,
        POVERLAPPED
        )
    )

def DeviceIoControl(hdl, ioctl, in_bytes, out_len):
    bytes_returned = DWORD(0)

    if in_bytes is None:
        iptr, ilen = None, 0
    else:
        iptr, ilen = _ref(in_bytes), len(in_bytes)

    if out_len is None or out_len == 0:
        out, optr, olen = None, None, 0
    else:
        out = _ct.create_string_buffer(out_len)
        optr, olen = _ref(out), out_len

    _raise_if(
        not _DeviceIoControl(
            hdl,
            ioctl,
            iptr,
            ilen,
            optr,
            olen,
            _ref(bytes_returned),
            None
            )
        )
    return out.raw[:bytes_returned.value] if out else None

################################################################################

_GetCurrentProcess = _fun_fact(_k32.GetCurrentProcess, (HANDLE,))

def GetCurrentProcess():
    return _GetCurrentProcess()

################################################################################

_GetCurrentProcessId = _fun_fact(_k32.GetCurrentProcessId, (DWORD,))

def GetCurrentProcessId():
    return _GetCurrentProcessId()

################################################################################

_WaitForSingleObject = _fun_fact(
    _k32.WaitForSingleObject, (DWORD, HANDLE, DWORD)
    )

def WaitForSingleObject(handle, timeout):
    res = _WaitForSingleObject(handle, timeout)
    _raise_if(res == WAIT_FAILED)
    return res

################################################################################

_OpenProcess = _fun_fact(
    _k32.OpenProcess, (HANDLE, DWORD, BOOL, DWORD)
    )

def OpenProcess(desired_acc, inherit, pid):
    res = KHANDLE(_OpenProcess(desired_acc, inherit, pid))
    _raise_if(not res.is_valid())
    return res

################################################################################

_TerminateProcess = _fun_fact(
    _k32.TerminateProcess, (BOOL, HANDLE, UINT)
    )

def TerminateProcess(handle, exit_code):
    _raise_if(not _TerminateProcess(handle, exit_code))

################################################################################

_QueryDosDevice = _fun_fact(
    _k32.QueryDosDeviceW, (DWORD, PWSTR, PWSTR, DWORD)
    )

def QueryDosDevice(device_name):
    size = 512
    buf = _ct.create_unicode_buffer(size)
    while True:
        res = _QueryDosDevice(device_name, buf, size)
        if res:
            return buf.value[:res]
        _raise_if(GetLastError() != ERROR_INSUFFICIENT_BUFFER)
        size *= 2
        buf = _ct.create_unicode_buffer(size)

################################################################################

def GetSystemTime():
    st = SYSTEMTIME()
    _k32.GetSystemTime(_ref(st))
    return st

################################################################################

def GetSystemTimeAsFileTime():
    ft = FILETIME()
    _k32.GetSystemTimeAsFileTime(_ref(ft))
    return ft

################################################################################

def SetSystemTime(st):
    _raise_if(not _k32.SetSystemTime(_ref(st)))

################################################################################

def GetLocalTime():
    st = SYSTEMTIME()
    _k32.GetLocalTime(_ref(st))
    return st

################################################################################

def SetLocalTime(st):
    _raise_if(not _k32.SetLocalTime(_ref(st)))

################################################################################

def FileTimeToSystemTime(ft):
    st = SYSTEMTIME()
    _raise_if(not _k32.FileTimeToSystemTime(_ref(ft), _ref(st)))
    return st

################################################################################

def SystemTimeToFileTime(st):
    ft = FILETIME()
    _raise_if(not _k32.SystemTimeToFileTime(_ref(st), _ref(ft)))
    return ft

################################################################################

def FileTimeToLocalFileTime(ft):
    lft = FILETIME()
    _raise_if(not _k32.FileTimeToLocalFileTime(_ref(ft), _ref(lft)))
    return lft

################################################################################

def FileTimeToLocalSystemTime(ft):
    st = FileTimeToSystemTime(ft)
    _raise_if(
        not _k32.SystemTimeToTzSpecificLocalTime(0, _ref(st), _ref(st))
        )
    return st

################################################################################

def AdjustTime(SecondsToAdjust):
    ft = GetSystemTimeAsFileTime()
    ft += int(SecondsToAdjust * 1e7)
    st = FileTimeToSystemTime(ft)
    _raise_if(not _k32.SetSystemTime(_ref(st)))

################################################################################

def GetCurrentThreadId():
    return _k32.GetCurrentThreadId()

################################################################################

def GetFileAttributes(fname):
    res = _k32.GetFileAttributesW(fname)
    _raise_if(res == INVALID_FILE_ATTRIBUTES)
    return res

################################################################################

_SetFileAttributes = _fun_fact(
    _k32.SetFileAttributesW, (BOOL, PWSTR, DWORD)
    )

################################################################################

def SetFileAttributes(fname, attribs):
    suc = _SetFileAttributes(fname, attribs)
    _raise_if(not suc)

################################################################################

_GetACP = _fun_fact(_k32.GetACP, (DWORD,))

def GetACP():
    return _GetACP()

################################################################################

_OutputDebugStringW = _fun_fact(_k32.OutputDebugStringW, (None, PWSTR))

def OutputDebugString(dstr):
    _OutputDebugStringW(dstr)

################################################################################

_SetThreadExecutionState = _fun_fact(
    _k32.SetThreadExecutionState, (DWORD, DWORD)
    )

def SetThreadExecutionState(es_flags):
    return _SetThreadExecutionState(es_flags)

################################################################################

_GetPrivateProfileSectionNames = _fun_fact(
    _k32.GetPrivateProfileSectionNamesW,
    (DWORD, PWSTR, DWORD, PWSTR)
    )

def GetPrivateProfileSectionNames(filename):
    size = 512
    buf = _ct.create_unicode_buffer(size)
    res = _GetPrivateProfileSectionNames(buf, size, filename)
    while res == size - 2:
        size *= 2
        buf = _ct.create_unicode_buffer(size)
        res = _GetPrivateProfileSectionNames(buf, size, filename)
    return buf[:res].split('\0')[:-1]

################################################################################

_GetPrivateProfileSection = _fun_fact(
    _k32.GetPrivateProfileSectionW,
    (DWORD, PWSTR, PWSTR, DWORD, PWSTR)
    )

def GetPrivateProfileSection(secname, filename):
    size = 512
    buf = _ct.create_unicode_buffer(size)
    res = _GetPrivateProfileSection(secname, buf, size, filename)
    while res == size - 2:
        size *= 2
        buf = _ct.create_unicode_buffer(size)
        res = _GetPrivateProfileSection(secname, buf, size, filename)
    entries = buf[:res].split('\0')[:-1]
    d = _collections.OrderedDict()
    for e in entries:
        k, v = e.split('=', 1)
        d[k] = v
    return d

################################################################################

_WritePrivateProfileSection = _fun_fact(
    _k32.WritePrivateProfileSectionW,
    (DWORD, PWSTR, PWSTR, PWSTR)
    )

def WritePrivateProfileSection(secname, secdata, filename):
    if not isinstance(secdata, str):
        lines = []
        for k, v in secdata.items():
            lines.append(f"{k}={v}")
        if lines:
            lines.append("\0")
            secdata = "\0".join(lines)
        else:
            secdata = "\0\0"
    # PyUnicode_AsWideCharString was updated to raise ValueError for
    # embedded nulls if the 'size' output parameter is NULL.
    # That's why we need to detour 'secdata' through a unicode buffer.
    buf = _ct.create_unicode_buffer(secdata, len(secdata))
    _raise_if(not _WritePrivateProfileSection(secname, buf, filename))

################################################################################

_GetEnvironmentVariable = _fun_fact(
    _k32.GetEnvironmentVariableW,
    (DWORD, PWSTR, PWSTR, DWORD)
    )

def GetEnvironmentVariable(name):
    size = 512
    while True:
        var = _ct.create_unicode_buffer(size)
        req = _GetEnvironmentVariable(name, var, size)
        _raise_if(req == 0)
        if req <= size:
            break
        else:
            size = req
    return var.value

################################################################################

_SetEnvironmentVariable = _fun_fact(
    _k32.SetEnvironmentVariableW,
    (BOOL, PWSTR, PWSTR)
    )

def SetEnvironmentVariable(name, value):
    _raise_if(not _SetEnvironmentVariable(name, value))

################################################################################

# using void pointers instead of PWSTR so we can do pointer arithmatic.

_FreeEnvironmentStrings = _fun_fact(
    _k32.FreeEnvironmentStringsW,
    (BOOL, PVOID)
    )

_GetEnvironmentStrings = _fun_fact(_k32.GetEnvironmentStringsW, (PVOID,))

def GetEnvironmentStrings():
    ptr = _GetEnvironmentStrings()
    _raise_if(not ptr)
    try:
        return multi_str_from_addr(ptr)
    finally:
        _raise_if(not _FreeEnvironmentStrings(ptr))

def env_str_to_dict(estr):
    return dict(s.rsplit("=", 1) for s in estr.strip("\0").split("\0"))

def get_env_as_dict():
    return env_str_to_dict(GetEnvironmentStrings())

################################################################################

_SetEnvironmentStrings = _fun_fact(
    _k32.SetEnvironmentStringsW,
    (BOOL, PWSTR)
    )

def SetEnvironmentStrings(strings):
    _raise_if(not _SetEnvironmentStrings(strings))

################################################################################

_ExpandEnvironmentStrings = _fun_fact(
    _k32.ExpandEnvironmentStringsW,
    (DWORD, PWSTR, PWSTR, DWORD)
    )

def ExpandEnvironmentStrings(template):
    size = len(template)
    while True:
        var = _ct.create_unicode_buffer(size)
        req = _ExpandEnvironmentStrings(template, var, size)
        _raise_if(req == 0)
        if req <= size:
            break
        else:
            size = req
    return var.value

################################################################################

class PROCESS_INFORMATION(_ct.Structure):
    _fields_ = (
        ("hProcess", KHANDLE),
        ("hThread", KHANDLE),
        ("dwProcessId", DWORD),
        ("dwThreadId", DWORD),
        )

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.hThread.close()
        self.hProcess.close()

PPROCESS_INFORMATION = _ct.POINTER(PROCESS_INFORMATION)

################################################################################

class STARTUPINFO(_ct.Structure):
    _fields_ = (
        ("cb", DWORD),
        ("lpReserved", PWSTR),
        ("lpDesktop", PWSTR),
        ("lpTitle", PWSTR),
        ("dwX", DWORD),
        ("dwY", DWORD),
        ("dwXSize", DWORD),
        ("dwYSize", DWORD),
        ("dwXCountChars", DWORD),
        ("dwYCountChars", DWORD),
        ("dwFillAttribute", DWORD),
        ("dwFlags", DWORD),
        ("wShowWindow", WORD),
        ("cbReserved2", WORD),
        ("lpReserved2", PBYTE),
        ("hStdInput", HANDLE),
        ("hStdOutput", HANDLE),
        ("hStdError", HANDLE),
        )
    def __init__(self):
        self.cb = _ct.sizeof(STARTUPINFO)

PSTARTUPINFO = _ct.POINTER(STARTUPINFO)

class STARTUPINFOEX(_ct.Structure):
    _fields_ = (
        ("StartupInfo", STARTUPINFO),
        ("lpAttributeList", PVOID),
        )
    def __init__(self, attr_lst=None):
        self.StartupInfo.cb = _ct.sizeof(STARTUPINFOEX)
        self.lpAttributeList = attr_lst

################################################################################

_InitializeProcThreadAttributeList = _fun_fact(
    _k32.InitializeProcThreadAttributeList,
    (BOOL, PVOID, DWORD, DWORD, PSIZE_T)
    )

def InitializeProcThreadAttributeList(alst, acnt, flags, size=0):
    size = SIZE_T(size)
    ok = _InitializeProcThreadAttributeList(alst, acnt, flags, _ref(size))
    _raise_if(not ok and alst)
    return size.value

################################################################################

_UpdateProcThreadAttribute = _fun_fact(
    _k32.UpdateProcThreadAttribute,
    (BOOL, PVOID, DWORD, UINT_PTR, PVOID, SIZE_T, PVOID, PSIZE_T)
    )

def UpdateProcThreadAttribute(alst, flags, id, attr):
    size = SIZE_T(_ct.sizeof(attr))
    _raise_if(
        not _UpdateProcThreadAttribute(
            alst,
            flags,
            id,
            _ref(attr),
            SIZE_T(_ct.sizeof(attr)),
            None,
            None
            )
        )

################################################################################

_DeleteProcThreadAttributeList = _fun_fact(
    _k32.DeleteProcThreadAttributeList, (None, PVOID)
    )

def DeleteProcThreadAttributeList(alst):
    _DeleteProcThreadAttributeList(alst)

################################################################################

class ProcThreadAttributeList:
    def __init__(self, attr_pairs):
        self.buf = None
        size = InitializeProcThreadAttributeList(None, len(attr_pairs), 0)
        buf = _ct.create_string_buffer(size)
        InitializeProcThreadAttributeList(buf, 1, 0, size)
        try:
            for id, value in attr_pairs:
                UpdateProcThreadAttribute(buf, 0, id, value)
        except OSError:
            DeleteProcThreadAttributeList(buf)
            raise
        self.buf = buf

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        if self.buf:
            DeleteProcThreadAttributeList(self.buf)
            self.buf = None

    def address(self):
        return _ct.addressof(self.buf) if self.buf else None

################################################################################

_CreateProcess = _fun_fact(
    _k32.CreateProcessW, (
        BOOL,
        PWSTR,
        PWSTR,
        PSECURITY_ATTRIBUTES,
        PSECURITY_ATTRIBUTES,
        BOOL,
        DWORD,
        PVOID,
        PWSTR,
        PSTARTUPINFO,
        PPROCESS_INFORMATION
        )
    )

def CreateProcess(
    app_name,
    cmd_line,
    proc_attr,
    thread_attr,
    inherit,
    cflags,
    env,
    curdir,
    startup_info,
    ):
    proc_info = PROCESS_INFORMATION()
    if isinstance(startup_info, STARTUPINFOEX):
        psi = _ref(startup_info.StartupInfo)
    else:
        psi = _ref(startup_info)
    _raise_if(
        not _CreateProcess(
            app_name,
            cmd_line,
            _ref(proc_attr) if proc_attr is not None else None,
            _ref(thread_attr) if thread_attr is not None else None,
            inherit,
            cflags,
            env,
            curdir,
            psi,
            _ref(proc_info)
            )
        )
    return proc_info

################################################################################

def create_process(
    arglist,
    cflags=0,
    startup_info=None,
    inherit=False,
    env=None,
    curdir=None,
    proc_attr=None,
    thread_attr=None,
    ):
    if startup_info is None:
        startup_info = STARTUPINFO()
    return CreateProcess(
        None,
        cmdline_from_args(arglist),
        proc_attr,
        thread_attr,
        inherit,
        cflags,
        env,
        curdir,
        startup_info
        )

################################################################################
