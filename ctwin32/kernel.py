################################################################################
#
# Copyright 2021-2025 Rocco Matano
# SPDX-License-Identifier: MIT
#
################################################################################

import sys
import traceback
import datetime as _dt
import collections as _collections
from enum import IntEnum as _int_enum

import ctypes
from .wtypes import (
    byte_buffer,
    string_buffer,
    BOOL,
    BYTE,
    CallbackContext,
    CallbackContextPtr,
    CHAR,
    DWORD,
    FILETIME,
    HANDLE,
    INT,
    LARGE_INTEGER,
    PBOOL,
    PBYTE,
    PDWORD,
    PLARGE_INTEGER,
    POINTER,
    PPWSTR,
    PSIZE_T,
    PULONG_PTR,
    PUSHORT,
    PVOID,
    PWIN32_FIND_DATA,
    PWSTR,
    ScdToBeClosed,
    SHORT,
    SIZE_T,
    SYSTEMTIME,
    UINT,
    UINT_PTR,
    ULONG,
    ULONGLONG,
    ULONG_PTR,
    USHORT,
    WCHAR,
    WCHAR_SIZE,
    WIN32_FIND_DATA,
    WinError,
    WORD,
    )
from . import (
    ApiDll,
    cmdline_from_args,
    multi_str_from_addr,
    multi_str_from_ubuf,
    ns_from_struct,
    ntdll,
    raise_if,
    raise_on_err,
    raise_on_zero,
    ref,
    ENABLE_VIRTUAL_TERMINAL_PROCESSING,
    ERROR_ACCESS_DENIED,
    ERROR_FILE_NOT_FOUND,
    ERROR_HANDLE_EOF,
    ERROR_INSUFFICIENT_BUFFER,
    ERROR_MORE_DATA,
    ERROR_NO_MORE_FILES,
    ERROR_PIPE_CONNECTED,
    ERROR_RESOURCE_ENUM_USER_STOP,
    ERROR_RESOURCE_NAME_NOT_FOUND,
    ERROR_SUCCESS,
    GENERIC_READ,
    GENERIC_WRITE,
    FILE_ATTRIBUTE_DIRECTORY,
    FILE_ATTRIBUTE_NORMAL,
    FILE_SHARE_READ,
    FILE_SHARE_WRITE,
    FILE_TYPE_CHAR,
    FILE_TYPE_UNKNOWN,
    INVALID_FILE_ATTRIBUTES,
    INVALID_HANDLE_VALUE,
    IMAGE_FILE_MACHINE_UNKNOWN,
    IMAGE_FILE_MACHINE_AMD64,
    IMAGE_FILE_MACHINE_I386,
    MB_OK,
    MB_ICONERROR,
    OPEN_EXISTING,
    PIPE_ACCESS_DUPLEX,
    PIPE_READMODE_MESSAGE,
    PIPE_REJECT_REMOTE_CLIENTS,
    PIPE_TYPE_MESSAGE,
    PIPE_UNLIMITED_INSTANCES,
    RT_MESSAGETABLE,
    STD_OUTPUT_HANDLE,
    THREAD_PRIORITY_ERROR_RETURN,
    WAIT_FAILED,
    )

_k32 = ApiDll("kernel32.dll")

################################################################################

ExitProcess = _k32.fun_fact("ExitProcess", (None, UINT))

################################################################################

# Here we use the functions from ctypes instead of using GetLastError and
# SetLastError directly. We do so to work with the copies that ctypes manages.
# These are protected from being manipulated by the system calls of CPython
# itself. This requires that all DLLs involved are created with
# 'use_last_error=True'.
GetLastError = ctypes.get_last_error
SetLastError = ctypes.set_last_error

################################################################################

_LocalFree = _k32.fun_fact("LocalFree", (HANDLE, HANDLE))

def LocalFree(hmem):
    raise_if(_LocalFree(hmem))

################################################################################

_GlobalFree = _k32.fun_fact("GlobalFree", (HANDLE, HANDLE))

def GlobalFree(hmem):
    raise_if(_GlobalFree(hmem))

################################################################################

_GlobalAlloc = _k32.fun_fact("GlobalAlloc", (HANDLE, UINT, SIZE_T))

def GlobalAlloc(flags, size):
    res = _GlobalAlloc(flags, size)
    raise_on_zero(res)
    return res

################################################################################

_GlobalLock = _k32.fun_fact("GlobalLock", (PVOID, HANDLE))

def GlobalLock(hmem):
    res = _GlobalLock(hmem)
    raise_on_zero(res)
    return res

################################################################################

_GlobalUnlock = _k32.fun_fact("GlobalUnlock", (BOOL, HANDLE))

def GlobalUnlock(hmem):
    res = _GlobalUnlock(hmem)
    if not res and (err := GetLastError()) != ERROR_SUCCESS:
        raise WinError(err)

################################################################################

_CloseHandle = _k32.fun_fact("CloseHandle", (BOOL, HANDLE))

def CloseHandle(handle):
    raise_on_zero(_CloseHandle(handle))

################################################################################

class KHANDLE(ScdToBeClosed, HANDLE, close_func=CloseHandle, invalid=0):
    pass

PKHANDLE = POINTER(KHANDLE)

################################################################################

class FHANDLE(
        ScdToBeClosed,
        HANDLE,
        close_func=CloseHandle,
        invalid=INVALID_HANDLE_VALUE
        ):
    pass

PFHANDLE = POINTER(FHANDLE)

################################################################################

class SECURITY_ATTRIBUTES(ctypes.Structure):
    _fields_ = (
        ("nLength", DWORD),
        ("lpSecurityDescriptor", PVOID),
        ("bInheritHandle", BOOL),
        )

    def __init__(self):
        self.nLength = ctypes.sizeof(self)

PSECURITY_ATTRIBUTES = POINTER(SECURITY_ATTRIBUTES)

################################################################################

_CreateFile = _k32.fun_fact(
    "CreateFileW", (
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
    hdl.raise_on_invalid()
    return hdl

def create_file(
        file_name,
        access=GENERIC_READ | GENERIC_WRITE,
        share_mode=FILE_SHARE_READ | FILE_SHARE_WRITE,
        flags=FILE_ATTRIBUTE_NORMAL,
        dispo=OPEN_EXISTING,
        sec_attr=None,
        template=None
        ):
    return CreateFile(
        file_name,
        access,
        share_mode,
        sec_attr,
        dispo,
        flags,
        template
        )

################################################################################

_ReadFile = _k32.fun_fact(
    "ReadFile",
    (BOOL, HANDLE, PVOID, DWORD, PDWORD, PVOID)
    )

def ReadFile(hdl, size_or_buf):
    buf_created = isinstance(size_or_buf, int)
    if buf_created:
        buf = byte_buffer(size_or_buf)
        size = size_or_buf
    else:
        buf = size_or_buf
        size = ctypes.sizeof(buf)

    num_read = DWORD()
    raise_on_zero(_ReadFile(hdl, buf, size, ref(num_read), None))
    if buf_created:
        return buf.raw[:num_read.value], num_read.value
    else:
        return buf, num_read.value

################################################################################

def read_file_text(hdl, size):
    buf, size = ReadFile(hdl, string_buffer(size))
    return buf[: size // WCHAR_SIZE]

################################################################################

_WriteFile = _k32.fun_fact(
    "WriteFile",
    (BOOL, HANDLE, PVOID, DWORD, PDWORD, PVOID)
    )

def WriteFile(hdl, data):
    try:
        ldata = ctypes.sizeof(data)
        rdata = ref(data)
    except TypeError:
        rdata = byte_buffer(data)
        ldata = len(data)

    written = DWORD()
    raise_on_zero(_WriteFile(hdl, rdata, ldata, ref(written), None))
    return written.value

################################################################################

def write_file_text(hdl, txt):
    return WriteFile(hdl, string_buffer(txt, len(txt)))

################################################################################

_FlushFileBuffers = _k32.fun_fact("FlushFileBuffers", (BOOL, HANDLE))

def FlushFileBuffers(hdl):
    raise_on_zero(_FlushFileBuffers(hdl))

################################################################################

class _DUMMY_OVRLPD_STRUCT(ctypes.Structure):
    _fields_ = (
        ("Offset", DWORD),
        ("OffsetHigh", DWORD),
        )

class _DUMMY_OVRLPD_UNION(ctypes.Union):
    _anonymous_ = ("anon",)
    _fields_ = (
        ("anon", _DUMMY_OVRLPD_STRUCT),
        ("Pointer", PVOID),
        )

class OVERLAPPED(ctypes.Structure):
    _anonymous_ = ("anon",)
    _fields_ = (
        ("Internal", ULONG_PTR),
        ("InternalHigh", ULONG_PTR),
        ("anon", _DUMMY_OVRLPD_UNION),
        ("hEvent", HANDLE)
        )

POVERLAPPED = POINTER(OVERLAPPED)
PPOVERLAPPED = POINTER(POVERLAPPED)

################################################################################

_DeviceIoControl = _k32.fun_fact(
    "DeviceIoControl", (
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

def DeviceIoControl(hdl, ioctl, in_ctobj, out_len):
    bytes_returned = DWORD(0)

    if in_ctobj is None or in_ctobj == 0:
        iptr, ilen = None, 0
    else:
        iptr, ilen = ref(in_ctobj), ctypes.sizeof(in_ctobj)

    if out_len is None or out_len == 0:
        out, optr, olen = None, None, 0
    else:
        out = byte_buffer(out_len)
        optr, olen = ref(out), out_len

    raise_on_zero(
        _DeviceIoControl(
            hdl,
            ioctl,
            iptr,
            ilen,
            optr,
            olen,
            ref(bytes_returned),
            None
            )
        )
    if num_ret := bytes_returned.value:
        return out if num_ret == olen else (CHAR * num_ret).from_buffer(out)
    return None

################################################################################

_CreateIoCompletionPort = _k32.fun_fact(
    "CreateIoCompletionPort",
    (KHANDLE, HANDLE, HANDLE, ULONG_PTR, DWORD)
    )

def CreateIoCompletionPort(file, existing, key, num_threads):
    ioport = _CreateIoCompletionPort(file, existing, key, num_threads)
    ioport.raise_on_invalid()
    return ioport

def create_io_completion_port(file, key, num_threads=0, existing=None):
    return CreateIoCompletionPort(file, existing, key, num_threads)

################################################################################

_GetQueuedCompletionStatus = _k32.fun_fact(
    "GetQueuedCompletionStatus",
    (BOOL, HANDLE, PDWORD, PULONG_PTR, PPOVERLAPPED, DWORD)
    )

def GetQueuedCompletionStatus(port, timeout):
    num_bytes = DWORD()
    key = ULONG_PTR()
    ovrl = POVERLAPPED()
    raise_on_zero(
        _GetQueuedCompletionStatus(
            port,
            ref(num_bytes),
            ref(key),
            ref(ovrl),
            timeout)
            )
    return num_bytes.value, key.value, ovrl

################################################################################

_CreateNamedPipe = _k32.fun_fact(
    "CreateNamedPipeW", (
        HANDLE,
        PWSTR,
        DWORD,
        DWORD,
        DWORD,
        DWORD,
        DWORD,
        DWORD,
        PSECURITY_ATTRIBUTES,
        )
    )

def CreateNamedPipe(
        name,
        open_mode,
        pipe_mode,
        num_inst,
        out_buf_size,
        in_buf_bsize,
        default_timeout,
        p_sec_attr
        ):
    hdl = FHANDLE(
        _CreateNamedPipe(
            name,
            open_mode,
            pipe_mode,
            num_inst,
            out_buf_size,
            in_buf_bsize,
            default_timeout,
            p_sec_attr
            )
        )
    hdl.raise_on_invalid()
    return hdl

DEFAULT_PIPE_MODE = (
    PIPE_TYPE_MESSAGE |
    PIPE_READMODE_MESSAGE |
    PIPE_REJECT_REMOTE_CLIENTS
    )

def create_named_pipe(
        name,
        open_mode=PIPE_ACCESS_DUPLEX,
        pipe_mode=DEFAULT_PIPE_MODE,
        num_inst=PIPE_UNLIMITED_INSTANCES,
        out_buf_size=0x400,
        in_buf_bsize=0x400,
        default_timeout=0,
        p_sec_attr=None
        ):
    return CreateNamedPipe(
        name,
        open_mode,
        pipe_mode,
        num_inst,
        out_buf_size,
        in_buf_bsize,
        default_timeout,
        p_sec_attr
        )

################################################################################

_ConnectNamedPipe = _k32.fun_fact("ConnectNamedPipe", (BOOL, HANDLE, PVOID))

def ConnectNamedPipe(hdl):
    if not _ConnectNamedPipe(hdl, None):
        if (err := GetLastError()) == ERROR_PIPE_CONNECTED:
            return
        raise WinError(err)

################################################################################

_DisconnectNamedPipe = _k32.fun_fact("DisconnectNamedPipe", (BOOL, HANDLE))

def DisconnectNamedPipe(hdl):
    raise_on_zero(_DisconnectNamedPipe(hdl))

################################################################################

GetCurrentProcess = _k32.fun_fact("GetCurrentProcess", (HANDLE,))

################################################################################

GetCurrentProcessId = _k32.fun_fact("GetCurrentProcessId", (DWORD,))

################################################################################

GetCurrentThread = _k32.fun_fact("GetCurrentThread", (HANDLE,))

################################################################################

_ProcessIdToSessionId = _k32.fun_fact(
    "ProcessIdToSessionId",
    (BOOL, DWORD, PDWORD)
    )

def ProcessIdToSessionId(pid):
    session = DWORD()
    raise_on_zero(_ProcessIdToSessionId(pid, ref(session)))
    return session.value

################################################################################

_GetModuleHandle = _k32.fun_fact("GetModuleHandleW", (HANDLE, PWSTR))

def GetModuleHandle(mod_name):
    res = _GetModuleHandle(mod_name)
    raise_on_zero(res)
    return res

################################################################################

_GetModuleFileName = _k32.fun_fact(
    "GetModuleFileNameW",
    (DWORD, HANDLE, PWSTR, DWORD)
    )

def GetModuleFileName(hmod):
    size = 128
    res = size
    while res >= size:
        size *= 2
        buf = string_buffer(size)
        res = _GetModuleFileName(hmod, buf, size)
    raise_on_zero(res)
    return buf.value

################################################################################

_WaitForSingleObject = _k32.fun_fact(
    "WaitForSingleObject",
    (DWORD, HANDLE, DWORD)
    )

def WaitForSingleObject(handle, timeout):
    res = _WaitForSingleObject(handle, timeout)
    raise_if(res == WAIT_FAILED)
    return res

################################################################################

_OpenProcess = _k32.fun_fact("OpenProcess", (HANDLE, DWORD, BOOL, DWORD))

def OpenProcess(desired_acc, inherit, pid):
    res = KHANDLE(_OpenProcess(desired_acc, inherit, pid))
    res.raise_on_invalid()
    return res

################################################################################

_TerminateProcess = _k32.fun_fact("TerminateProcess", (BOOL, HANDLE, UINT))

def TerminateProcess(handle, exit_code):
    raise_on_zero(_TerminateProcess(handle, exit_code))

################################################################################

_GetExitCodeProcess = _k32.fun_fact(
    "GetExitCodeProcess",
    (BOOL, HANDLE, PDWORD)
    )

def GetExitCodeProcess(handle):
    exit_code = DWORD()
    raise_on_zero(_GetExitCodeProcess(handle, ref(exit_code)))
    return exit_code.value

################################################################################

_GetCommandLine = _k32.fun_fact("GetCommandLineW", (PWSTR,))
def GetCommandLine():
    return ctypes.wstring_at(_GetCommandLine())

################################################################################

_QueryDosDevice = _k32.fun_fact("QueryDosDeviceW", (DWORD, PWSTR, PWSTR, DWORD))

def QueryDosDevice(device_name):
    size = 512
    buf = string_buffer(size)
    while True:
        if res := _QueryDosDevice(device_name, buf, size):
            if device_name is None:
                return multi_str_from_ubuf(buf, res)
            return buf.value[:res]
        raise_if(GetLastError() != ERROR_INSUFFICIENT_BUFFER)
        size *= 2
        buf = string_buffer(size)

################################################################################

def GetSystemTime():
    st = SYSTEMTIME()
    _k32.GetSystemTime(ref(st))
    return st

################################################################################

def GetSystemTimeAsFileTime():
    ft = FILETIME()
    _k32.GetSystemTimeAsFileTime(ref(ft))
    return ft

################################################################################

def SetSystemTime(st):
    raise_on_zero(_k32.SetSystemTime(ref(st)))

################################################################################

def GetLocalTime():
    st = SYSTEMTIME()
    _k32.GetLocalTime(ref(st))
    return st

################################################################################

def SetLocalTime(st):
    raise_on_zero(_k32.SetLocalTime(ref(st)))

################################################################################

def FileTimeToSystemTime(ft):
    st = SYSTEMTIME()
    raise_on_zero(_k32.FileTimeToSystemTime(ref(ft), ref(st)))
    return st

################################################################################

def SystemTimeToFileTime(st):
    ft = FILETIME()
    raise_on_zero(_k32.SystemTimeToFileTime(ref(st), ref(ft)))
    return ft

################################################################################

def FileTimeToLocalFileTime(ft):
    lft = FILETIME()
    raise_on_zero(_k32.FileTimeToLocalFileTime(ref(ft), ref(lft)))
    return lft

################################################################################

def FileTimeToLocalSystemTime(ft):
    st = FileTimeToSystemTime(ft)
    raise_on_zero(_k32.SystemTimeToTzSpecificLocalTime(0, ref(st), ref(st)))
    return st

################################################################################

def adjust_time(seconds_to_adjust):
    ft = GetSystemTimeAsFileTime()
    ft += int(seconds_to_adjust * 1e7)
    st = FileTimeToSystemTime(ft)
    raise_on_zero(_k32.SetSystemTime(ref(st)))

################################################################################

def get_local_tzinfo():
    utc = GetSystemTimeAsFileTime()
    local = FileTimeToLocalFileTime(utc)
    return _dt.timezone(_dt.timedelta(0, int(local - utc) // 10_000_000))

################################################################################

def GetCurrentThreadId():
    return _k32.GetCurrentThreadId()

################################################################################

def GetFileAttributes(fname):
    res = _k32.GetFileAttributesW(fname)
    raise_if(res == INVALID_FILE_ATTRIBUTES)
    return res

################################################################################

_SetFileAttributes = _k32.fun_fact("SetFileAttributesW", (BOOL, PWSTR, DWORD))

################################################################################

def SetFileAttributes(fname, attribs):
    raise_on_zero(_SetFileAttributes(fname, attribs))

################################################################################

_GetACP = _k32.fun_fact("GetACP", (DWORD,))

def GetACP():
    return _GetACP()

def get_ansi_encoding():
    return f"cp{GetACP()}"

################################################################################

_OutputDebugStringW = _k32.fun_fact("OutputDebugStringW", (None, PWSTR))

def OutputDebugString(dstr):
    _OutputDebugStringW(dstr)

################################################################################

def dbg_print(*args, end="\n"):
    _OutputDebugStringW(f"{' '.join(map(str, args))}{end}")

################################################################################

_SetThreadExecutionState = _k32.fun_fact(
    "SetThreadExecutionState",
    (DWORD, DWORD)
    )

def SetThreadExecutionState(es_flags):
    return _SetThreadExecutionState(es_flags)

################################################################################

_GetPrivateProfileSectionNames = _k32.fun_fact(
    "GetPrivateProfileSectionNamesW",
    (DWORD, PWSTR, DWORD, PWSTR)
    )

def GetPrivateProfileSectionNames(filename):
    size = 512
    buf = string_buffer(size)
    res = _GetPrivateProfileSectionNames(buf, size, filename)
    while res == size - 2:
        size *= 2
        buf = string_buffer(size)
        res = _GetPrivateProfileSectionNames(buf, size, filename)
    return multi_str_from_ubuf(buf, res)

################################################################################

_GetPrivateProfileSection = _k32.fun_fact(
    "GetPrivateProfileSectionW",
    (DWORD, PWSTR, PWSTR, DWORD, PWSTR)
    )

def GetPrivateProfileSection(secname, filename):
    size = 512
    buf = string_buffer(size)
    res = _GetPrivateProfileSection(secname, buf, size, filename)
    while res == size - 2:
        size *= 2
        buf = string_buffer(size)
        res = _GetPrivateProfileSection(secname, buf, size, filename)
    entries = multi_str_from_ubuf(buf, res)
    d = _collections.OrderedDict()
    for e in entries:
        k, v = e.split("=", 1)
        d[k] = v
    return d

################################################################################

_WritePrivateProfileSection = _k32.fun_fact(
    "WritePrivateProfileSectionW",
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
    raise_on_zero(_WritePrivateProfileSection(secname, secdata, filename))

################################################################################

_GetEnvironmentVariable = _k32.fun_fact(
    "GetEnvironmentVariableW",
    (DWORD, PWSTR, PWSTR, DWORD)
    )

def GetEnvironmentVariable(name):
    size = 512
    while True:
        var = string_buffer(size)
        req = _GetEnvironmentVariable(name, var, size)
        raise_on_zero(req)
        if req <= size:
            break
        size = req
    return var.value

################################################################################

_SetEnvironmentVariable = _k32.fun_fact(
    "SetEnvironmentVariableW",
    (BOOL, PWSTR, PWSTR)
    )

def SetEnvironmentVariable(name, value):
    raise_on_zero(_SetEnvironmentVariable(name, value))

################################################################################

# using void pointers instead of PWSTR so we can do pointer arithmatic.

_FreeEnvironmentStrings = _k32.fun_fact(
    "FreeEnvironmentStringsW",
    (BOOL, PVOID)
    )

_GetEnvironmentStrings = _k32.fun_fact("GetEnvironmentStringsW", (PVOID,))

def GetEnvironmentStrings():
    ptr = _GetEnvironmentStrings()
    raise_on_zero(ptr)
    try:
        return multi_str_from_addr(ptr)
    finally:
        raise_on_zero(_FreeEnvironmentStrings(ptr))

def env_str_to_dict(estr):
    return dict(s.split("=", 1) for s in estr if s[0] != "=")

def get_env_as_dict():
    return env_str_to_dict(GetEnvironmentStrings())

################################################################################

_SetEnvironmentStrings = _k32.fun_fact(
    "SetEnvironmentStringsW",
    (BOOL, PWSTR)
    )

def SetEnvironmentStrings(strings):
    raise_on_zero(_SetEnvironmentStrings(strings))

################################################################################

_ExpandEnvironmentStrings = _k32.fun_fact(
    "ExpandEnvironmentStringsW",
    (DWORD, PWSTR, PWSTR, DWORD)
    )

def ExpandEnvironmentStrings(template):
    size = len(template)
    while True:
        var = string_buffer(size)
        req = _ExpandEnvironmentStrings(template, var, size)
        raise_on_zero(req)
        if req <= size:
            break
        size = req
    return var.value

################################################################################

class PROCESS_INFORMATION(ctypes.Structure):
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

PPROCESS_INFORMATION = POINTER(PROCESS_INFORMATION)

################################################################################

class STARTUPINFO(ctypes.Structure):
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
        self.cb = ctypes.sizeof(STARTUPINFO)

PSTARTUPINFO = POINTER(STARTUPINFO)

class STARTUPINFOEX(ctypes.Structure):
    _fields_ = (
        ("StartupInfo", STARTUPINFO),
        ("lpAttributeList", PVOID),
        )

    def __init__(self, attr_lst=None):
        self.StartupInfo.cb = ctypes.sizeof(STARTUPINFOEX)
        self.lpAttributeList = attr_lst

################################################################################

_InitializeProcThreadAttributeList = _k32.fun_fact(
    "InitializeProcThreadAttributeList",
    (BOOL, PVOID, DWORD, DWORD, PSIZE_T)
    )

def InitializeProcThreadAttributeList(alst, acnt, flags, size=0):
    size = SIZE_T(size)
    ok = _InitializeProcThreadAttributeList(alst, acnt, flags, ref(size))
    raise_if(not ok and alst)
    return size.value

################################################################################

_UpdateProcThreadAttribute = _k32.fun_fact(
    "UpdateProcThreadAttribute",
    (BOOL, PVOID, DWORD, UINT_PTR, PVOID, SIZE_T, PVOID, PSIZE_T)
    )

def UpdateProcThreadAttribute(alst, flags, id, attr):
    raise_on_zero(
        _UpdateProcThreadAttribute(
            alst,
            flags,
            id,
            ref(attr),
            SIZE_T(ctypes.sizeof(attr)),
            None,
            None
            )
        )

################################################################################

_DeleteProcThreadAttributeList = _k32.fun_fact(
    "DeleteProcThreadAttributeList",
    (None, PVOID)
    )

def DeleteProcThreadAttributeList(alst):
    _DeleteProcThreadAttributeList(alst)

################################################################################

class ProcThreadAttributeList:
    def __init__(self, attr_pairs):
        self.buf = None
        size = InitializeProcThreadAttributeList(None, len(attr_pairs), 0)
        buf = byte_buffer(size)
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
        return ctypes.addressof(self.buf) if self.buf else None

################################################################################

_CreateProcess = _k32.fun_fact(
    "CreateProcessW", (
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
        psi = ref(startup_info.StartupInfo)
    else:
        psi = ref(startup_info)
    raise_on_zero(
        _CreateProcess(
            app_name,
            cmd_line,
            ref(proc_attr) if proc_attr is not None else None,
            ref(thread_attr) if thread_attr is not None else None,
            inherit,
            cflags,
            env,
            curdir,
            psi,
            ref(proc_info)
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

_CreateJobObject = _k32.fun_fact(
    "CreateJobObjectW",
    (KHANDLE, PSECURITY_ATTRIBUTES, PWSTR)
    )

def CreateJobObject(attrib=None, name=None):
    attrib = None if attrib is None else ref(attrib)
    job = _CreateJobObject(attrib, name)
    job.raise_on_invalid()
    return job

################################################################################

_AssignProcessToJobObject = _k32.fun_fact(
    "AssignProcessToJobObject",
    (BOOL, HANDLE, HANDLE)
    )

def AssignProcessToJobObject(job, proc):
    raise_on_zero(_AssignProcessToJobObject(job, proc))

################################################################################

class JOBOBJECT_ASSOCIATE_COMPLETION_PORT(ctypes.Structure):
    _fields_ = (
        ("CompletionKey", PVOID),
        ("CompletionPort", HANDLE),
        )

class JOBOBJECT_BASIC_ACCOUNTING_INFORMATION(ctypes.Structure):
    _fields_ = (
        ("TotalUserTime", LARGE_INTEGER),
        ("TotalKernelTime", LARGE_INTEGER),
        ("ThisPeriodTotalUserTime", LARGE_INTEGER),
        ("ThisPeriodTotalKernelTime", LARGE_INTEGER),
        ("TotalPageFaultCount", DWORD),
        ("TotalProcesses", DWORD),
        ("ActiveProcesses", DWORD),
        ("TotalTerminatedProcesses", DWORD),
    )

################################################################################

_SetInformationJobObject = _k32.fun_fact(
    "SetInformationJobObject",
    (BOOL, HANDLE, INT, PVOID, DWORD)
    )

def SetInformationJobObject(job, cls, ct_info):
    size = ctypes.sizeof(ct_info)
    raise_on_zero(_SetInformationJobObject(job, cls, ref(ct_info), size))

################################################################################

_QueryInformationJobObject = _k32.fun_fact(
    "QueryInformationJobObject",
    (BOOL, HANDLE, INT, PVOID, DWORD, PDWORD)
    )

def QueryInformationJobObject(job, cls, res_obj):
    raise_on_zero(
        _QueryInformationJobObject(
            job,
            cls,
            ref(res_obj),
            ctypes.sizeof(res_obj),
            None
            )
        )
    return res_obj

################################################################################

_ResumeThread = _k32.fun_fact("ResumeThread", (DWORD, HANDLE))

def ResumeThread(thdl):
    scnt = _ResumeThread(thdl)
    raise_if(scnt == 0xffffffff)
    return scnt

################################################################################

_GetPriorityClass = _k32.fun_fact("GetPriorityClass", (DWORD, HANDLE))

def GetPriorityClass(phdl):
    raise_on_zero(result := _GetPriorityClass(phdl))
    return result

################################################################################

_SetPriorityClass = _k32.fun_fact("SetPriorityClass", (BOOL, HANDLE, DWORD))

def SetPriorityClass(phdl, prio):
    raise_on_zero(_SetPriorityClass(phdl, prio))

################################################################################

_GetThreadPriority = _k32.fun_fact("GetThreadPriority", (INT, HANDLE))

def GetThreadPriority(thdl):
    result = _GetThreadPriority(thdl)
    raise_if(result == THREAD_PRIORITY_ERROR_RETURN)
    return result

################################################################################

_SetThreadPriority = _k32.fun_fact("SetThreadPriority", (BOOL, HANDLE, INT))

def SetThreadPriority(thdl, prio):
    raise_on_zero(_SetThreadPriority(thdl, prio))

################################################################################

def _get_dir(func, order):
    buf_size = 256
    while True:
        buf = string_buffer(buf_size)
        req_size = func(*((buf, buf_size) if order else (buf_size, buf)))
        if req_size <= buf_size:
            return buf.value
        buf_size = req_size

################################################################################

_GetSystemDirectory = _k32.fun_fact("GetSystemDirectoryW", (UINT, PWSTR, UINT))

def GetSystemDirectory():
    return _get_dir(_GetSystemDirectory, 1)

################################################################################

_GetWindowsDirectory = _k32.fun_fact(
    "GetWindowsDirectoryW",
    (UINT, PWSTR, UINT)
    )

def GetWindowsDirectory():
    return _get_dir(_GetWindowsDirectory, 1)


################################################################################

_GetCurrentDirectory = _k32.fun_fact(
    "GetCurrentDirectoryW",
    (DWORD, DWORD, PWSTR)
    )

def GetCurrentDirectory():
    return _get_dir(_GetCurrentDirectory, 0)

################################################################################

_GetSystemWow64Directory = _k32.fun_fact(
    "GetSystemWow64DirectoryW",
    (UINT, PWSTR, UINT)
    )

def GetSystemWow64Directory():
    return _get_dir(_GetSystemWow64Directory, 1)

################################################################################

_SetCurrentDirectory = _k32.fun_fact("SetCurrentDirectoryW", (BOOL, PWSTR))

def SetCurrentDirectory(path):
    raise_on_zero(_SetCurrentDirectory(path))

################################################################################

class ACTCTX(ctypes.Structure):
    _fields_ = (
        ("cbSize", ULONG),
        ("dwFlags", DWORD),
        ("lpSource", PWSTR),
        ("wProcessorArchitecture", USHORT),
        ("wLangId", USHORT),
        ("lpAssemblyDirectory", PWSTR),
        ("lpResourceName", PWSTR),
        ("lpApplicationName", PWSTR),
        ("hModule", HANDLE),
        )

    def __init__(self):
        self.cbSize = ctypes.sizeof(self)

PACTCTX = POINTER(ACTCTX)

################################################################################

_CreateActCtx = _k32.fun_fact("CreateActCtxW", (HANDLE, PACTCTX))

def CreateActCtx(actctx):
    res = _CreateActCtx(ref(actctx))
    raise_if(res == INVALID_HANDLE_VALUE)
    return res

################################################################################

_ActivateActCtx = _k32.fun_fact("ActivateActCtx", (BOOL, HANDLE, PULONG_PTR))

def ActivateActCtx(ctx):
    cookie = ULONG_PTR()
    raise_on_zero(_ActivateActCtx(ctx, ref(cookie)))
    return cookie.value

################################################################################

_DeactivateActCtx = _k32.fun_fact("DeactivateActCtx", (BOOL, DWORD, ULONG_PTR))

def DeactivateActCtx(flags, cookie):
    raise_on_zero(_DeactivateActCtx(flags, cookie))

################################################################################

ReleaseActCtx = _k32.fun_fact("ReleaseActCtx", (None, HANDLE))

################################################################################

_GlobalAddAtom = _k32.fun_fact("GlobalAddAtomW", (WORD, PWSTR))

def GlobalAddAtom(name):
    atom = _GlobalAddAtom(name)
    raise_on_zero(atom)
    return atom

################################################################################

def global_add_atom(name):
    return ctypes.cast(GlobalAddAtom(name), PWSTR)

################################################################################

GlobalDeleteAtom = _k32.fun_fact("GlobalDeleteAtom", (None, WORD))

################################################################################

_GlobalGetAtomName = _k32.fun_fact(
    "GlobalGetAtomNameW",
    (UINT, WORD, PWSTR, INT))

def GlobalGetAtomName(atom):
    size = 512
    while True:
        var = string_buffer(size)
        req = _GlobalGetAtomName(atom, var, size)
        raise_on_zero(req)
        if req <= size:
            break
        size = req
    return var.value

################################################################################

_FreeLibrary = _k32.fun_fact("FreeLibrary", (BOOL, HANDLE))

def FreeLibrary(hmod):
    raise_on_zero(_FreeLibrary(hmod))

################################################################################

class HMODULE(ScdToBeClosed, HANDLE, close_func=FreeLibrary, invalid=0):
    pass

################################################################################

_LoadLibraryEx = _k32.fun_fact("LoadLibraryExW", (HANDLE, PWSTR, HANDLE, DWORD))

def LoadLibraryEx(filename, flags=0):
    hmod = HMODULE(_LoadLibraryEx(filename, None, flags))
    hmod.raise_on_invalid()
    return hmod

def LoadLibrary(filename):
    return LoadLibraryEx(filename, 0)

################################################################################

class terminate_on_exception:

    def __enter__(self):
        return self

    def __exit__(self, typ, val, tb):
        if typ is None:
            return

        # An exception has occurred, which our caller would like to be taken
        # as a reason to terminate this process. Most likely our caller wants
        # this, because it is executing a callback from C code into python code
        # (through ctypes). In such a situation there is no possibility to
        # propagate this exception to the python interpreter and therefore the
        # process has to be terminated.
        # Before we do that, we try to inform the user.

        try:
            from ctwin32 import user  # noqa: PLC0415
            info = "".join(traceback.format_exception(typ, val, tb))
            try:
                interactive = user.is_interactive_process()
            except OSError:
                interactive = False

            if interactive:
                if sys.stderr is None or not hasattr(sys.stderr, "mode"):
                    user.txt_to_clip(info)
                    info += "\nThe above text has been copied to the clipboard."
                    user.MessageBox(
                        None,
                        info,
                        "Terminating program",
                        MB_OK | MB_ICONERROR
                        )
                else:
                    sys.stderr.write(info)
            else:
                dbg_print(info)

        finally:
            # Calling sys.exit() here won't help, since it depends on exception
            # propagation. We could hope that this thread is pumping messages
            # while watching for WM_QUIT messages and post such a message.
            # Since this possibility seems too vague, we play it safe
            # and call:
            ExitProcess(1)

################################################################################

_EnumResNameCallback = ctypes.WINFUNCTYPE(
    BOOL,
    HANDLE,
    PVOID,  # must not use PWSTR as parameter type since ctypes conversion
    PVOID,  # code will get confused by 16-bit IDs that are NOT valid pointers
    CallbackContextPtr
    )

@_EnumResNameCallback
def _EnumResNameCb(hmod, typ, name, ctxt):
    # cannot propagate exceptions from callback
    with terminate_on_exception():
        typ = typ if not (typ >> 16) else ctypes.wstring_at(typ)
        name = name if not (name >> 16) else ctypes.wstring_at(name)
        cbc = ctxt.contents
        res = cbc.callback(hmod, typ, name, cbc.context)
        # keep on enumerating if the callback fails to return a value
        return res if res is not None else True

_EnumResourceNames = _k32.fun_fact(
    "EnumResourceNamesW",
    (BOOL, HANDLE, PWSTR, _EnumResNameCallback, CallbackContextPtr)
    )

def EnumResourceNames(hmod, typ, callback, context):
    cbc = CallbackContext(callback, context)
    if not _EnumResourceNames(hmod, typ, _EnumResNameCb, ref(cbc)):
        if (err := GetLastError()) != ERROR_RESOURCE_ENUM_USER_STOP:
            raise WinError(err)

################################################################################

def get_resource_names(hmod, typ):
    names = []

    @_EnumResNameCallback
    def collect(not_used1, not_used2, name, not_used3):
        # cannot propagate exceptions from callback
        with terminate_on_exception():
            if name >= 0x10000:
                name = PWSTR(name).value
            names.append(name)
            return True

    raise_on_zero(_EnumResourceNames(hmod, typ, collect, None))
    return names

################################################################################

_FindResource = _k32.fun_fact("FindResourceW", (HANDLE, HANDLE, PWSTR, PWSTR))

def FindResource(hmod, name, typ):
    name = name if isinstance(name, PWSTR) else PWSTR(name)
    typ = typ if isinstance(typ, PWSTR) else PWSTR(typ)
    res = _FindResource(hmod, name, typ)
    raise_on_zero(res)
    return res

################################################################################

_SizeofResource = _k32.fun_fact("SizeofResource", (DWORD, HANDLE, HANDLE))

def SizeofResource(hmod, hrsc):
    res = _SizeofResource(hmod, hrsc)
    raise_on_zero(res)
    return res

################################################################################

_LoadResource = _k32.fun_fact("LoadResource", (PVOID, HANDLE, HANDLE))

def LoadResource(hmod, hrsc):
    res = _LoadResource(hmod, hrsc)
    raise_on_zero(res)
    return res

################################################################################

def get_resource_info(hmod, name, typ):
    hrsc = FindResource(hmod, name, typ)
    size = SizeofResource(hmod, hrsc)
    return LoadResource(hmod, hrsc), size

################################################################################

MESSAGE_RESOURCE_ANSI = 0
MESSAGE_RESOURCE_UNICODE = 1
MESSAGE_RESOURCE_UTF8 = 2

class MESSAGE_RESOURCE_ENTRY(ctypes.Structure):
    _fields_ = (
        ("Length", WORD),
        ("Flags", WORD),
        ("Text", BYTE),  # an array of (Length - offsetof(Text)) bytes
    )

class MESSAGE_RESOURCE_BLOCK(ctypes.Structure):
    _fields_ = (
        ("LowId", DWORD),
        ("HighId", DWORD),
        ("OffsetToEntries", DWORD),
    )

class MESSAGE_RESOURCE_DATA(ctypes.Structure):
    _fields_ = (
        ("NumberOfBlocks", DWORD),
        ("Blocks", MESSAGE_RESOURCE_BLOCK),  # an array of NumberOfBlocks
    )

def load_message_string(hmod, msg_id):
    msg_id = DWORD(msg_id).value
    for name in get_resource_names(hmod, RT_MESSAGETABLE):
        addr, _ = get_resource_info(hmod, name, RT_MESSAGETABLE)
        nblocks = MESSAGE_RESOURCE_DATA.from_address(addr).NumberOfBlocks
        bsize = ctypes.sizeof(MESSAGE_RESOURCE_BLOCK)
        bbase = addr + MESSAGE_RESOURCE_DATA.Blocks.offset
        for b in range(nblocks):
            block = MESSAGE_RESOURCE_BLOCK.from_address(bbase + b * bsize)
            if block.LowId <= msg_id <= block.HighId:
                eaddr = addr + block.OffsetToEntries
                for cur_id in range(block.LowId, block.HighId + 1):
                    entry = MESSAGE_RESOURCE_ENTRY.from_address(eaddr)
                    if cur_id != msg_id:
                        eaddr += entry.Length
                        continue
                    toff = MESSAGE_RESOURCE_ENTRY.Text.offset
                    taddr = eaddr + toff
                    slen = entry.Length - toff
                    if entry.Flags == MESSAGE_RESOURCE_UNICODE:
                        msg = ctypes.wstring_at(taddr, slen // 2)
                    else:
                        msg = ctypes.string_at(taddr, slen).decode(
                            "utf-8" if entry.Flags == MESSAGE_RESOURCE_UTF8
                            else get_ansi_encoding()
                            )
                    return msg.strip("\0")

    raise WinError(ERROR_RESOURCE_NAME_NOT_FOUND)

################################################################################

class SYSTEM_INFO(ctypes.Structure):
    _fields_ = (
        ("wProcessorArchitecture", WORD),
        ("wReserved", WORD),
        ("dwPageSize", DWORD),
        ("lpMinimumApplicationAddress", PVOID),
        ("lpMaximumApplicationAddress", PVOID),
        ("dwActiveProcessorMask", ULONG_PTR),
        ("dwNumberOfProcessors", DWORD),
        ("dwProcessorType", DWORD),
        ("dwAllocationGranularity", DWORD),
        ("wProcessorLevel", WORD),
        ("wProcessorRevision", WORD),
        )
PSYSTEM_INFO = POINTER(SYSTEM_INFO)

_GetSystemInfo = _k32.fun_fact("GetSystemInfo", (None, PSYSTEM_INFO))

def GetSystemInfo():
    si = SYSTEM_INFO()
    _GetSystemInfo(ref(si))
    return ns_from_struct(si)

################################################################################

_GetNativeSystemInfo = _k32.fun_fact(
    "GetNativeSystemInfo",
    (None, PSYSTEM_INFO)
    )

def GetNativeSystemInfo():
    si = SYSTEM_INFO()
    _GetNativeSystemInfo(ref(si))
    return ns_from_struct(si)

################################################################################

_IsWow64Process = _k32.fun_fact("IsWow64Process", (BOOL, HANDLE, PBOOL))

def IsWow64Process(hprocess):
    res = BOOL()
    raise_on_zero(_IsWow64Process(hprocess, ref(res)))
    return res != 0

################################################################################

def get_wow64_info(hprocess):
    mach = USHORT(IMAGE_FILE_MACHINE_UNKNOWN)
    proc = USHORT(IMAGE_FILE_MACHINE_UNKNOWN)
    try:
        _IsWow64Process2 = _k32.fun_fact(
            "IsWow64Process2",
            (BOOL, HANDLE, PUSHORT, PUSHORT)
            )
    except AttributeError:
        # IsWow64Process2 not available
        if IsWow64Process(hprocess):
            mach = USHORT(IMAGE_FILE_MACHINE_AMD64)
        else:
            mach = USHORT(IMAGE_FILE_MACHINE_I386)
    else:
        raise_on_zero(_IsWow64Process2(hprocess, ref(proc), ref(mach)))
    return mach.value, proc.value

################################################################################

_GetStdHandle = _k32.fun_fact("GetStdHandle", (HANDLE, DWORD))

def GetStdHandle(nhdl):
    res = _GetStdHandle(nhdl)
    raise_if(res == INVALID_HANDLE_VALUE)
    return res

################################################################################

_GetFileType = _k32.fun_fact("GetFileType", (DWORD, HANDLE))

def GetFileType(hdl):
    res = _GetFileType(hdl)
    if res == FILE_TYPE_UNKNOWN:
        if (err := GetLastError()) != ERROR_SUCCESS:
            raise WinError(err)
    return res

################################################################################

_SetConsoleTextAttribute = _k32.fun_fact(
    "SetConsoleTextAttribute",
    (BOOL, HANDLE, WORD)
    )

def SetConsoleTextAttribute(hcon, attr):
    raise_on_zero(_SetConsoleTextAttribute(hcon, attr))

################################################################################

class COORD(ctypes.Structure):
    _fields_ = (
        ("X", SHORT),
        ("Y", SHORT),
        )

class SMALL_RECT(ctypes.Structure):
    _fields_ = (
        ("Left", SHORT),
        ("Top", SHORT),
        ("Right", SHORT),
        ("Bottom", SHORT),
        )

class CONSOLE_SCREEN_BUFFER_INFO(ctypes.Structure):
    _fields_ = (
        ("dwSize", COORD),
        ("dwCursorPosition", COORD),
        ("wAttributes", WORD),
        ("srWindow", SMALL_RECT),
        ("dwMaximumWindowSize", COORD),
        )
PCONSOLE_SCREEN_BUFFER_INFO = POINTER(CONSOLE_SCREEN_BUFFER_INFO)

################################################################################

_GetConsoleScreenBufferInfo = _k32.fun_fact(
    "GetConsoleScreenBufferInfo",
    (BOOL, HANDLE, PCONSOLE_SCREEN_BUFFER_INFO)
    )

def GetConsoleScreenBufferInfo(hcon):
    info = CONSOLE_SCREEN_BUFFER_INFO()
    raise_on_zero(_GetConsoleScreenBufferInfo(hcon, ref(info)))
    return info

################################################################################

_FillConsoleOutputCharacter = _k32.fun_fact(
    "FillConsoleOutputCharacterW",
    (BOOL, HANDLE, WCHAR, DWORD, COORD, PDWORD)
    )

def FillConsoleOutputCharacter(hdl, char, length, coord):
    num_written = DWORD()
    raise_on_zero(
        _FillConsoleOutputCharacter(hdl, char, length, coord, ref(num_written))
        )
    return num_written

################################################################################

_FillConsoleOutputAttribute = _k32.fun_fact(
    "FillConsoleOutputCharacterW",
    (BOOL, HANDLE, WORD, DWORD, COORD, PDWORD)
    )

def FillConsoleOutputAttribute(hdl, attr, length, coord):
    num_written = DWORD()
    raise_on_zero(
        _FillConsoleOutputCharacter(hdl, attr, length, coord, ref(num_written))
        )
    return num_written

################################################################################

_SetConsoleCursorPosition = _k32.fun_fact(
    "SetConsoleCursorPosition",
    (BOOL, HANDLE, COORD)
    )

def SetConsoleCursorPosition(hdl, coord):
    raise_on_zero(_SetConsoleCursorPosition(hdl, coord))

################################################################################

def clear_screen(hdl):
    info = GetConsoleScreenBufferInfo(hdl)
    size = info.dwMaximumWindowSize
    length = size.X * size.Y
    attr = info.wAttributes
    coord = COORD(0, 0)
    FillConsoleOutputAttribute(hdl, attr, length, coord)
    FillConsoleOutputCharacter(hdl, ord(" "), length, coord)
    SetConsoleCursorPosition(hdl, coord)

################################################################################

def cls(hdl=None):
    if hdl is None:
        hdl = GetStdHandle(STD_OUTPUT_HANDLE)
        if GetFileType(hdl) != FILE_TYPE_CHAR:
            return
    clear_screen(hdl)

################################################################################

_GetConsoleMode = _k32.fun_fact("GetConsoleMode", (BOOL, HANDLE, PDWORD))

def GetConsoleMode(hdl):
    mode = DWORD()
    raise_on_zero(_GetConsoleMode(hdl, ref(mode)))
    return mode.value

################################################################################

_SetConsoleMode = _k32.fun_fact("SetConsoleMode", (BOOL, HANDLE, DWORD))

def SetConsoleMode(hdl, mode):
    raise_on_zero(_SetConsoleMode(hdl, mode))

################################################################################

def enable_virt_term(hdl=None):
    if hdl is None:
        hdl = GetStdHandle(STD_OUTPUT_HANDLE)
        if GetFileType(hdl) != FILE_TYPE_CHAR:
            return
    mode = GetConsoleMode(hdl) | ENABLE_VIRTUAL_TERMINAL_PROCESSING
    SetConsoleMode(hdl, mode)

################################################################################

_GetNumberOfConsoleInputEvents  = _k32.fun_fact(
    "GetNumberOfConsoleInputEvents",
    (BOOL, HANDLE, PDWORD)
    )

def GetNumberOfConsoleInputEvents(hdl):
    num = DWORD()
    raise_on_zero(_GetNumberOfConsoleInputEvents(hdl, ref(num)))
    return num.value

################################################################################

class FOCUS_EVENT_RECORD(ctypes.Structure):
    _fields_ = (
        ("bSetFocus", BOOL),
        )

class KEY_EVENT_RECORD(ctypes.Structure):
    _fields_ = (
        ("bKeyDown", BOOL),
        ("wRepeatCount", WORD),
        ("wVirtualKeyCode", WORD),
        ("wVirtualScanCode", WORD),
        ("UnicodeChar", WCHAR),
        ("dwControlKeyState", DWORD),
        )

class MENU_EVENT_RECORD(ctypes.Structure):
    _fields_ = (
        ("dwCommandId", UINT),
        )

class MOUSE_EVENT_RECORD(ctypes.Structure):
    _fields_ = (
        ("dwMousePosition", COORD),
        ("dwButtonState", DWORD),
        ("dwControlKeyState", DWORD),
        ("dwEventFlags", DWORD),
        )

class WINDOW_BUFFER_SIZE_RECORD(ctypes.Structure):
    _fields_ = (
        ("dwSize", COORD),
        )

class INPUT_RECORD_EVENT_UNION(ctypes.Union):
    _fields_ = (
        ("KeyEvent", KEY_EVENT_RECORD),
        ("MouseEvent", MOUSE_EVENT_RECORD),
        ("WindowBufferSizeEvent", WINDOW_BUFFER_SIZE_RECORD),
        ("MenuEvent", MENU_EVENT_RECORD),
        ("FocusEvent", FOCUS_EVENT_RECORD),
        )

class INPUT_RECORD(ctypes.Structure):
    _fields_ = (
        ("EventType", WORD),
        ("Event", INPUT_RECORD_EVENT_UNION),
        )

PINPUT_RECORD = POINTER(INPUT_RECORD)

################################################################################

_ReadConsoleInput  = _k32.fun_fact(
    "ReadConsoleInputW",
    (BOOL, HANDLE, PINPUT_RECORD, DWORD, PDWORD)
    )

def ReadConsoleInput(hdl, num_records=1):
    num_records = max(num_records, 1)
    ir = (INPUT_RECORD * num_records)()
    num_read = DWORD()
    raise_on_zero(_ReadConsoleInput(hdl, ir, num_records, ref(num_read)))
    return ir[:num_read.value]

################################################################################

SetErrorMode = _k32.fun_fact("SetErrorMode", (UINT, UINT))

################################################################################

_SetThreadErrorMode = _k32.fun_fact("SetThreadErrorMode", (BOOL, DWORD, PDWORD))

def SetThreadErrorMode(mode):
    old = DWORD()
    raise_on_zero(_SetThreadErrorMode(mode, ref(old)))
    return old.value

################################################################################

_FindClose = _k32.fun_fact("FindClose", (BOOL, HANDLE))

def FindClose(hdl):
    raise_on_zero(_FindClose(hdl))

################################################################################

class FFHANDLE(
        ScdToBeClosed,
        HANDLE,
        close_func=FindClose,
        invalid=INVALID_HANDLE_VALUE
        ):
    pass

################################################################################

_FindFirstFile = _k32.fun_fact(
    "FindFirstFileW",
    (HANDLE, PWSTR, PWIN32_FIND_DATA)
    )

def FindFirstFile(name, ignore_not_found=False):
    find_data = WIN32_FIND_DATA()
    hdl = FFHANDLE(_FindFirstFile(name, ref(find_data)))
    if not hdl.is_valid():
        err = GetLastError()
        if ignore_not_found and err == ERROR_FILE_NOT_FOUND:
            return None, None
        raise WinError(err)
    return hdl, find_data

################################################################################

_FindNextFile = _k32.fun_fact("FindNextFileW", (BOOL, HANDLE, PWIN32_FIND_DATA))

def FindNextFile(hdl):
    find_data = WIN32_FIND_DATA()
    res = _FindNextFile(hdl, ref(find_data))
    if not res:
        err = GetLastError()
        if err == ERROR_NO_MORE_FILES:
            return None
        raise WinError(err)
    return find_data

################################################################################

def iter_dir(directory, ignore_access_denied=True):
    pattern = str(directory) + "\\*"
    try:
        hdl, info = FindFirstFile(pattern, True)
    except OSError as e:
        if ignore_access_denied and e.winerror == ERROR_ACCESS_DENIED:
            return
        raise
    if hdl is None:
        return
    with hdl:
        while True:
            yield directory, info
            is_sub = (
                bool(info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) and
                info.cFileName not in (".", "..")
                )
            if is_sub:
                sub = rf"{directory}\{info.cFileName}"
                yield from iter_dir(sub, ignore_access_denied)

            info = FindNextFile(hdl)
            if info is None:
                break

################################################################################

def find_file(name):
    hdl, info = FindFirstFile(name)
    hdl.close()
    return info

################################################################################

_FindFirstFileName = _k32.fun_fact(
    "FindFirstFileNameW",
    (HANDLE, PWSTR, DWORD, PDWORD, PWSTR)
    )

def FindFirstFileName(name):
    size = DWORD(256)
    while True:
        size.value *= 2
        buf = string_buffer(size.value)
        hdl = FFHANDLE(_FindFirstFileName(name, 0, ref(size), buf))
        if not hdl.is_valid():
            err = GetLastError()
            if err == ERROR_MORE_DATA:
                continue
            if err == ERROR_FILE_NOT_FOUND:
                return None, None
            raise WinError(err)
        return hdl, buf.value

################################################################################

_FindNextFileName = _k32.fun_fact(
    "FindNextFileNameW",
    (BOOL, HANDLE, PDWORD, PWSTR)
    )

def FindNextFileName(hdl):
    size = DWORD(256)
    while True:
        size.value *= 2
        buf = string_buffer(size.value)
        if not _FindNextFileName(hdl, ref(size), buf):
            err = GetLastError()
            if err == ERROR_MORE_DATA:
                continue
            if err == ERROR_HANDLE_EOF:
                return None
            raise WinError(err)
        return buf.value

################################################################################

def find_all_filenames(name):
    hdl, name = FindFirstFileName(name)
    if hdl is not None:
        with hdl:
            while True:
                yield name
                name = FindNextFileName(hdl)
                if name is None:
                    break

################################################################################

class PowerRequest(_int_enum):
    DisplayRequired = 0
    SystemRequired = 1
    AwayModeRequired = 2
    ExecutionRequired = 3
    Inactive = -1

    @classmethod
    def from_param(cls, obj):
        return int(cls(obj))

# values for REASON_CONTEXT.Version and REASON_CONTEXT.Flags
POWER_REQUEST_CONTEXT_VERSION = 0
POWER_REQUEST_CONTEXT_SIMPLE_STRING = 1
POWER_REQUEST_CONTEXT_DETAILED_STRING = 2

class REASON_CONTEXT_DETAILED(ctypes.Structure):
    _fields_ = (
        ("LocalizedReasonModule", HMODULE),
        ("LocalizedReasonId", ULONG),
        ("ReasonStringCount", ULONG),
        ("ReasonStrings", PPWSTR),
        )

class REASON_CONTEXT_UNION(ctypes.Union):
    _fields_ = (
        ("Detailed", REASON_CONTEXT_DETAILED),
        ("SimpleReasonString", PWSTR),
        )

class REASON_CONTEXT(ctypes.Structure):
    _fields_ = (
        ("Version", ULONG),
        ("Flags", DWORD),
        ("Reason", REASON_CONTEXT_UNION)
        )

    def __init__(self, reason_str=""):
        self.Version = POWER_REQUEST_CONTEXT_VERSION
        self.Flags = POWER_REQUEST_CONTEXT_SIMPLE_STRING
        self.Reason = REASON_CONTEXT_UNION(SimpleReasonString=reason_str)

PREASON_CONTEXT = POINTER(REASON_CONTEXT)

################################################################################

_PowerCreateRequest = _k32.fun_fact(
    "PowerCreateRequest",
    (HANDLE, PREASON_CONTEXT)
    )

def PowerCreateRequest(reason):
    hdl = FHANDLE(_PowerCreateRequest(ref(reason)))
    hdl.raise_on_invalid()
    return hdl

################################################################################

_PowerSetRequest = _k32.fun_fact(
    "PowerSetRequest",
    (BOOL, HANDLE, PowerRequest)
    )

def PowerSetRequest(hdl, pwr_request):
    raise_on_zero(_PowerSetRequest(hdl, pwr_request))

################################################################################

_PowerClearRequest = _k32.fun_fact(
    "PowerClearRequest",
    (BOOL, HANDLE, PowerRequest)
    )

def PowerClearRequest(hdl, pwr_request):
    raise_on_zero(_PowerClearRequest(hdl, pwr_request))

################################################################################

def create_power_request(reason_str, pwr_request=PowerRequest.Inactive):
    hdl = PowerCreateRequest(REASON_CONTEXT(reason_str))
    if pwr_request != PowerRequest.Inactive:
        PowerSetRequest(hdl, pwr_request)
    return hdl

################################################################################

GetDriveType = _k32.fun_fact("GetDriveTypeW", (UINT, PWSTR))

################################################################################

_GetLogicalDriveStrings = _k32.fun_fact(
    "GetLogicalDriveStringsW",
    (DWORD, DWORD, PWSTR)
    )

def GetLogicalDriveStrings():
    size = 256
    buf = string_buffer(size)
    raise_on_zero(res := _GetLogicalDriveStrings(size, buf))
    return multi_str_from_ubuf(buf, res)

################################################################################

_FindFirstVolume = _k32.fun_fact("FindFirstVolumeW", (HANDLE, PWSTR, DWORD))

def FindFirstVolume():
    size = 256
    buf = string_buffer(size)
    hdl = _FindFirstVolume(buf, size)
    raise_if(hdl == INVALID_HANDLE_VALUE)
    return hdl, buf.value

################################################################################

_FindNextVolume = _k32.fun_fact("FindNextVolumeW", (BOOL, HANDLE, PWSTR, DWORD))

def FindNextVolume(hdl):
    size = 256
    buf = string_buffer(size)
    raise_on_zero(_FindNextVolume(hdl, buf, size))
    return buf.value

################################################################################

_FindVolumeClose = _k32.fun_fact("FindVolumeClose", (BOOL, HANDLE))

def FindVolumeClose(hdl):
    raise_on_zero(_FindVolumeClose(hdl))

################################################################################

def enum_volumes():
    hdl, vol = FindFirstVolume()
    try:
        while True:
            yield vol
            vol = FindNextVolume(hdl)
    except OSError as e:
        if e.winerror != ERROR_NO_MORE_FILES:
            raise
    finally:
        FindVolumeClose(hdl)

################################################################################

_GetVolumePathNamesForVolumeName = _k32.fun_fact(
    "GetVolumePathNamesForVolumeNameW",
    (BOOL, PWSTR, PWSTR, DWORD, PDWORD)
    )

def GetVolumePathNamesForVolumeName(vol):
    size = DWORD(256)
    while True:
        buf = string_buffer(size.value)
        ok = _GetVolumePathNamesForVolumeName(vol, buf, size, ref(size))
        if ok:
            return multi_str_from_ubuf(buf, size.value)
        elif (err := GetLastError()) != ERROR_MORE_DATA:
            raise_on_err(err)

################################################################################

_ReadProcessMemory = _k32.fun_fact(
    "ReadProcessMemory",
    (BOOL, HANDLE, PVOID, PVOID, SIZE_T, PSIZE_T)
    )

def ReadProcessMemory(hdl, addr, length):
    buf = byte_buffer(length)
    raise_on_zero(_ReadProcessMemory(hdl, addr, buf, length, None))
    return buf

################################################################################

_WriteProcessMemory = _k32.fun_fact(
    "WriteProcessMemory",
    (BOOL, HANDLE, PVOID, PVOID, SIZE_T, PSIZE_T)
    )

def WriteProcessMemory(hdl, addr, data):
    raise_on_zero(_WriteProcessMemory(hdl, addr, data, len(data), None))

################################################################################

def get_proc_env_as_dict(hdl):
    t32 = (    DWORD, 16,  72,  656)    # noqa: E201, RUF100
    t64 = (ULONGLONG, 32, 128, 1008)
    peb = ntdll.get_wow64_proc_env_blk(hdl)
    if peb != 0:
        # type, offs process params, offs env ptr, offs env len
        typ, opp, oep, oel = t32
    else:
        typ, opp, oep, oel = t64 if ctypes.sizeof(PVOID) == 8 else t32
        peb = ntdll.get_proc_env_blk(hdl)
    isize = ctypes.sizeof(typ)

    def read_proc_int(addr):
        return typ.from_buffer(ReadProcessMemory(hdl, addr, isize)).value

    process_params = read_proc_int(peb + opp)
    env_ptr = read_proc_int(process_params + oep)
    env_len = read_proc_int(process_params + oel)

    buf = ReadProcessMemory(hdl, env_ptr, env_len)
    str_len = env_len // ctypes.sizeof(WCHAR)
    str_type = WCHAR * str_len
    env = multi_str_from_ubuf(str_type.from_buffer(buf), str_len)
    return env_str_to_dict(env)

################################################################################

class BY_HANDLE_FILE_INFORMATION(ctypes.Structure):
    _fields_ = (
        ("dwFileAttributes", DWORD),
        ("ftCreationTime", FILETIME),
        ("ftLastAccessTime", FILETIME),
        ("ftLastWriteTime", FILETIME),
        ("dwVolumeSerialNumber", DWORD),
        ("nFileSizeHigh", DWORD),
        ("nFileSizeLow", DWORD),
        ("nNumberOfLinks", DWORD),
        ("nFileIndexHigh", DWORD),
        ("nFileIndexLow", DWORD),
        )
PBY_HANDLE_FILE_INFORMATION = POINTER(BY_HANDLE_FILE_INFORMATION)

_GetFileInformationByHandle = _k32.fun_fact(
    "GetFileInformationByHandle",
    (BOOL, HANDLE, PBY_HANDLE_FILE_INFORMATION)
    )

def GetFileInformationByHandle(hdl):
    info = BY_HANDLE_FILE_INFORMATION()
    raise_on_zero(_GetFileInformationByHandle(hdl, ref(info)))
    return ns_from_struct(info)

################################################################################

_CreateFileMapping = _k32.fun_fact(
    "CreateFileMappingW", (
        HANDLE,
        HANDLE,
        PSECURITY_ATTRIBUTES,
        DWORD,
        DWORD,
        DWORD,
        PWSTR
        )
    )

def CreateFileMapping(fhdl, sec_attr, prot, maxsize, name=None):
    hdl = KHANDLE(
        _CreateFileMapping(
            fhdl,
            sec_attr,
            prot,
            maxsize >> 32,
            maxsize & 0xffffffff,
            name
            )
        )
    hdl.raise_on_invalid()
    return hdl

################################################################################

_MapViewOfFile = _k32.fun_fact(
    "MapViewOfFile",
    (PVOID, HANDLE, DWORD, DWORD, DWORD, SIZE_T)
    )

def MapViewOfFile(mapping, acc, offset, size):
    addr = _MapViewOfFile(mapping, acc, offset >> 32, offset & 0xffffffff, size)
    raise_on_zero(addr)
    return addr

################################################################################

_UnmapViewOfFile = _k32.fun_fact("UnmapViewOfFile", (BOOL, PVOID))

def UnmapViewOfFile(addr):
    raise_on_zero(_UnmapViewOfFile(addr))

################################################################################

_GetFileSizeEx = _k32.fun_fact("GetFileSizeEx", (BOOL, HANDLE, PLARGE_INTEGER))

def GetFileSizeEx(hdl):
    size = LARGE_INTEGER()
    raise_on_zero(_GetFileSizeEx(hdl, ref(size)))
    return size.value

GetFileSize = GetFileSizeEx

################################################################################

_AddDllDirectory = _k32.fun_fact("AddDllDirectory", (PVOID, PWSTR))

def AddDllDirectory(dir_name):
    cookie = _AddDllDirectory(dir_name)
    raise_if(cookie is None)
    return cookie

################################################################################

_RemoveDllDirectory = _k32.fun_fact("RemoveDllDirectory", (BOOL, PVOID))

def RemoveDllDirectory(cookie):
    raise_on_zero(_RemoveDllDirectory(cookie))

################################################################################
