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

import collections as _collections

from .wtypes import *
from . import (
    ref,
    raise_if,
    raise_on_zero,
    fun_fact,
    ERROR_INSUFFICIENT_BUFFER,
    ERROR_RESOURCE_ENUM_USER_STOP,
    ERROR_RESOURCE_NAME_NOT_FOUND,
    INVALID_FILE_ATTRIBUTES,
    INVALID_HANDLE_VALUE,
    RT_MESSAGETABLE,
    multi_str_from_addr,
    cmdline_from_args,
    ns_from_struct,
    )

_k32 = ctypes.WinDLL("kernel32.dll")

################################################################################

ExitProcess = fun_fact(_k32.ExitProcess, (None, UINT))

################################################################################

GetLastError = fun_fact(_k32.GetLastError, (DWORD,))
SetLastError = fun_fact(_k32.SetLastError, (None, DWORD))

################################################################################

_LocalFree = fun_fact(_k32.LocalFree, (HANDLE, HANDLE))

def LocalFree(hmem):
    raise_if(_LocalFree(hmem))

################################################################################

_GlobalFree = fun_fact(_k32.GlobalFree, (HANDLE, HANDLE))

def GlobalFree(hmem):
    raise_if(_GlobalFree(hmem))

################################################################################

_GlobalAlloc = fun_fact(_k32.GlobalAlloc, (HANDLE, UINT, SIZE_T))

def GlobalAlloc(flags, size):
    res = _GlobalAlloc(flags, size)
    raise_on_zero(res)
    return res

################################################################################

_GlobalLock = fun_fact(_k32.GlobalLock, (PVOID, HANDLE))

def GlobalLock(hmem):
    res = _GlobalLock(hmem)
    raise_on_zero(res)
    return res

################################################################################

GlobalUnlock = fun_fact(_k32.GlobalUnlock, (PVOID, HANDLE))

################################################################################

_CloseHandle = fun_fact(_k32.CloseHandle, (BOOL, HANDLE))

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
        ("lpSecurityDescriptor", PVOID),
        ("nLength", DWORD),
        ("bInheritHandle", BOOL),
    )
PSECURITY_ATTRIBUTES = POINTER(SECURITY_ATTRIBUTES)

################################################################################

_CreateFile = fun_fact(
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
    hdl.raise_on_invalid()
    return hdl

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

################################################################################

_DeviceIoControl = fun_fact(
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
        iptr, ilen = ref(in_bytes), len(in_bytes)

    if out_len is None or out_len == 0:
        out, optr, olen = None, None, 0
    else:
        out = ctypes.create_string_buffer(out_len)
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
    return out.raw[:bytes_returned.value] if out else None

################################################################################

_GetCurrentProcess = fun_fact(_k32.GetCurrentProcess, (HANDLE,))

def GetCurrentProcess():
    return _GetCurrentProcess()

################################################################################

_GetCurrentProcessId = fun_fact(_k32.GetCurrentProcessId, (DWORD,))

def GetCurrentProcessId():
    return _GetCurrentProcessId()

################################################################################

_GetModuleHandle = fun_fact(_k32.GetModuleHandleW, (HANDLE, PWSTR))

def GetModuleHandle(mod_name):
    res = _GetModuleHandle(mod_name)
    raise_on_zero(res)
    return res

################################################################################

_WaitForSingleObject = fun_fact(
    _k32.WaitForSingleObject, (DWORD, HANDLE, DWORD)
    )

def WaitForSingleObject(handle, timeout):
    res = _WaitForSingleObject(handle, timeout)
    raise_if(res == WAIT_FAILED)
    return res

################################################################################

_OpenProcess = fun_fact(
    _k32.OpenProcess, (HANDLE, DWORD, BOOL, DWORD)
    )

def OpenProcess(desired_acc, inherit, pid):
    res = KHANDLE(_OpenProcess(desired_acc, inherit, pid))
    res.raise_on_invalid()
    return res

################################################################################

_TerminateProcess = fun_fact(
    _k32.TerminateProcess, (BOOL, HANDLE, UINT)
    )

def TerminateProcess(handle, exit_code):
    raise_on_zero(_TerminateProcess(handle, exit_code))

################################################################################

_QueryDosDevice = fun_fact(
    _k32.QueryDosDeviceW, (DWORD, PWSTR, PWSTR, DWORD)
    )

def QueryDosDevice(device_name):
    size = 512
    buf = ctypes.create_unicode_buffer(size)
    while True:
        res = _QueryDosDevice(device_name, buf, size)
        if res:
            return buf.value[:res]
        raise_if(GetLastError() != ERROR_INSUFFICIENT_BUFFER)
        size *= 2
        buf = ctypes.create_unicode_buffer(size)

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

def AdjustTime(SecondsToAdjust):
    ft = GetSystemTimeAsFileTime()
    ft += int(SecondsToAdjust * 1e7)
    st = FileTimeToSystemTime(ft)
    raise_on_zero(_k32.SetSystemTime(ref(st)))

################################################################################

def GetCurrentThreadId():
    return _k32.GetCurrentThreadId()

################################################################################

def GetFileAttributes(fname):
    res = _k32.GetFileAttributesW(fname)
    raise_if(res == INVALID_FILE_ATTRIBUTES)
    return res

################################################################################

_SetFileAttributes = fun_fact(
    _k32.SetFileAttributesW, (BOOL, PWSTR, DWORD)
    )

################################################################################

def SetFileAttributes(fname, attribs):
    raise_on_zero(_SetFileAttributes(fname, attribs))

################################################################################

_GetACP = fun_fact(_k32.GetACP, (DWORD,))

def GetACP():
    return _GetACP()

def get_ansi_encoding():
    return f"cp{GetACP()}"

################################################################################

_OutputDebugStringW = fun_fact(_k32.OutputDebugStringW, (None, PWSTR))

def OutputDebugString(dstr):
    _OutputDebugStringW(dstr)

################################################################################

_SetThreadExecutionState = fun_fact(
    _k32.SetThreadExecutionState, (DWORD, DWORD)
    )

def SetThreadExecutionState(es_flags):
    return _SetThreadExecutionState(es_flags)

################################################################################

_GetPrivateProfileSectionNames = fun_fact(
    _k32.GetPrivateProfileSectionNamesW,
    (DWORD, PWSTR, DWORD, PWSTR)
    )

def GetPrivateProfileSectionNames(filename):
    size = 512
    buf = ctypes.create_unicode_buffer(size)
    res = _GetPrivateProfileSectionNames(buf, size, filename)
    while res == size - 2:
        size *= 2
        buf = ctypes.create_unicode_buffer(size)
        res = _GetPrivateProfileSectionNames(buf, size, filename)
    return buf[:res].split('\0')[:-1]

################################################################################

_GetPrivateProfileSection = fun_fact(
    _k32.GetPrivateProfileSectionW,
    (DWORD, PWSTR, PWSTR, DWORD, PWSTR)
    )

def GetPrivateProfileSection(secname, filename):
    size = 512
    buf = ctypes.create_unicode_buffer(size)
    res = _GetPrivateProfileSection(secname, buf, size, filename)
    while res == size - 2:
        size *= 2
        buf = ctypes.create_unicode_buffer(size)
        res = _GetPrivateProfileSection(secname, buf, size, filename)
    entries = buf[:res].split('\0')[:-1]
    d = _collections.OrderedDict()
    for e in entries:
        k, v = e.split('=', 1)
        d[k] = v
    return d

################################################################################

_WritePrivateProfileSection = fun_fact(
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
    # quote from https://bugs.python.org/issue32745 concerning CPython versions
    # up to 3.9:
    #   "PyUnicode_AsWideCharString was updated to raise ValueError for
    #    embedded nulls if the 'size' output parameter is NULL."
    # That's why we need to detour 'secdata' through a unicode buffer. Since
    # py310 that would no longer be necessary (ctypes was fixed).
    buf = ctypes.create_unicode_buffer(secdata, len(secdata))
    raise_on_zero(_WritePrivateProfileSection(secname, buf, filename))

################################################################################

_GetEnvironmentVariable = fun_fact(
    _k32.GetEnvironmentVariableW,
    (DWORD, PWSTR, PWSTR, DWORD)
    )

def GetEnvironmentVariable(name):
    size = 512
    while True:
        var = ctypes.create_unicode_buffer(size)
        req = _GetEnvironmentVariable(name, var, size)
        raise_on_zero(req)
        if req <= size:
            break
        else:
            size = req
    return var.value

################################################################################

_SetEnvironmentVariable = fun_fact(
    _k32.SetEnvironmentVariableW,
    (BOOL, PWSTR, PWSTR)
    )

def SetEnvironmentVariable(name, value):
    raise_on_zero(_SetEnvironmentVariable(name, value))

################################################################################

# using void pointers instead of PWSTR so we can do pointer arithmatic.

_FreeEnvironmentStrings = fun_fact(
    _k32.FreeEnvironmentStringsW,
    (BOOL, PVOID)
    )

_GetEnvironmentStrings = fun_fact(_k32.GetEnvironmentStringsW, (PVOID,))

def GetEnvironmentStrings():
    ptr = _GetEnvironmentStrings()
    raise_on_zero(ptr)
    try:
        return multi_str_from_addr(ptr)
    finally:
        raise_on_zero(_FreeEnvironmentStrings(ptr))

def env_str_to_dict(estr):
    return dict(s.split("=", 1) for s in estr.strip("\0").split("\0"))

def get_env_as_dict():
    return env_str_to_dict(GetEnvironmentStrings())

################################################################################

_SetEnvironmentStrings = fun_fact(
    _k32.SetEnvironmentStringsW,
    (BOOL, PWSTR)
    )

def SetEnvironmentStrings(strings):
    # see comment on PyUnicode_AsWideCharString above
    buf = ctypes.create_unicode_buffer(strings, len(strings))
    raise_on_zero(_SetEnvironmentStrings(buf))

################################################################################

_ExpandEnvironmentStrings = fun_fact(
    _k32.ExpandEnvironmentStringsW,
    (DWORD, PWSTR, PWSTR, DWORD)
    )

def ExpandEnvironmentStrings(template):
    size = len(template)
    while True:
        var = ctypes.create_unicode_buffer(size)
        req = _ExpandEnvironmentStrings(template, var, size)
        raise_on_zero(req)
        if req <= size:
            break
        else:
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

_InitializeProcThreadAttributeList = fun_fact(
    _k32.InitializeProcThreadAttributeList,
    (BOOL, PVOID, DWORD, DWORD, PSIZE_T)
    )

def InitializeProcThreadAttributeList(alst, acnt, flags, size=0):
    size = SIZE_T(size)
    ok = _InitializeProcThreadAttributeList(alst, acnt, flags, ref(size))
    raise_if(not ok and alst)
    return size.value

################################################################################

_UpdateProcThreadAttribute = fun_fact(
    _k32.UpdateProcThreadAttribute,
    (BOOL, PVOID, DWORD, UINT_PTR, PVOID, SIZE_T, PVOID, PSIZE_T)
    )

def UpdateProcThreadAttribute(alst, flags, id, attr):
    size = SIZE_T(ctypes.sizeof(attr))
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

_DeleteProcThreadAttributeList = fun_fact(
    _k32.DeleteProcThreadAttributeList, (None, PVOID)
    )

def DeleteProcThreadAttributeList(alst):
    _DeleteProcThreadAttributeList(alst)

################################################################################

class ProcThreadAttributeList:
    def __init__(self, attr_pairs):
        self.buf = None
        size = InitializeProcThreadAttributeList(None, len(attr_pairs), 0)
        buf = ctypes.create_string_buffer(size)
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

_CreateProcess = fun_fact(
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

_GetSystemDirectory = fun_fact(_k32.GetSystemDirectoryW, (UINT, PWSTR, UINT))

def GetSystemDirectory():
    buf_size = 256
    buf = ctypes.create_unicode_buffer(buf_size)
    req_size = _GetSystemDirectory(buf, buf_size)
    if req_size <= buf_size:
        return buf.value
    buf = ctypes.create_unicode_buffer(req_size)
    req_size = _GetSystemDirectory(buf, buf_size)
    raise_if(req_size > buf_size)
    return buf.value

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

_CreateActCtx = fun_fact(_k32.CreateActCtxW, (HANDLE, PACTCTX))

def CreateActCtx(actctx):
    res = _CreateActCtx(ref(actctx))
    raise_if(res == INVALID_HANDLE_VALUE)
    return res

################################################################################

_ActivateActCtx = fun_fact(_k32.ActivateActCtx, (BOOL, HANDLE, PULONG_PTR))

def ActivateActCtx(ctx):
    cookie = ULONG_PTR()
    raise_on_zero(_ActivateActCtx(ctx, ref(cookie)))
    return cookie.value

################################################################################

_DeactivateActCtx = fun_fact(_k32.DeactivateActCtx, (BOOL, DWORD, ULONG_PTR))

def DeactivateActCtx(flags, cookie):
    raise_on_zero(_DeactivateActCtx(flags, cookie))

################################################################################

ReleaseActCtx = fun_fact(_k32.ReleaseActCtx, (None, HANDLE))

################################################################################

_GlobalAddAtom = fun_fact(_k32.GlobalAddAtomW, (WORD, PWSTR))

def GlobalAddAtom(name):
    atom = _GlobalAddAtom(name)
    raise_on_zero(atom)
    return atom

################################################################################

def global_add_atom(name):
    return ctypes.cast(GlobalAddAtom(name), PWSTR)

################################################################################

GlobalDeleteAtom = fun_fact(_k32.GlobalDeleteAtom, (None, WORD))

################################################################################

_GlobalGetAtomName = fun_fact(_k32.GlobalGetAtomNameW, (UINT, WORD, PWSTR, INT))

def GlobalGetAtomName(atom):
    size = 512
    while True:
        var = ctypes.create_unicode_buffer(size)
        req = _GlobalGetAtomName(atom, var, size)
        raise_on_zero(req)
        if req <= size:
            break
        else:
            size = req
    return var.value

################################################################################

_FreeLibrary = fun_fact(_k32.FreeLibrary, (BOOL, HANDLE))

def FreeLibrary(hmod):
    raise_on_zero(_FreeLibrary(hmod))

################################################################################

class HMODULE(ScdToBeClosed, HANDLE, close_func=FreeLibrary, invalid=0):
    pass

################################################################################

_LoadLibraryEx = fun_fact(_k32.LoadLibraryExW, (HANDLE, PWSTR, HANDLE, DWORD))

def LoadLibraryEx(filename, flags=0):
    hmod = HMODULE(_LoadLibraryEx(filename, None, flags))
    hmod.raise_on_invalid()
    return hmod

def LoadLibrary(filename):
    return LoadLibraryEx(filename, 0)

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
    typ = typ if not (typ >> 16) else ctypes.wstring_at(typ)
    name = name if not (name >> 16) else ctypes.wstring_at(name)
    cbc = ctxt.contents
    res = cbc.callback(hmod, typ, name, cbc.context)
    # keep on enumerating if the callback fails to return a value
    return res if res is not None else True


_EnumResourceNames = fun_fact(
    _k32.EnumResourceNamesW,
    (BOOL, HANDLE, PWSTR, _EnumResNameCallback, CallbackContextPtr)
    )

def EnumResourceNames(hmod, typ, callback, context):
    cbc = CallbackContext(callback, context)
    if not _EnumResourceNames(hmod, typ, _EnumResNameCb, ref(cbc)):
        err = GetLastError()
        if err != ERROR_RESOURCE_ENUM_USER_STOP:
            raise ctypes.WinError(err)

################################################################################

def get_resource_names(hmod, typ):
    names = []

    @_EnumResNameCallback
    def collect(not_used1, not_used2, name, not_used3):
        if name >= 0x10000:
            name = PWSTR(name).value
        names.append(name)
        return True

    raise_on_zero(_EnumResourceNames(hmod, typ, collect, None))
    return names

################################################################################

_FindResource = fun_fact(
    _k32.FindResourceW, (HANDLE, HANDLE, PWSTR, PWSTR)
    )

def FindResource(hmod, name, typ):
    name = name if isinstance(name, PWSTR) else PWSTR(name)
    typ = typ if isinstance(typ, PWSTR) else PWSTR(typ)
    res = _FindResource(hmod, name, typ)
    raise_on_zero(res)
    return res

################################################################################

_SizeofResource = fun_fact(_k32.SizeofResource, (DWORD, HANDLE, HANDLE))

def SizeofResource(hmod, hrsc):
    res = _SizeofResource(hmod, hrsc)
    raise_on_zero(res)
    return res

################################################################################

_LoadResource = fun_fact(_k32.LoadResource, (PVOID, HANDLE, HANDLE))

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
        ("Text", BYTE), # in fact an array of (Length - offsetof(Text)) bytes
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
        ("Blocks", MESSAGE_RESOURCE_BLOCK), # in fact an array of NumberOfBlocks
    )

def load_message_string(hmod, msg_id):
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
                    return msg.strip('\0')

    raise ctypes.WinError(ERROR_RESOURCE_NAME_NOT_FOUND)

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

_GetSystemInfo = fun_fact(_k32.GetSystemInfo, (None, PSYSTEM_INFO))

def GetSystemInfo():
    si = SYSTEM_INFO()
    _GetSystemInfo(ref(si))
    return ns_from_struct(si)

################################################################################
