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

import ctypes as _ct
from enum import IntFlag as _int_flag
from types import SimpleNamespace as _namespace
from collections import defaultdict as _defdict

from .wtypes import *
from . import (
    kernel,
    _fun_fact,
    ERROR_FILE_NOT_FOUND,
    ERROR_NO_MORE_FILES,
    SystemProcessInformation,
    SystemProcessIdInformation,
    SystemExtendedHandleInformation,
    ProcessImageFileName,
    ProcessBasicInformation,
    )

_nt = _ct.windll.ntdll
_ref = _ct.byref

def _ntstatus(status):
    return LONG(status).value

STATUS_INFO_LENGTH_MISMATCH = _ntstatus(0xC0000004)
STATUS_BUFFER_OVERFLOW = _ntstatus(0x80000005)
STATUS_BUFFER_TOO_SMALL = _ntstatus(0xC0000023)

################################################################################

_RtlNtStatusToDosError = _fun_fact(
    _nt.RtlNtStatusToDosError, (ULONG, LONG)
    )

def RtlNtStatusToDosError(status):
    winerr = _RtlNtStatusToDosError(status)
    return winerr if winerr < 65536 else status

################################################################################

def _raise_failed_status(status):
    if status < 0:
        raise _ct.WinError(RtlNtStatusToDosError(status))

################################################################################

class UNICODE_STRING(_ct.Structure):
    _fields_ = (
        ("Length", WORD),
        ("MaximumLength", WORD),
        ("Buffer", PWSTR),
        )

PUNICODE_STRING = _ct.POINTER(UNICODE_STRING)

################################################################################

class SYSTEM_PROCESS_ID_INFORMATION(_ct.Structure):
    _fields_ = (
        ("ProcessId", HANDLE),
        ("ImageName", UNICODE_STRING),
        )

################################################################################

class SYSTEM_PROCESS_INFORMATION(_ct.Structure):
    "this is just a partial definition"
    _fields_ = (
    ("NextEntryOffset", ULONG),
    ("NumberOfThreads", ULONG),
    ("WorkingSetPrivateSize", LARGE_INTEGER),
    ("HardFaultCount", ULONG),
    ("NumberOfThreadsHighWatermark", ULONG),
    ("CycleTime", ULARGE_INTEGER),
    ("CreateTime", LARGE_INTEGER),
    ("UserTime", LARGE_INTEGER),
    ("KernelTime", LARGE_INTEGER),
    ("ImageName", UNICODE_STRING), # file name only, no path
    ("BasePriority", LONG),
    ("UniqueProcessId", HANDLE),
    ("InheritedFromUniqueProcessId", HANDLE),
    ("HandleCount", ULONG),
    ("SessionId", ULONG),
    ("UniqueProcessKey", UINT_PTR),
    )

################################################################################

class CLIENT_ID(_ct.Structure):
    _fields_ = (
        ("UniqueProcess", LONG_PTR),
        ("UniqueThread", LONG_PTR)
        )

################################################################################

class SYSTEM_HANDLE_TABLE_ENTRY_INFO(_ct.Structure):
    _fields_ = (
        ("Object", PVOID),
        ("UniqueProcessId", UINT_PTR),
        ("HandleValue", UINT_PTR),
        ("GrantedAccess", ULONG),
        ("CreatorBackTraceIndex", WORD),
        ("ObjectTypeIndex", WORD),
        ("HandleAttributes", ULONG),
        ("Reserved", ULONG),
        )

################################################################################

class PROCESS_BASIC_INFORMATION(_ct.Structure):
    _fields_ = (
        ("ExitStatus", INT),
        ("PebBaseAddress", LONG_PTR),
        ("AffinityMask", LONG_PTR),
        ("BasePriority", INT),
        ("UniqueProcessId", LONG_PTR),
        ("InheritedFromUniqueProcessId", LONG_PTR)
        )

################################################################################

class PROCESS_EXTENDED_BASIC_INFORMATION(_ct.Structure):
    _fields_ = (
        ("Size", LONG_PTR),
        ("BasicInfo", PROCESS_BASIC_INFORMATION),
        ("Flags", INT)
        )
    def __init__(self):
        self.Size = _ct.sizeof(self)

class PROCESS_EXTENDED_BASIC_FLAGS(_int_flag):
    IsProtectedProcess   = 1
    IsWow64Process       = 2
    IsProcessDeleting    = 4
    IsCrossSessionCreate = 8
    IsFrozen             = 16
    IsBackground         = 32
    IsStronglyNamed      = 64
    IsSecureProcess      = 128
    IsSubsystemProcess   = 256

################################################################################

class OBJECT_ATTRIBUTES(_ct.Structure):
    _fields_ = (
        ("Length", ULONG),
        ("RootDirectory", HANDLE),
        ("ObjectName", PUNICODE_STRING),
        ("Attributes", ULONG),
        ("SecurityDescriptor", PVOID),
        ("SecurityQualityOfService", PVOID)
        )

    def __init__(self):
        self.Length = _ct.sizeof(self)

################################################################################

def _make_handle_info(num_entries):
    class _handle_info_t(_ct.Structure):
        _fields_ = (
            ("NumberOfHandles", UINT_PTR),
            ("Reserved", UINT_PTR),
            ("Handles", SYSTEM_HANDLE_TABLE_ENTRY_INFO * num_entries)
            )
    return _handle_info_t()

################################################################################

_NtClose = _fun_fact(_nt.NtClose, (ULONG, PVOID))
_NtClose.restype = ULONG

def NtClose(handle):
    _raise_failed_status(_NtClose(handle))

################################################################################

_NtOpenProcess = _fun_fact(
    _nt.NtOpenProcess,
    (ULONG, PVOID, ULONG, PVOID, PVOID)
    )

def NtOpenProcess(pid, desired_access):
    cid = CLIENT_ID()
    cid.UniqueProcess = pid
    h = HANDLE()
    oa = OBJECT_ATTRIBUTES()
    s = _NtOpenProcess(_ref(h), desired_access, _ref(oa), _ref(cid))
    _raise_failed_status(s)
    return h

################################################################################

_RtlAdjustPrivilege = _fun_fact(
    _nt.RtlAdjustPrivilege,
    (LONG, ULONG, BOOLEAN, BOOLEAN, PBOOLEAN)
    )

def RtlAdjustPrivilege(priv, enable, thread_priv=False):
    prev = BOOLEAN()
    status = _RtlAdjustPrivilege(priv, enable, thread_priv, _ref(prev))
    _raise_failed_status(status)
    return bool(prev)

################################################################################

_NtQuerySystemInformation = _fun_fact(
    _nt.NtQuerySystemInformation,
    (LONG, LONG, PVOID, ULONG, PULONG)
    )

def NtQuerySystemInformation(sys_info, buf, buf_size, p_ret_len):
    return _NtQuerySystemInformation(sys_info, buf, buf_size, p_ret_len)

################################################################################

_NtQueryInformationProcess = _fun_fact(
    _nt.NtQueryInformationProcess,
    (ULONG, PVOID, LONG, PVOID, ULONG, PVOID)
    )

def NtQueryInformationProcess(phandle, pinfo, buf, buf_size, p_ret_len):
    return _NtQueryInformationProcess(phandle, pinfo, buf, buf_size, p_ret_len)

################################################################################

def required_sys_info_size(sys_info):
    size = ULONG(0)
    NtQuerySystemInformation(sys_info, 0, size, _ref(size))
    return size

################################################################################

def required_proc_info_size(handle, proc_info):
    size = ULONG(0)
    NtQueryInformationProcess(handle, proc_info, 0, size, _ref(size))
    return size

################################################################################

def enum_processes():
    def _name_pid(pi):
        pid = pi.UniqueProcessId if pi.UniqueProcessId else 0
        name = (
            _ct.wstring_at(pi.ImageName.Buffer, pi.ImageName.Length // 2)
            if pi.ImageName.Buffer else
            ("idle" if pid == 0 else "system")
            )
        return _namespace(name=name, pid=pid)

    res = []
    status = STATUS_INFO_LENGTH_MISMATCH
    while status == STATUS_INFO_LENGTH_MISMATCH:
        size = required_sys_info_size(SystemProcessInformation)
        buf = _ct.create_string_buffer(size.value)
        status = NtQuerySystemInformation(
            SystemProcessInformation,
            _ref(buf),
            size,
            _ref(size)
            )
    _raise_failed_status(status)

    pi = SYSTEM_PROCESS_INFORMATION.from_address(_ct.addressof(buf))
    res.append(_name_pid(pi))

    while True:
        offs = pi.NextEntryOffset
        if offs == 0:
            break
        pi = SYSTEM_PROCESS_INFORMATION.from_address(_ct.addressof(pi) + offs)
        res.append(_name_pid(pi))
    return res

################################################################################

def _resolve_device_prefix(fname):
    dos_devices = {}
    for dc in "abcdefghijklmnopqrstuvwxyz":
        dn = dc + ":"
        try:
            dos_devices[kernel.QueryDosDevice(dn)] = dn
        except OSError as e:
            if e.winerror != ERROR_FILE_NOT_FOUND:
                raise e

    for ddk in dos_devices.keys():
        if fname.startswith(ddk):
            fname = fname.replace(ddk, dos_devices[ddk], 1)
            break
    return fname

################################################################################

def proc_path_from_pid(pid):

    if pid == 0:
        return "idle"
    elif pid == 4:
        return "system"

    buf = _ct.create_unicode_buffer(512)
    size = _ct.sizeof(SYSTEM_PROCESS_ID_INFORMATION)
    spii = SYSTEM_PROCESS_ID_INFORMATION()
    spii.ProcessId = _ct.cast(pid, HANDLE)
    spii.ImageName.Length = 0
    spii.ImageName.MaximumLength = buf._length_
    spii.ImageName.Buffer = _ct.addressof(buf)

    while True:
        status = NtQuerySystemInformation(
            SystemProcessIdInformation,
            _ref(spii),
            size,
            None
            )
        if status != STATUS_INFO_LENGTH_MISMATCH:
            break

        # Required length is stored in MaximumLength.
        buf = _ct.create_unicode_buffer(spii.ImageName.MaximumLength)
        spii.ImageName.Buffer = _ct.addressof(buf)

    _raise_failed_status(status)
    return _resolve_device_prefix(buf.value)

################################################################################

def proc_path_from_handle(handle):
    info = ProcessImageFileName
    rlen = required_proc_info_size(handle, info)
    buf = _ct.create_string_buffer(rlen.value)
    _raise_failed_status(
        NtQueryInformationProcess(handle, info, _ref(buf), rlen, _ref(rlen))
        )
    return _resolve_device_prefix(
        _ct.wstring_at(_ct.addressof(buf) + _ct.sizeof(UNICODE_STRING))
        )

################################################################################

def get_handles(pid=-1):
    info = SystemExtendedHandleInformation
    hi = _make_handle_info(1)
    rlen = ULONG(0)
    _NtQuerySystemInformation(info, _ref(hi), _ct.sizeof(hi), _ref(rlen))
    hi = _make_handle_info(hi.NumberOfHandles)
    _raise_failed_status(
        _NtQuerySystemInformation(info, _ref(hi), _ct.sizeof(hi), _ref(rlen))
        )
    if pid == -1:
        return list(hi.Handles)
    else:
        return [h for h in hi.Handles if pid == h.UniqueProcessId]

################################################################################

def get_grouped_handles(pid=-1):
    grouped_handles = _defdict(list)
    for h in get_handles(pid):
        grouped_handles[h.UniqueProcessId].append(h)
    return grouped_handles

################################################################################

_NtGetNextProcess = _fun_fact(
    _nt.NtGetNextProcess,
    (ULONG, PVOID, UINT, UINT, INT, PVOID)
    )

def NtGetNextProcess(current, access, attribs=0, flags=0):
    nxt = HANDLE()
    _raise_failed_status(
        _NtGetNextProcess(current, access, attribs, flags, _ref(nxt))
        )
    return nxt

################################################################################

def get_proc_ext_basic_info(proc_handle):
    pebi = PROCESS_EXTENDED_BASIC_INFORMATION()
    rlen = ULONG(0)
    _raise_failed_status(
        NtQueryInformationProcess(
            proc_handle,
            ProcessBasicInformation,
            _ref(pebi),
            _ct.sizeof(pebi),
            _ref(rlen)
            )
        )
    return pebi

################################################################################

def pid_from_handle(handle):
    return get_proc_ext_basic_info(handle).BasicInfo.UniqueProcessId

################################################################################

class _DUMMY_STATUS_UNION(_ct.Union):
    _fields_ = (
        ("Status", LONG),
        ("Pointer", PVOID),
        )

class IO_STATUS_BLOCK(_ct.Structure):
    _anonymous_ = ("anon",)
    _fields_ = (
        ("anon", _DUMMY_STATUS_UNION),
        ("Information", UINT_PTR),
        )
PIO_STATUS_BLOCK = _ct.POINTER(IO_STATUS_BLOCK)

################################################################################

class FILE_DIRECTORY_INFORMATION(_ct.Structure):
    _fields_ = (
    ("NextEntryOffset", ULONG),
    ("FileIndex", ULONG),
    ("CreationTime", LARGE_INTEGER),
    ("LastAccessTime", LARGE_INTEGER),
    ("LastWriteTime", LARGE_INTEGER),
    ("ChangeTime", LARGE_INTEGER),
    ("EndOfFile", LARGE_INTEGER),
    ("AllocationSize", LARGE_INTEGER),
    ("FileAttributes", ULONG),
    ("FileNameLength", ULONG),
    ("FileName", WCHAR * 1),
    )
PFILE_DIRECTORY_INFORMATION = _ct.POINTER(FILE_DIRECTORY_INFORMATION)

################################################################################

_NtQueryDirectoryFile = _fun_fact(
    _nt.NtQueryDirectoryFile, (
        LONG,
        HANDLE,
        HANDLE,
        PVOID, # PIO_APC_ROUTINE
        PVOID,
        PIO_STATUS_BLOCK,
        PVOID,
        ULONG,
        INT,
        BOOLEAN,
        PUNICODE_STRING,
        BOOLEAN,
        )
    )

################################################################################

def get_directory_info(hdir, restart_scan):
    iosb = IO_STATUS_BLOCK()
    bsize = 256
    while True:
        buf = _ct.create_string_buffer(bsize)
        stat = _NtQueryDirectoryFile(
            hdir,
            None,
            None,
            None,
            _ref(iosb),
            buf,
            bsize,
            1, # FileDirectoryInformation
            False,
            None,
            restart_scan
            )
        too_short = (
            stat == STATUS_BUFFER_OVERFLOW
            or stat == STATUS_INFO_LENGTH_MISMATCH
            )
        if too_short:
            bsize *= 2
        else:
            break
    _raise_failed_status(stat)

    pv = _ct.cast(_ct.addressof(buf), PVOID)
    dinfo = _ct.cast(_ct.addressof(buf), PFILE_DIRECTORY_INFORMATION).contents
    name_addr = pv.value + FILE_DIRECTORY_INFORMATION.FileName.offset
    name = _ct.wstring_at(name_addr, dinfo.FileNameLength // 2)

    def la2dt(la):
        return kernel.FileTimeToLocalSystemTime(
            FILETIME(la)
            ).to_datetime()

    return _namespace(
        FileIndex=dinfo.FileIndex,
        CreationTime=la2dt(dinfo.CreationTime),
        LastAccessTime=la2dt(dinfo.LastAccessTime),
        LastWriteTime=la2dt(dinfo.LastWriteTime),
        ChangeTime=la2dt(dinfo.ChangeTime),
        EndOfFile=dinfo.EndOfFile,
        AllocationSize=dinfo.AllocationSize,
        FileAttributes=dinfo.FileAttributes,
        FileName=name,
        )

################################################################################

def enum_directory_info(hdir):
    restart_scan = True
    while True:
        try:
            info = get_directory_info(hdir, restart_scan)
            restart_scan = False
            yield info
        except OSError as e:
            if e.winerror == ERROR_NO_MORE_FILES:
                break
            else:
                raise

################################################################################
