################################################################################
#
# Copyright 2021-2024 Rocco Matano
# SPDX-License-Identifier: MIT
#
################################################################################

from enum import IntFlag as _int_flag
from types import SimpleNamespace as _namespace
from collections import defaultdict as _defdict

import ctypes
from .wtypes import (
    byte_buffer,
    string_buffer,
    BOOLEAN,
    BYTE,
    FILETIME,
    HANDLE,
    LARGE_INTEGER,
    LONG,
    LONG_PTR,
    INT,
    NTSTATUS,
    OSVERSIONINFOEX,
    PBOOLEAN,
    POINTER,
    POSVERSIONINFOEX,
    PULONG,
    PUNICODE_STRING,
    PVOID,
    UINT_PTR,
    ULARGE_INTEGER,
    ULONG,
    ULONG_PTR,
    UNICODE_STRING,
    WCHAR,
    WCHAR_SIZE,
    WinError,
    WORD,
    )
from . import (
    ref,
    kernel,
    fun_fact,
    ns_from_struct,
    suppress_winerr,
    ERROR_FILE_NOT_FOUND,
    ERROR_NO_MORE_FILES,
    SystemProcessInformation,
    SystemProcessIdInformation,
    SystemExtendedHandleInformation,
    ThreadBasicInformation,
    ProcessCommandLineInformation,
    ProcessImageFileName,
    ProcessBasicInformation,
    ProcessWow64Information,
    )

_nt = ctypes.WinDLL("ntdll.dll", use_last_error=True)

def _ntstatus(status):
    return LONG(status).value

################################################################################

RtlGetCurrentPeb = fun_fact(_nt.RtlGetCurrentPeb, (PVOID,))

################################################################################

STATUS_INFO_LENGTH_MISMATCH = _ntstatus(0xC0000004)
STATUS_BUFFER_OVERFLOW = _ntstatus(0x80000005)
STATUS_BUFFER_TOO_SMALL = _ntstatus(0xC0000023)
STATUS_INVALID_SIGNATURE = _ntstatus(0xC000A000)

################################################################################

_RtlNtStatusToDosError = fun_fact(
    _nt.RtlNtStatusToDosError, (ULONG, NTSTATUS)
    )

def RtlNtStatusToDosError(status):
    winerr = _RtlNtStatusToDosError(status)
    return winerr if winerr < 65536 else status

################################################################################

def raise_failed_status(status):
    if status < 0:
        raise WinError(RtlNtStatusToDosError(status))

################################################################################

class SYSTEM_PROCESS_ID_INFORMATION(ctypes.Structure):
    _fields_ = (
        ("ProcessId", HANDLE),
        ("ImageName", UNICODE_STRING),
        )

################################################################################

class SYSTEM_PROCESS_INFORMATION(ctypes.Structure):
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
        ("ImageName", UNICODE_STRING),  # file name only, no path
        ("BasePriority", LONG),
        ("UniqueProcessId", HANDLE),
        ("InheritedFromUniqueProcessId", HANDLE),
        ("HandleCount", ULONG),
        ("SessionId", ULONG),
        ("UniqueProcessKey", UINT_PTR),
        )

################################################################################

class SYSTEM_BASIC_INFORMATION(ctypes.Structure):
    _fields_ = (
        ("Reserved", ULONG),
        ("TimerResolution", ULONG),
        ("PageSize", ULONG),
        ("NumberOfPhysicalPages", ULONG),
        ("LowestPhysicalPageNumber", ULONG),
        ("HighestPhysicalPageNumber", ULONG),
        ("AllocationGranularity", ULONG),
        ("MinimumUserModeAddress", ULONG_PTR),
        ("MaximumUserModeAddress", ULONG_PTR),
        ("ActiveProcessorsAffinityMask", ULONG_PTR),
        ("NumberOfProcessors", BYTE),
        )

################################################################################

class SYSTEM_PROCESSOR_PERFORMANCE_INFORMATION(ctypes.Structure):
    _fields_ = (
        ("IdleTime", LARGE_INTEGER),
        ("KernelTime", LARGE_INTEGER),
        ("UserTime", LARGE_INTEGER),
        ("DpcTime", LARGE_INTEGER),
        ("InterruptTime", LARGE_INTEGER),
        ("InterruptCount", ULONG),
        )

################################################################################

class CLIENT_ID(ctypes.Structure):
    _fields_ = (
        ("UniqueProcess", LONG_PTR),
        ("UniqueThread", LONG_PTR)
        )

################################################################################

class SYSTEM_HANDLE_TABLE_ENTRY_INFO(ctypes.Structure):
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

class PROCESS_BASIC_INFORMATION(ctypes.Structure):
    _fields_ = (
        ("ExitStatus", INT),
        ("PebBaseAddress", LONG_PTR),
        ("AffinityMask", LONG_PTR),
        ("BasePriority", INT),
        ("UniqueProcessId", LONG_PTR),
        ("InheritedFromUniqueProcessId", LONG_PTR)
        )

################################################################################

class PROCESS_EXTENDED_BASIC_INFORMATION(ctypes.Structure):
    _fields_ = (
        ("Size", LONG_PTR),
        ("BasicInfo", PROCESS_BASIC_INFORMATION),
        ("Flags", INT)
        )

    def __init__(self):
        self.Size = ctypes.sizeof(self)

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

class OBJECT_ATTRIBUTES(ctypes.Structure):
    _fields_ = (
        ("Length", ULONG),
        ("RootDirectory", HANDLE),
        ("ObjectName", PUNICODE_STRING),
        ("Attributes", ULONG),
        ("SecurityDescriptor", PVOID),
        ("SecurityQualityOfService", PVOID)
        )

    def __init__(self):
        self.Length = ctypes.sizeof(self)

################################################################################

def _make_handle_info(num_entries):
    class _handle_info_t(ctypes.Structure):
        _fields_ = (
            ("NumberOfHandles", UINT_PTR),
            ("Reserved", UINT_PTR),
            ("Handles", SYSTEM_HANDLE_TABLE_ENTRY_INFO * num_entries)
            )
    return _handle_info_t()

################################################################################

_NtClose = fun_fact(_nt.NtClose, (NTSTATUS, PVOID))

def NtClose(handle):
    raise_failed_status(_NtClose(handle))

################################################################################

_NtOpenProcess = fun_fact(
    _nt.NtOpenProcess,
    (NTSTATUS, PVOID, ULONG, PVOID, PVOID)
    )

def NtOpenProcess(pid, desired_access):
    cid = CLIENT_ID()
    cid.UniqueProcess = pid
    h = HANDLE()
    oa = OBJECT_ATTRIBUTES()
    s = _NtOpenProcess(ref(h), desired_access, ref(oa), ref(cid))
    raise_failed_status(s)
    return h

################################################################################

_RtlAdjustPrivilege = fun_fact(
    _nt.RtlAdjustPrivilege,
    (NTSTATUS, ULONG, BOOLEAN, BOOLEAN, PBOOLEAN)
    )

def RtlAdjustPrivilege(priv, enable, thread_priv=False):
    prev = BOOLEAN()
    status = _RtlAdjustPrivilege(priv, enable, thread_priv, ref(prev))
    raise_failed_status(status)
    return bool(prev)

################################################################################

_NtQuerySystemInformation = fun_fact(
    _nt.NtQuerySystemInformation,
    (NTSTATUS, LONG, PVOID, ULONG, PULONG)
    )

def NtQuerySystemInformation(sys_info, buf, buf_size, p_ret_len):
    return _NtQuerySystemInformation(sys_info, buf, buf_size, p_ret_len)

################################################################################

_NtQueryInformationProcess = fun_fact(
    _nt.NtQueryInformationProcess,
    (NTSTATUS, PVOID, LONG, PVOID, ULONG, PVOID)
    )

def NtQueryInformationProcess(phandle, pinfo, buf, buf_size, p_ret_len):
    return _NtQueryInformationProcess(phandle, pinfo, buf, buf_size, p_ret_len)

################################################################################

def _var_size_proc_info(proc_handle, proc_info):
    # This works only for the few information classes that return variable
    # size items (50, 51, 60, 64, 85, 97). Those that deliver fixed size items
    # cannot be queried for the required size.
    size = ULONG(0)
    NtQueryInformationProcess(proc_handle, proc_info, 0, size, ref(size))
    buff = byte_buffer(size.value)
    raise_failed_status(
        NtQueryInformationProcess(proc_handle, proc_info, buff, size, ref(size))
        )
    return buff

################################################################################

def _fixed_size_proc_info(proc_handle, proc_info, dest):
    size = ctypes.sizeof(dest)
    raise_failed_status(
        NtQueryInformationProcess(proc_handle, proc_info, ref(dest), size, None)
        )

################################################################################

def enum_processes():
    def name_pid(pi):
        return _namespace(
            name=(
                str(pi.ImageName) if pi.ImageName.Buffer else
                ("idle" if not pi.UniqueProcessId else "system")
                ),
            pid=pi.UniqueProcessId or 0
            )

    status = STATUS_INFO_LENGTH_MISMATCH
    while status == STATUS_INFO_LENGTH_MISMATCH:
        size = ULONG(0)
        NtQuerySystemInformation(SystemProcessInformation, 0, 0, ref(size))
        buf = byte_buffer(size.value)
        status = NtQuerySystemInformation(
            SystemProcessInformation,
            ref(buf),
            size,
            ref(size)
            )
    raise_failed_status(status)

    offs = 0
    pi = SYSTEM_PROCESS_INFORMATION.from_buffer(buf, offs)
    res = [name_pid(pi)]

    while pi.NextEntryOffset:
        offs += pi.NextEntryOffset
        pi = SYSTEM_PROCESS_INFORMATION.from_buffer(buf, offs)
        res.append(name_pid(pi))
    return res

################################################################################

def _resolve_device_prefix(fname):
    dos_devices = {}
    for dc in "abcdefghijklmnopqrstuvwxyz":
        dn = dc + ":"
        with suppress_winerr(ERROR_FILE_NOT_FOUND):
            dos_devices[kernel.QueryDosDevice(dn)] = dn

    for ddk in dos_devices:
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

    buf = string_buffer(512)
    size = ctypes.sizeof(SYSTEM_PROCESS_ID_INFORMATION)
    spii = SYSTEM_PROCESS_ID_INFORMATION()
    spii.ProcessId = ctypes.cast(pid, HANDLE)
    spii.ImageName.Length = 0
    spii.ImageName.MaximumLength = buf._length_
    spii.ImageName.Buffer = ctypes.addressof(buf)

    while True:
        status = NtQuerySystemInformation(
            SystemProcessIdInformation,
            ref(spii),
            size,
            None
            )
        if status != STATUS_INFO_LENGTH_MISMATCH:
            break

        # Required length is stored in MaximumLength.
        buf = string_buffer(spii.ImageName.MaximumLength)
        spii.ImageName.Buffer = ctypes.addressof(buf)

    raise_failed_status(status)
    return _resolve_device_prefix(str(spii.ImageName))

################################################################################

def proc_path_from_handle(handle):
    buf = _var_size_proc_info(handle, ProcessImageFileName)
    return _resolve_device_prefix(str(UNICODE_STRING.from_buffer(buf)))

################################################################################

def get_handles(pid=-1):
    info = SystemExtendedHandleInformation
    hi = _make_handle_info(1)
    rlen = ULONG(0)
    while True:
        _NtQuerySystemInformation(info, ref(hi), ctypes.sizeof(hi), ref(rlen))
        hi = _make_handle_info(hi.NumberOfHandles)
        status = _NtQuerySystemInformation(
            info,
            ref(hi),
            ctypes.sizeof(hi),
            ref(rlen)
            )
        if status == STATUS_INFO_LENGTH_MISMATCH:
            continue
        raise_failed_status(status)
        if pid == -1:
            return list(hi.Handles)
        return [h for h in hi.Handles if pid == h.UniqueProcessId]

################################################################################

def get_grouped_handles(pid=-1):
    grouped_handles = _defdict(list)
    for h in get_handles(pid):
        grouped_handles[h.UniqueProcessId].append(h)
    return grouped_handles

################################################################################

_NtGetNextProcess = fun_fact(
    _nt.NtGetNextProcess,
    (NTSTATUS, PVOID, ULONG, ULONG, ULONG, PVOID)
    )

def NtGetNextProcess(current, access, attribs=0, flags=0):
    nxt = HANDLE()
    # have to ignore returned NTSTATUS, success/failure is conveyed by the
    # nxt handle
    _NtGetNextProcess(current, access, attribs, flags, ref(nxt))
    return nxt.value

################################################################################

def get_proc_ext_basic_info(proc_handle):
    pebi = PROCESS_EXTENDED_BASIC_INFORMATION()
    _fixed_size_proc_info(proc_handle, ProcessBasicInformation, pebi)
    return pebi

################################################################################

def pid_from_handle(proc_handle):
    return get_proc_ext_basic_info(proc_handle).BasicInfo.UniqueProcessId

################################################################################

class _DUMMY_STATUS_UNION(ctypes.Union):
    _fields_ = (
        ("Status", LONG),
        ("Pointer", PVOID),
        )

class IO_STATUS_BLOCK(ctypes.Structure):
    _anonymous_ = ("anon",)
    _fields_ = (
        ("anon", _DUMMY_STATUS_UNION),
        ("Information", UINT_PTR),
        )
PIO_STATUS_BLOCK = POINTER(IO_STATUS_BLOCK)

################################################################################

class FILE_DIRECTORY_INFORMATION(ctypes.Structure):
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

PFILE_DIRECTORY_INFORMATION = POINTER(FILE_DIRECTORY_INFORMATION)

################################################################################

_NtQueryDirectoryFile = fun_fact(
    _nt.NtQueryDirectoryFile, (
        NTSTATUS,
        HANDLE,
        HANDLE,
        PVOID,  # PIO_APC_ROUTINE
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
    bsize = 1024
    while True:
        buf = byte_buffer(bsize)
        stat = _NtQueryDirectoryFile(
            hdir,
            None,
            None,
            None,
            ref(iosb),
            buf,
            bsize,
            1,  # FileDirectoryInformation
            False,
            None,
            restart_scan
            )
        if stat in (STATUS_BUFFER_OVERFLOW, STATUS_INFO_LENGTH_MISMATCH):
            bsize *= 2
        else:
            break
    raise_failed_status(stat)

    def extract_info(addr):
        def la2dt(la):
            return kernel.FileTimeToLocalSystemTime(
                FILETIME(la)
                ).to_datetime()

        info = FILE_DIRECTORY_INFORMATION.from_address(addr)
        name = ctypes.wstring_at(
            addr + FILE_DIRECTORY_INFORMATION.FileName.offset,
            info.FileNameLength // WCHAR_SIZE
            )
        nxt = addr + info.NextEntryOffset if info.NextEntryOffset else 0
        return nxt, _namespace(
            FileIndex=info.FileIndex,
            CreationTime=la2dt(info.CreationTime),
            LastAccessTime=la2dt(info.LastAccessTime),
            LastWriteTime=la2dt(info.LastWriteTime),
            ChangeTime=la2dt(info.ChangeTime),
            EndOfFile=info.EndOfFile,
            AllocationSize=info.AllocationSize,
            FileAttributes=info.FileAttributes,
            FileName=name,
            )

    addr = ctypes.addressof(buf)
    while addr:
        addr, info = extract_info(addr)
        yield info

################################################################################

def enum_directory_info(hdir):
    restart_scan = True
    with suppress_winerr(ERROR_NO_MORE_FILES):
        while True:
            yield from get_directory_info(hdir, restart_scan)
            restart_scan = False

################################################################################

_RtlGetVersion = fun_fact(_nt.RtlGetVersion, (NTSTATUS, POSVERSIONINFOEX))

def RtlGetVersion():
    osve = OSVERSIONINFOEX()
    raise_failed_status(_RtlGetVersion(ref(osve)))
    return ns_from_struct(osve)

################################################################################

_NtPowerInformation = fun_fact(
    _nt.NtPowerInformation, (
        NTSTATUS,
        LONG,
        PVOID,
        ULONG,
        PVOID,
        ULONG,
        )
    )

def NtPowerInformation(pwr_info, in_bytes, out_len):
    if in_bytes is None:
        iptr, ilen = None, 0
    else:
        iptr, ilen = ref(in_bytes), len(in_bytes)

    if out_len is None or out_len == 0:
        out, optr, olen = byte_buffer(0), None, 0
    else:
        out = byte_buffer(out_len)
        optr, olen = ref(out), out_len

    raise_failed_status(_NtPowerInformation(pwr_info, iptr, ilen, optr, olen))
    return out

################################################################################

def get_proc_command_line(proc_handle):
    buf = _var_size_proc_info(proc_handle, ProcessCommandLineInformation)
    return str(UNICODE_STRING.from_buffer(buf))

################################################################################

def get_proc_env_blk(proc_handle):
    return get_proc_ext_basic_info(proc_handle).BasicInfo.PebBaseAddress

################################################################################

def get_wow64_proc_env_blk(proc_handle):
    peb32 = ULONG_PTR()
    _fixed_size_proc_info(proc_handle, ProcessWow64Information, peb32)
    return peb32.value

################################################################################

class THREAD_BASIC_INFORMATION(ctypes.Structure):
    _fields_ = (
        ("ExitStatus", LONG),
        ("TebBaseAddress", PVOID),
        ("ClientId", CLIENT_ID),
        ("AffinityMask", ULONG_PTR),
        ("Priority", LONG),
        ("BasePriority", LONG),
        )

################################################################################

_NtQueryInformationThread = fun_fact(
    _nt.NtQueryInformationThread,
    (NTSTATUS, PVOID, LONG, PVOID, ULONG, PVOID)
    )

def NtQueryInformationThread(hdl, tinfo, buf, buf_size, p_ret_len):
    return _NtQueryInformationThread(hdl, tinfo, buf, buf_size, p_ret_len)

################################################################################

def get_thread_basic_info(hdl):
    tbi = THREAD_BASIC_INFORMATION()
    size = ctypes.sizeof(tbi)
    raise_failed_status(
        NtQueryInformationThread(
            hdl,
            ThreadBasicInformation,
            ref(tbi),
            size,
            None
            )
        )
    return tbi

################################################################################

_NtGetNextThread = fun_fact(
    _nt.NtGetNextThread,
    (NTSTATUS, PVOID, PVOID, ULONG, ULONG, ULONG, PVOID)
    )

def NtGetNextThread(proc, cur_thrd, access, attribs=0, flags=0):
    nxt = HANDLE()
    _NtGetNextThread(proc, cur_thrd, access, attribs, flags, ref(nxt))
    return nxt.value

################################################################################
