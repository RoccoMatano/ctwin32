################################################################################
#
# Copyright 2021-2025 Rocco Matano
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
    Struct,
    Union,
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
    SIZE_T,
    UINT_PTR,
    ULARGE_INTEGER,
    ULONG,
    ULONG_PTR,
    UNICODE_STRING,
    UnicodeStrBuffer,
    WCHAR,
    WCHAR_SIZE,
    WinError,
    WORD,
    )
from . import (
    ApiDll,
    ref,
    kernel,
    ns_from_struct,
    suppress_winerr,
    wtypes,
    ERROR_NO_MORE_FILES,
    DIRECTORY_QUERY,
    GENERIC_READ,
    SystemProcessInformation,
    SystemProcessIdInformation,
    SystemExtendedHandleInformation,
    STATUS_BUFFER_OVERFLOW,
    STATUS_BUFFER_TOO_SMALL,
    STATUS_INFO_LENGTH_MISMATCH,
    STATUS_MORE_ENTRIES,
    STATUS_NO_MORE_ENTRIES,
    ThreadBasicInformation,
    ThreadPriority,
    ProcessCommandLineInformation,
    ProcessImageFileName,
    ProcessBasicInformation,
    ProcessWow64Information,
    )

_nt = ApiDll("ntdll.dll")

################################################################################

RtlGetCurrentPeb = _nt.fun_fact("RtlGetCurrentPeb", (PVOID,))

################################################################################

_RtlNtStatusToDosError = _nt.fun_fact(
    "RtlNtStatusToDosError",
    (ULONG, NTSTATUS)
    )

def RtlNtStatusToDosError(status):
    winerr = _RtlNtStatusToDosError(status)
    return winerr if winerr < 65536 else status

################################################################################

def raise_failed_status(status):
    if status < 0:
        raise WinError(RtlNtStatusToDosError(status))

################################################################################

class SYSTEM_PROCESS_ID_INFORMATION(Struct):
    _fields_ = (
        ("ProcessId", HANDLE),
        ("ImageName", UNICODE_STRING),
        )

################################################################################

class CLIENT_ID(Struct):
    _fields_ = (
        ("UniqueProcess", LONG_PTR),
        ("UniqueThread", LONG_PTR)
        )

################################################################################

class SYSTEM_THREAD_INFORMATION(Struct):
    _fields_ = (
        ("KernelTime", LARGE_INTEGER),
        ("UserTime", LARGE_INTEGER),
        ("CreateTime", LARGE_INTEGER),
        ("WaitTime", ULONG),
        ("StartAddress", PVOID),
        ("ClientId", CLIENT_ID),
        ("Priority", LONG),
        ("BasePriority", LONG),
        ("ContextSwitches", ULONG),
        ("ThreadState", INT),
        ("WaitReason", INT),
        )

################################################################################

class SYSTEM_PROCESS_INFORMATION(Struct):
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
        ("PeakVirtualSize", SIZE_T),
        ("VirtualSize", SIZE_T),
        ("PageFaultCount",  ULONG),
        ("PeakWorkingSetSize", SIZE_T),
        ("WorkingSetSize", SIZE_T),
        ("QuotaPeakPagedPoolUsage", SIZE_T),
        ("QuotaPagedPoolUsage", SIZE_T),
        ("QuotaPeakNonPagedPoolUsage", SIZE_T),
        ("QuotaNonPagedPoolUsage", SIZE_T),
        ("PagefileUsage", SIZE_T),
        ("PeakPagefileUsage", SIZE_T),
        ("PrivatePageCount", SIZE_T),
        ("ReadOperationCount", LARGE_INTEGER),
        ("WriteOperationCount", LARGE_INTEGER),
        ("OtherOperationCount", LARGE_INTEGER),
        ("ReadTransferCount", LARGE_INTEGER),
        ("WriteTransferCount", LARGE_INTEGER),
        ("OtherTransferCount", LARGE_INTEGER),
        )
        # At this point there is an array of
        # NumberOfThreads * SYSTEM_THREAD_INFORMATION.

################################################################################

class SYSTEM_BASIC_INFORMATION(Struct):
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

class SYSTEM_PROCESSOR_PERFORMANCE_INFORMATION(Struct):
    _fields_ = (
        ("IdleTime", LARGE_INTEGER),
        ("KernelTime", LARGE_INTEGER),
        ("UserTime", LARGE_INTEGER),
        ("DpcTime", LARGE_INTEGER),
        ("InterruptTime", LARGE_INTEGER),
        ("InterruptCount", ULONG),
        )

################################################################################

class SYSTEM_HANDLE_TABLE_ENTRY_INFO(Struct):
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

class PROCESS_BASIC_INFORMATION(Struct):
    _fields_ = (
        ("ExitStatus", INT),
        ("PebBaseAddress", LONG_PTR),
        ("AffinityMask", LONG_PTR),
        ("BasePriority", INT),
        ("UniqueProcessId", LONG_PTR),
        ("InheritedFromUniqueProcessId", LONG_PTR)
        )

################################################################################

class PROCESS_EXTENDED_BASIC_INFORMATION(Struct):
    _fields_ = (
        ("Size", LONG_PTR),
        ("BasicInfo", PROCESS_BASIC_INFORMATION),
        ("Flags", INT)
        )

    def __init__(self):
        self.Size = self._size_

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

class OBJECT_ATTRIBUTES(Struct):
    _fields_ = (
        ("Length", ULONG),
        ("RootDirectory", HANDLE),
        ("ObjectName", PUNICODE_STRING),
        ("Attributes", ULONG),
        ("SecurityDescriptor", PVOID),
        ("SecurityQualityOfService", PVOID)
        )

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.Length = self._size_

def obj_attr(name, root=None, attr=0):
    name = wtypes.UnicodeStrBuffer(name).ptr if name else None
    return OBJECT_ATTRIBUTES(0, root, name, attr)

################################################################################

def _make_handle_info(num_entries):
    class _handle_info_t(Struct):
        _fields_ = (
            ("NumberOfHandles", UINT_PTR),
            ("Reserved", UINT_PTR),
            ("Handles", SYSTEM_HANDLE_TABLE_ENTRY_INFO * num_entries)
            )
    return _handle_info_t()

################################################################################

_NtClose = _nt.fun_fact("NtClose", (NTSTATUS, PVOID))

def NtClose(handle):
    raise_failed_status(_NtClose(handle))

################################################################################

_NtOpenProcess = _nt.fun_fact(
    "NtOpenProcess",
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

_RtlAdjustPrivilege = _nt.fun_fact(
    "RtlAdjustPrivilege",
    (NTSTATUS, ULONG, BOOLEAN, BOOLEAN, PBOOLEAN)
    )

def RtlAdjustPrivilege(priv, enable, *, thread_priv=False):
    prev = BOOLEAN()
    status = _RtlAdjustPrivilege(priv, enable, thread_priv, ref(prev))
    raise_failed_status(status)
    return bool(prev)

################################################################################

_NtQuerySystemInformation = _nt.fun_fact(
    "NtQuerySystemInformation",
    (NTSTATUS, LONG, PVOID, ULONG, PULONG)
    )

def NtQuerySystemInformation(sys_info, buf, buf_size, p_ret_len):
    return _NtQuerySystemInformation(sys_info, buf, buf_size, p_ret_len)

################################################################################

_NtQueryInformationProcess = _nt.fun_fact(
    "NtQueryInformationProcess",
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

def _enum_proc_worker(extract_func):
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

    res = []
    pinfo_size = SYSTEM_PROCESS_INFORMATION._size_
    offs, offs_inc = 0, 1
    while offs_inc:
        pi = SYSTEM_PROCESS_INFORMATION.from_buffer(buf, offs)
        nt = pi.NumberOfThreads
        ti_addr = ctypes.addressof(pi) + pinfo_size
        ti = (SYSTEM_THREAD_INFORMATION * nt).from_address(ti_addr)
        res.append(extract_func(pi, ti))
        offs_inc = pi.NextEntryOffset
        offs += offs_inc
    return res

################################################################################

def _pi_img_name_to_str(pi):
    return (
        str(pi.ImageName) if pi.ImageName.Buffer else
        ("idle" if not pi.UniqueProcessId else "system")
        )

################################################################################

def _extract_basic_proc_info(pi, ti):
    return _namespace(
        name=_pi_img_name_to_str(pi),
        pid=pi.UniqueProcessId or 0,
        tids=[i.ClientId.UniqueThread for i in ti],
        )

################################################################################

def _extract_full_proc_info(pi, ti):
    pins = ns_from_struct(pi)
    pins.ImageName = _pi_img_name_to_str(pi)
    del pins.NextEntryOffset
    pins.Threads = [ns_from_struct(t) for t in ti]
    return pins

################################################################################

def enum_processes():
    return _enum_proc_worker(_extract_basic_proc_info)

################################################################################

def enum_processes_ex():
    return _enum_proc_worker(_extract_full_proc_info)

################################################################################

def _resolve_device_prefix(fname):
    gattr = obj_attr("\\GLOBAL??")
    with NtOpenDirectoryObject(DIRECTORY_QUERY, gattr) as glob:
        for prefix, typ in NtQueryDirectoryObject(glob):
            if len(prefix) != 2 or prefix[1] != ":" or typ != "SymbolicLink":
                continue
            lattr = obj_attr(prefix, glob)
            with NtOpenSymbolicLinkObject(GENERIC_READ, lattr) as hsl:
                link = NtQuerySymbolicLinkObject(hsl)
                if fname.startswith(link):
                    return fname.replace(link, prefix, 1)
    return fname

################################################################################

def proc_path_from_pid(pid):

    if pid == 0:
        return "idle"
    if pid == 4:
        return "system"

    buf = string_buffer(512)
    spii = SYSTEM_PROCESS_ID_INFORMATION()
    spii.ProcessId = ctypes.cast(pid, HANDLE)
    spii.ImageName.Length = 0
    spii.ImageName.MaximumLength = buf._length_
    spii.ImageName.Buffer = ctypes.addressof(buf)

    while True:
        status = NtQuerySystemInformation(
            SystemProcessIdInformation,
            ref(spii),
            spii._size_,
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
        _NtQuerySystemInformation(info, ref(hi), hi._size_, ref(rlen))
        hi = _make_handle_info(hi.NumberOfHandles)
        status = _NtQuerySystemInformation(
            info,
            ref(hi),
            hi._size_,
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

_NtGetNextProcess = _nt.fun_fact(
    "NtGetNextProcess",
    (NTSTATUS, PVOID, ULONG, ULONG, ULONG, PVOID)
    )

def NtGetNextProcess(current, access, attribs=0, flags=0):
    nxt = HANDLE()
    status = _NtGetNextProcess(current, access, attribs, flags, ref(nxt))
    if status == STATUS_NO_MORE_ENTRIES:
        return None
    raise_failed_status(status)
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

class _DUMMY_STATUS_UNION(Union):
    _fields_ = (
        ("Status", LONG),
        ("Pointer", PVOID),
        )

class IO_STATUS_BLOCK(Struct):
    _anonymous_ = ("anon",)
    _fields_ = (
        ("anon", _DUMMY_STATUS_UNION),
        ("Information", UINT_PTR),
        )
PIO_STATUS_BLOCK = POINTER(IO_STATUS_BLOCK)

################################################################################

class FILE_DIRECTORY_INFORMATION(Struct):
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

_NtQueryDirectoryFile = _nt.fun_fact(
    "NtQueryDirectoryFile", (
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

_RtlGetVersion = _nt.fun_fact("RtlGetVersion", (NTSTATUS, POSVERSIONINFOEX))

def RtlGetVersion():
    osve = OSVERSIONINFOEX()
    raise_failed_status(_RtlGetVersion(ref(osve)))
    return ns_from_struct(osve)

################################################################################

_NtPowerInformation = _nt.fun_fact(
    "NtPowerInformation", (
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

class THREAD_BASIC_INFORMATION(Struct):
    _fields_ = (
        ("ExitStatus", LONG),
        ("TebBaseAddress", PVOID),
        ("ClientId", CLIENT_ID),
        ("AffinityMask", ULONG_PTR),
        ("Priority", LONG),
        ("BasePriority", LONG),
        )

################################################################################

_NtQueryInformationThread = _nt.fun_fact(
    "NtQueryInformationThread",
    (NTSTATUS, PVOID, LONG, PVOID, ULONG, PVOID)
    )

def NtQueryInformationThread(thdl, tinfo, buf, buf_size, p_ret_len):
    return _NtQueryInformationThread(thdl, tinfo, buf, buf_size, p_ret_len)

################################################################################

def get_thread_basic_info(thdl):
    tbi = THREAD_BASIC_INFORMATION()
    raise_failed_status(
        NtQueryInformationThread(
            thdl,
            ThreadBasicInformation,
            ref(tbi),
            tbi._size_,
            None
            )
        )
    return tbi

################################################################################

_NtSetInformationThread = _nt.fun_fact(
    "NtSetInformationThread",
    (NTSTATUS, PVOID, LONG, PVOID, ULONG)
    )

def NtSetInformationThread(thdl, tinfo, ct_info_obj):
    raise_failed_status(
        _NtSetInformationThread(
            thdl,
            tinfo,
            ref(ct_info_obj),
            ctypes.sizeof(ct_info_obj)
            )
        )

################################################################################

# requires SeIncreaseBasePriorityPrivilege

def set_abs_thread_priority(thdl, prio):
    prio = ULONG(prio)
    NtSetInformationThread(thdl, ThreadPriority, prio)

################################################################################

def get_abs_thread_priority(thdl):
    tbi = get_thread_basic_info(thdl)
    return tbi.Priority

################################################################################

_NtGetNextThread = _nt.fun_fact(
    "NtGetNextThread",
    (NTSTATUS, PVOID, PVOID, ULONG, ULONG, ULONG, PVOID)
    )

def NtGetNextThread(proc, cur_thrd, access, attribs=0, flags=0):
    nxt = HANDLE()
    _NtGetNextThread(proc, cur_thrd, access, attribs, flags, ref(nxt))
    return nxt.value

################################################################################

_NtOpenDirectoryObject = _nt.fun_fact(
    "NtOpenDirectoryObject",
    (NTSTATUS, PVOID, ULONG, PVOID)
    )

def NtOpenDirectoryObject(acc, obj_attr):
    hdl = kernel.KHANDLE()
    raise_failed_status(_NtOpenDirectoryObject(ref(hdl), acc, ref(obj_attr)))
    return hdl

################################################################################

class OBJECT_DIRECTORY_INFORMATION(Struct):
    _fields_ = (
        ("Name", UNICODE_STRING),
        ("TypeName", UNICODE_STRING),
        )

################################################################################

_NtQueryDirectoryObject = _nt.fun_fact(
    "NtQueryDirectoryObject",
    (NTSTATUS, HANDLE, PVOID, ULONG, BOOLEAN, BOOLEAN, PULONG, PULONG)
    )

def NtQueryDirectoryObject(hdir):
    res = []
    bsize = 4096
    buf = byte_buffer(bsize)
    context = ULONG()
    rlen = ULONG()
    restart = True
    while True:
        stat = _NtQueryDirectoryObject(
            hdir,
            buf,
            bsize,
            False,
            restart,
            ref(context),
            ref(rlen)
            )
        if stat >= 0:
            addr = ctypes.addressof(buf)
            while True:
                info = OBJECT_DIRECTORY_INFORMATION.from_address(addr)
                if info.Name.Length == 0:
                    break
                res.append((str(info.Name), str(info.TypeName)))
                addr += info._size_
            restart = False
            if stat != STATUS_MORE_ENTRIES:
                break
        elif stat == STATUS_NO_MORE_ENTRIES:
            break
        else:
            raise_failed_status(stat)
    return res

################################################################################

_NtOpenSymbolicLinkObject = _nt.fun_fact(
    "NtOpenSymbolicLinkObject",
    (NTSTATUS, PVOID, ULONG, PVOID)
    )

def NtOpenSymbolicLinkObject(acc, obj_attr):
    hdl = kernel.KHANDLE()
    raise_failed_status(_NtOpenSymbolicLinkObject(ref(hdl), acc, ref(obj_attr)))
    return hdl

################################################################################

_NtQuerySymbolicLinkObject = _nt.fun_fact(
    "NtQuerySymbolicLinkObject",
    (NTSTATUS, HANDLE, PUNICODE_STRING, PULONG)
    )

def NtQuerySymbolicLinkObject(hdl):
    size = 256
    us = UnicodeStrBuffer(size)
    rlen = ULONG()
    while True:
        stat = _NtQuerySymbolicLinkObject(hdl, us.ptr, ref(rlen))
        if stat == STATUS_BUFFER_TOO_SMALL:
            size *= 2
            us = UnicodeStrBuffer(size)
        else:
            raise_failed_status(stat)
            return us.str

################################################################################

_NtQueryTimerResolution = _nt.fun_fact(
    "NtQueryTimerResolution",
    (NTSTATUS, PULONG, PULONG, PULONG)
    )

def NtQueryTimerResolution():
    min = ULONG(0)
    max = ULONG(0)
    cur = ULONG(0)
    raise_failed_status(_NtQueryTimerResolution(ref(min), ref(max), ref(cur)))
    return min.value, max.value, cur.value

################################################################################
