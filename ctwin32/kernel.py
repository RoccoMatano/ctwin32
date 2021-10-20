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
import ctypes.wintypes as _wt
from datetime import datetime as _datetime
import collections as _collections

from . import (
    _raise_if,
    _fun_fact,
    ERROR_INSUFFICIENT_BUFFER,
    INVALID_FILE_ATTRIBUTES
    )

_k32 = _ct.windll.kernel32
_ref = _ct.byref

################################################################################

GetLastError = _ct.GetLastError

################################################################################

_LocalFree = _fun_fact(_k32.LocalFree, (_wt.HLOCAL, _wt.HLOCAL))

def LocalFree(hmem):
    _raise_if(_LocalFree(hmem))

################################################################################

_CloseHandle = _fun_fact(_k32.CloseHandle, (_wt.BOOL, _wt.HANDLE))

def CloseHandle(handle):
    _raise_if(not _CloseHandle(handle))

################################################################################

_GetCurrentProcess = _fun_fact(_k32.GetCurrentProcess, (_wt.HANDLE,))

def GetCurrentProcess():
    return _GetCurrentProcess()

################################################################################

_GetCurrentProcessId = _fun_fact(_k32.GetCurrentProcessId, (_wt.DWORD,))

def GetCurrentProcessId():
    return _GetCurrentProcessId()

################################################################################

_WaitForSingleObject = _fun_fact(
    _k32.WaitForSingleObject, (_wt.DWORD, _wt.HANDLE, _wt.DWORD)
    )

def WaitForSingleObject(handle, timeout):
    res = _WaitForSingleObject(handle, timeout)
    _raise_if(res == WAIT_FAILED)
    return res

################################################################################

_OpenProcess = _fun_fact(
    _k32.OpenProcess, (_wt.HANDLE, _wt.DWORD, _wt.BOOL, _wt.DWORD)
    )

def OpenProcess(desired_acc, inherit, pid):
    res = _OpenProcess(desired_acc, inherit, pid)
    _raise_if(not res)
    return res

################################################################################

_TerminateProcess = _fun_fact(
    _k32.TerminateProcess, (_wt.BOOL, _wt.HANDLE, _wt.UINT)
    )

def TerminateProcess(handle, exit_code):
    _raise_if(not _TerminateProcess(handle, exit_code))

################################################################################

_QueryDosDevice = _fun_fact(
    _k32.QueryDosDeviceW, (_wt.DWORD, _wt.LPCWSTR, _wt.LPWSTR, _wt.DWORD)
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

class FILETIME(_ct.Structure):
    "100-nanoseconds since 12:00 AM January 1, 1601"
    # cannot represent FILETIME as _ct.c_longlong since that would change
    # the alignment
    _fields_ = (
        ("LowDateTime", _wt.DWORD),
        ("HighDateTime", _wt.DWORD),
        )
    def __init__(self, i64=0):
        self.LowDateTime = i64 & 0xffffffff
        self.HighDateTime = i64 >> 32

    def __int__(self):
        return self.LowDateTime | (self.HighDateTime << 32)

    def __iadd__(self, other):
        i64 = int(self) + other
        self.LowDateTime = i64 & 0xffffffff
        self.HighDateTime = i64 >> 32
        return self

    def __repr__(self):
        return f"{self.__class__.__name__}({int(self)})"

################################################################################

class SYSTEMTIME(_ct.Structure):
    _fields_ = (
        ("Year",         _wt.WORD),
        ("Month",        _wt.WORD),
        ("DayOfWeek",    _wt.WORD),
        ("Day",          _wt.WORD),
        ("Hour",         _wt.WORD),
        ("Minute",       _wt.WORD),
        ("Second",       _wt.WORD),
        ("Milliseconds", _wt.WORD)
        )

    ############################################################################

    def to_datetime(self):
        return _datetime(
            self.Year,
            self.Month,
            self.Day,
            self.Hour,
            self.Minute,
            self.Second,
            self.Milliseconds * 1000
            )

    ############################################################################

    def from_datetime(self, dt):
        self.Year = dt.year
        self.Month = dt.month
        self.Day = dt.day
        self.Hour = dt.hour
        self.Minute = dt.minute
        self.Second = dt.second
        self.Milliseconds = dt.microsecond // 1000
        dow = dt.isoweekday()
        self.DayOfWeek = 0 if dow == 7 else dow
        return self

    ############################################################################

    def to_struct_time(self):
        return self.to_datetime().timetuple()

    ############################################################################

    def from_struct_time(self, st):
        self.Year = st.tm_year
        self.Month = st.tm_mon
        self.Day = st.tm_mday
        self.Hour = st.tm_hour
        self.Minute = st.tm_min
        self.Second = st.tm_sec
        self.Milliseconds = 0
        self.DayOfWeek = 0 if st.tm_wday == 6 else st.tm_wday + 1
        return self

    ############################################################################

    def __repr__(self):
        flds = ", ".join([f"{n}={getattr(self, n)}" for n, _ in self._fields_])
        return f"{self.__class__.__name__}({flds})"

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
    _k32.SetFileAttributesW, (_wt.BOOL, _wt.LPCWSTR, _wt.DWORD)
    )

################################################################################

def SetFileAttributes(fname, attribs):
    suc = _SetFileAttributes(fname, attribs)
    _raise_if(not suc)

################################################################################

_GetACP = _fun_fact(_k32.GetACP, (_wt.DWORD,))

def GetACP():
    return _GetACP()

################################################################################

_OutputDebugStringW = _fun_fact(_k32.OutputDebugStringW, (None, _wt.LPCWSTR))

def OutputDebugString(dstr):
    _OutputDebugStringW(dstr)

################################################################################

_SetThreadExecutionState = _fun_fact(
    _k32.SetThreadExecutionState, (_wt.DWORD, _wt.DWORD)
    )

def SetThreadExecutionState(es_flags):
    return _SetThreadExecutionState(es_flags)

################################################################################

_GetPrivateProfileSectionNames = _fun_fact(
    _k32.GetPrivateProfileSectionNamesW,
    (_wt.DWORD, _wt.LPWSTR, _wt.DWORD, _wt.LPWSTR)
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
    (_wt.DWORD, _wt.LPWSTR, _wt.LPWSTR, _wt.DWORD, _wt.LPWSTR)
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
    (_wt.DWORD, _wt.LPWSTR, _wt.LPWSTR, _wt.LPWSTR)
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
