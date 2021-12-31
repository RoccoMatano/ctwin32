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
from datetime import datetime as _datetime
from uuid import UUID

################################################################################

# N.B.: This module is imported by 'import *'. Make sure that any global name
# that should not be injected into the namespace of importing modules starts
# with '_'!

################################################################################

# integral types

BYTE = _ct.c_byte
CHAR = _ct.c_char
BOOLEAN = BYTE

WCHAR = _ct.c_wchar
SHORT = _ct.c_short
USHORT = _ct.c_ushort
WORD = _ct.c_ushort

INT = _ct.c_int
UINT = _ct.c_uint
LONG = _ct.c_long
ULONG = _ct.c_ulong
DWORD = _ct.c_ulong
BOOL = _ct.c_long

# While the large integers are defined as a struct of low and high part, they
# are also unions containing a long long part. That is why we can simply define
# them as long longs without changing the aligment. For FILETIME (see below)
# this is not the case.

LARGE_INTEGER = _ct.c_longlong
ULARGE_INTEGER = _ct.c_ulonglong

UINT_PTR = WPARAM = SIZE_T = ULONG_PTR = _ct.c_size_t
INT_PTR = LPARAM = SSIZE_T = LRESULT = LONG_PTR = _ct.c_ssize_t

################################################################################

# floating point types

FLOAT = _ct.c_float
DOUBLE = _ct.c_double

################################################################################

# handle types

HANDLE = _ct.c_void_p
HINSTANCE = HWND = HANDLE

################################################################################

# some structure definitions

class GUID(_ct.c_ulong * 4):            # using c_ulong for correct alignment
    def __init__(self, init=None):
        # init is None or str or GUID or UUID or something that can be
        # converted to bytes (like comtypes.GUID). If init is None we simply
        # keep the initial state of 'all bytes are zero'.
        if init is not None:
            if isinstance(init, str):
                src = UUID(init).bytes_le
            elif isinstance(init, GUID):
                src = init
            elif isinstance(init, UUID):
                src = init.bytes_le
            else:
                src = bytes(init)
            _ct.memmove(self, src, _ct.sizeof(self))

    def uuid(self):
        return UUID(bytes_le=bytes(self))

    def __str__(self):
        return f"{{{self.uuid()!s}}}"

    def __repr__(self):
        return f"{self.__class__.__name__}('{self.uuid()!s}')"

################################################################################

class FILETIME(_ct.Structure):
    "Time in 100 nanosecond steps since January 1, 1601 (UTC)"
    # cannot represent FILETIME as _ct.c_ulonglong since that would change
    # the alignment
    _fields_ = (
        ("LowDateTime", DWORD),
        ("HighDateTime", DWORD),
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
        ("Year",         WORD),
        ("Month",        WORD),
        ("DayOfWeek",    WORD),
        ("Day",          WORD),
        ("Hour",         WORD),
        ("Minute",       WORD),
        ("Second",       WORD),
        ("Milliseconds", WORD)
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

class POINT(_ct.Structure):
    _fields_ = (
        ("x", LONG),
        ("y", LONG)
        )

    @classmethod
    def from_lparam(cls, lp):
        return cls(lp & 0xffff, (lp >> 16) & 0xffff)

    def as_lparam(self):
        return (pt.x & 0xffff) | ((pt.y & 0xffff) << 16)

################################################################################

class RECT(_ct.Structure):
    _fields_ = (
        ("left", LONG),
        ("top", LONG),
        ("right", LONG),
        ("bottom", LONG)
        )

    @property
    def width(self):
        return self.right - self.left

    @property
    def height(self):
        return self.bottom - self.top

    @property
    def center(self):
        return (self.left + self.right) // 2, (self.top + self.bottom) // 2

################################################################################

# pointer types

PWSTR = _ct.c_wchar_p
PPWSTR = _ct.POINTER(PWSTR)
PSTR = _ct.c_char_p
PVOID = _ct.c_void_p
PPVOID = _ct.POINTER(PVOID)
PBYTE = _ct.POINTER(BYTE)
PCHAR = _ct.POINTER(CHAR)
PBOOLEAN = _ct.POINTER(BOOLEAN)
PWCHAR = _ct.POINTER(WCHAR)
PSHORT = _ct.POINTER(SHORT)
PUSHORT = PWORD = _ct.POINTER(USHORT)
PINT = _ct.POINTER(INT)
PUINT = _ct.POINTER(UINT)
PLONG = PBOOL = _ct.POINTER(LONG)
PULONG = PDWORD = _ct.POINTER(ULONG)
PUINT_PTR = PWPARAM = PSIZE_T = PULONG_PTR = _ct.POINTER(UINT_PTR)
PLARGE_INTEGER = _ct.POINTER(LARGE_INTEGER)
PULARGE_INTEGER = _ct.POINTER(ULARGE_INTEGER)
PHANDLE = _ct.POINTER(HANDLE)
PGUID = _ct.POINTER(GUID)
PFILETIME = _ct.POINTER(FILETIME)
PSYSTEMTIME = _ct.POINTER(SYSTEMTIME)
PPOINT = _ct.POINTER(POINT)
PRECT = _ct.POINTER(RECT)

################################################################################

# A class that allows to create types (by multiple inheritance) that are based
# on ctypes._SimpleCData and can be used as context managers (i.e. can be used
# in 'with' statements) in order to ensure that handles are orderly closed.
# When defining such a type it must be configured with the approriate base
# class and two parameters:
# - close_func: A function to be called on an instance to close it.
# - invalid: The value that represents an invalid object.
#
# e.g.:
# class KHNDL(
#   ScdToBeClosed,
#   HANDLE,
#   close_func=CloseHandle,
#   invalid=0
#   ):

class ScdToBeClosed():

    def __init_subclass__(cls, /, close_func, invalid, **kwargs):
        if not issubclass(cls, _ct._SimpleCData):
            raise TypeError("must inherit from ctypes._SimpleCData")
        super().__init_subclass__(**kwargs)
        cls.close_func = close_func
        cls.invalid_value = invalid

    def __init__(self, init=None):
        if init is None:
            init = self.invalid_value
        self.value = init.value if hasattr(init, "value") else init

    def close(self):
        if self.is_valid():
            self.close_func()
            self.value = self.invalid_value

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()

    @classmethod
    def from_param(cls, obj):
        if hasattr(obj, "value"):
            return obj.value
        elif isinstance(obj, int):
            return obj
        elif obj is None:
            return cls.invalid_value
        else:
            msg = (
                "Don't know how to convert from " +
                f"{type(obj).__name__} to {cls.__name__}"
                )
            raise TypeError(msg)

    def __int__(self):
        return self.value

    def is_valid(self):
        return self.value != self.invalid_value

################################################################################
