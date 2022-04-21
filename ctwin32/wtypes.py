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
#
# N.B.: This module is designed to be imported by 'import *'. Make sure that
# any global names that should not be injected into the namespace of importing
# modules start with '_'!
#
################################################################################

import sys as _sys
from datetime import datetime as _datetime

# let ctypes and UUID become visible on the outside (by not giving
# them a '_' name!
import ctypes
from uuid import UUID

################################################################################

# integral types

ENDIANNESS = _sys.byteorder

BYTE = ctypes.c_ubyte
CHAR = ctypes.c_char
BOOLEAN = BYTE

WCHAR = ctypes.c_wchar
SHORT = ctypes.c_short
WORD = USHORT = ctypes.c_ushort

INT = ctypes.c_int
UINT = ctypes.c_uint
LONG = BOOL = HRESULT = NTSTATUS = ctypes.c_long
DWORD = ULONG = ctypes.c_ulong

# While the large integers are defined as a struct of low and high part, they
# are also unions containing a long long part. That is why we can simply define
# them as long longs without changing the aligment. For FILETIME (see below)
# this is not the case.

LARGE_INTEGER = LONGLONG = ctypes.c_longlong
ULARGE_INTEGER = ULONGLONG = ctypes.c_ulonglong

UINT_PTR = WPARAM = SIZE_T = ULONG_PTR = ctypes.c_size_t
INT_PTR = LPARAM = SSIZE_T = LRESULT = LONG_PTR = ctypes.c_ssize_t

################################################################################

# floating point types

FLOAT = ctypes.c_float
DOUBLE = ctypes.c_double

################################################################################

# handle types

HANDLE = HINSTANCE = HWND = ctypes.c_void_p

################################################################################

# some structure definitions

class GUID(ULONG * 4):         # using ULONG for correct alignment
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
            ctypes.memmove(self, src, ctypes.sizeof(self))

    def uuid(self):
        return UUID(bytes_le=bytes(self))

    def __str__(self):
        return f"{{{self.uuid()!s}}}"

    def __repr__(self):
        return f"{self.__class__.__name__}('{self.uuid()!s}')"

################################################################################

class FILETIME(ctypes.Structure):
    "Time in 100 nanosecond steps since January 1, 1601 (UTC)"
    # cannot represent FILETIME as ctypes.c_ulonglong since that would change
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

class SYSTEMTIME(ctypes.Structure):
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

class POINT(ctypes.Structure):
    _fields_ = (
        ("x", LONG),
        ("y", LONG)
        )

    @classmethod
    def from_lparam(cls, lp):
        return cls(lp & 0xffff, (lp >> 16) & 0xffff)

    def as_lparam(self):
        return (pt.x & 0xffff) | ((pt.y & 0xffff) << 16)

    def copy(self):
        return self.__class__(self.x, self.y)

    def __repr__(self):
        return f"{self.__class__.__name__}({self.x}, {self.y})"

################################################################################

class RECT(ctypes.Structure):
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

    def copy(self):
        return self.__class__(self.left, self.top, self.right, self.bottom)

    def __repr__(self):
        name = self.__class__.__name__
        return f"{name}({self.left}, {self.top}, {self.right}, {self.bottom})"

################################################################################

class UNICODE_STRING(ctypes.Structure):
    _fields_ = (
        ("Length", WORD),
        ("MaximumLength", WORD),
        ("Buffer", ctypes.c_wchar_p),
        )

################################################################################

class LUID(ctypes.Structure):
    _fields_ = (
        ("LowPart", DWORD),
        ("HighPart", LONG)
        )
    def __int__(self):
        return self.LowPart | (self.HighPart << 32)

################################################################################

class CallbackContext(ctypes.Structure):
    _fields_ = (
        ("callback", ctypes.py_object),
        ("context", ctypes.py_object)
        )

################################################################################

class LOGFONT(ctypes.Structure):
    _fields_ = (
        ("lfHeight", LONG),
        ("lfWidth", LONG),
        ("lfEscapement", LONG),
        ("lfOrientation", LONG),
        ("lfWeight", LONG),
        ("lfItalic", BYTE),
        ("lfUnderline", BYTE),
        ("lfStrikeOut", BYTE),
        ("lfCharSet", BYTE),
        ("lfOutPrecision", BYTE),
        ("lfClipPrecision", BYTE),
        ("lfQuality", BYTE),
        ("lfPitchAndFamily", BYTE),
        ("lfFaceName", WCHAR * 32),
        )

################################################################################

# pointer types

PWSTR = ctypes.c_wchar_p
PSTR = ctypes.c_char_p
PVOID = ctypes.c_void_p
POINTER = ctypes.POINTER
PPWSTR = POINTER(PWSTR)
PPVOID = POINTER(PVOID)
PBYTE = POINTER(BYTE)
PCHAR = POINTER(CHAR)
PBOOLEAN = POINTER(BOOLEAN)
PWCHAR = POINTER(WCHAR)
PSHORT = POINTER(SHORT)
PUSHORT = PWORD = POINTER(USHORT)
PINT = POINTER(INT)
PUINT = POINTER(UINT)
PLONG = PBOOL = POINTER(LONG)
PULONG = PDWORD = POINTER(ULONG)
PUINT_PTR = PWPARAM = PSIZE_T = PULONG_PTR = POINTER(UINT_PTR)
PLARGE_INTEGER = POINTER(LARGE_INTEGER)
PULARGE_INTEGER = POINTER(ULARGE_INTEGER)
PHANDLE = POINTER(HANDLE)
PGUID = POINTER(GUID)
PFILETIME = POINTER(FILETIME)
PSYSTEMTIME = POINTER(SYSTEMTIME)
PPOINT = POINTER(POINT)
PRECT = POINTER(RECT)
PUNICODE_STRING = POINTER(UNICODE_STRING)
PLUID = POINTER(LUID)
PPLUID = POINTER(PLUID)
CallbackContextPtr = POINTER(CallbackContext)
PLOGFONT = POINTER(LOGFONT)

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
#
# Since most of the time HANDLE/ctypes.c_void_p will be the _SimpleCData base
# class, we have to deal with the fact that ctypes.c_void_p will report 'None'
# for its attribute 'value', if the actual integer value is zero.

class ScdToBeClosed():

    def __init_subclass__(cls, /, close_func, invalid, **kwargs):
        if not issubclass(cls, ctypes._SimpleCData):
            raise TypeError("must inherit from ctypes._SimpleCData")
        super().__init_subclass__(**kwargs)
        cls.close_func = close_func
        cls.invalid_value = int(0 if invalid is None else invalid)

    def __init__(self, init=None):
        if hasattr(init, "value"):
            init = 0 if init.value is None else init.value
        if init is None:
            init = self.invalid_value
        self.value = init

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
        return obj if isinstance(obj, cls) else cls(obj)

    def __int__(self):
        return 0 if self.value is None else self.value

    def is_valid(self):
        return int(self) != self.invalid_value

    def raise_on_invalid(self):
        if int(self) == self.invalid_value:
            raise ctypes.WinError()

################################################################################
