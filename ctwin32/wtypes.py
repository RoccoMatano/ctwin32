################################################################################
#
# Copyright 2021-2024 Rocco Matano
# SPDX-License-Identifier: MIT
#
################################################################################

import sys
import ctypes
from uuid import UUID
from datetime import datetime

# avoid circular dependency: ctwin32 -> wtypes -> ctwin32
MAX_PATH = 260

################################################################################

# integral types

ENDIANNESS = sys.byteorder

BYTE = ctypes.c_ubyte
CHAR = ctypes.c_char
BOOLEAN = BYTE

WCHAR = ctypes.c_wchar
WCHAR_SIZE = ctypes.sizeof(WCHAR)
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

HANDLE = HINSTANCE = HMODULE = HWND = ctypes.c_void_p

################################################################################

# byte and string buffers

def byte_buffer(init, size=None):
    if isinstance(init, bytes):
        if size is None:
            size = 1 + len(init)
        (buf := (CHAR * size)()).value = init
        return buf
    elif isinstance(init, int):
        return (CHAR * init)()
    raise TypeError(init)

def wchar_len_sz(wstr):
    return 1 + sum(2 if ord(c) > 0xFFFF else 1 for c in wstr)

def string_buffer(init, size=None):
    if isinstance(init, str):
        if size is None:
            size = wchar_len_sz(init)
        (buf := (WCHAR * size)()).value = init
        return buf
    elif isinstance(init, int):
        return (WCHAR * init)()
    raise TypeError(init)

################################################################################

# error handling based on ctypes error shadow copy

def WinError(code=None, descr=None):
    if code is None:
        code = ctypes.get_last_error()
    if descr is None:
        descr = ctypes.FormatError(code).strip()
    return OSError(None, descr, None, code)

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

    def __eq__(self, other):
        try:
            return bytes(self) == bytes(other)
        except Exception:   # noqa: BLE001
            return False

################################################################################

class FILETIME(ctypes.Structure):
    "Time in 100 nanosecond steps since January 1, 1601 (UTC)"
    # cannot represent FILETIME as ctypes.c_ulonglong since that would change
    # the alignment
    _fields_ = (
        ("dwLowDateTime", DWORD),
        ("dwHighDateTime", DWORD),
        )

    def __init__(self, i64=0):
        self.dwLowDateTime = i64 & 0xffffffff
        self.dwHighDateTime = i64 >> 32

    def __int__(self):
        return self.dwLowDateTime | (self.dwHighDateTime << 32)

    def __add__(self, other):
        return self.__class__(int(self) + int(other))

    def __sub__(self, other):
        return self.__class__(int(self) - int(other))

    def __iadd__(self, other):
        i64 = int(self) + int(other)
        self.dwLowDateTime = i64 & 0xffffffff
        self.dwHighDateTime = i64 >> 32
        return self

    def __isub__(self, other):
        i64 = int(self) - int(other)
        self.dwLowDateTime = i64 & 0xffffffff
        self.dwHighDateTime = i64 >> 32
        return self

    def __repr__(self):
        return f"{self.__class__.__name__}({int(self)})"

################################################################################

class SYSTEMTIME(ctypes.Structure):
    _fields_ = (
        ("wYear",         WORD),
        ("wMonth",        WORD),
        ("wDayOfWeek",    WORD),
        ("wDay",          WORD),
        ("wHour",         WORD),
        ("wMinute",       WORD),
        ("wSecond",       WORD),
        ("wMilliseconds", WORD)
        )

    ############################################################################

    def to_datetime(self, tzinfo=None):
        return datetime(
            self.wYear,
            self.wMonth,
            self.wDay,
            self.wHour,
            self.wMinute,
            self.wSecond,
            self.wMilliseconds * 1000,
            tzinfo
            )

    ############################################################################

    def from_datetime(self, dt):
        self.wYear = dt.year
        self.wMonth = dt.month
        self.wDay = dt.day
        self.wHour = dt.hour
        self.wMinute = dt.minute
        self.wSecond = dt.second
        self.wMilliseconds = dt.microsecond // 1000
        dow = dt.isoweekday()
        self.wDayOfWeek = 0 if dow == 7 else dow
        return self

    ############################################################################

    def to_struct_time(self):
        return self.to_datetime().timetuple()

    ############################################################################

    def from_struct_time(self, st):
        self.wYear = st.tm_year
        self.wMonth = st.tm_mon
        self.wDay = st.tm_mday
        self.wHour = st.tm_hour
        self.wMinute = st.tm_min
        self.wSecond = st.tm_sec
        self.wMilliseconds = 0
        self.wDayOfWeek = 0 if st.tm_wday == 6 else st.tm_wday + 1
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
        return (self.x & 0xffff) | ((self.y & 0xffff) << 16)

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

class LUID(ctypes.Structure):
    _fields_ = (
        ("LowPart", DWORD),
        ("HighPart", LONG)
        )

    def __init__(self, value=None):
        if value is None:
            value = 0
        self.LowPart = value & 0xffffffff
        self.HighPart = value >> 32

    def __int__(self):
        return self.LowPart | (self.HighPart << 32)

    def __repr__(self):
        return f"{self.__class__.__name__}({int(self)})"

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

class OSVERSIONINFOEX(ctypes.Structure):
    _fields_ = (
        ("dwOSVersionInfoSize", DWORD),
        ("dwMajorVersion", DWORD),
        ("dwMinorVersion", DWORD),
        ("dwBuildNumber", DWORD),
        ("dwPlatformId", DWORD),
        ("szCSDVersion", WCHAR * 128),
        ("wServicePackMajor", WORD),
        ("wServicePackMinor", WORD),
        ("wSuiteMask", WORD),
        ("wProductType", BYTE),
        ("wReserved", BYTE),
        )

    def __init__(self):
        self.dwOSVersionInfoSize = ctypes.sizeof(self)

################################################################################

class WIN32_FIND_DATA(ctypes.Structure):
    _fields_ = (
        ("dwFileAttributes", DWORD),
        ("ftCreationTime", FILETIME),
        ("ftLastAccessTime", FILETIME),
        ("ftLastWriteTime", FILETIME),
        ("nFileSizeHigh", DWORD),
        ("nFileSizeLow", DWORD),
        ("dwReserved0", DWORD),
        ("dwReserved1", DWORD),
        ("cFileName", WCHAR * MAX_PATH),
        ("cAlternateFileName", WCHAR * 14),
        ("dwFileType", DWORD),     # obsolete - do not use
        ("dwCreatorType", DWORD),  # obsolete - do not use
        ("wFinderFlags", WORD),    # obsolete - do not use
        )

################################################################################

# pointer types

PTR_32_BIT = ctypes.sizeof(ctypes.c_void_p) == 4
PTR_64_BIT = ctypes.sizeof(ctypes.c_void_p) == 8

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
PULONGLONG = POINTER(ULONGLONG)
PLUID = POINTER(LUID)
PPLUID = POINTER(PLUID)
CallbackContextPtr = POINTER(CallbackContext)
PLOGFONT = POINTER(LOGFONT)
POSVERSIONINFOEX = POINTER(OSVERSIONINFOEX)
PWIN32_FIND_DATA = POINTER(WIN32_FIND_DATA)

def ptr_addr(ct_obj):
    return PVOID.from_buffer(ct_obj).value

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
            raise WinError()

################################################################################

# c_void_p has a flaw: neither can c_void_p.from_param() process a py_object,
# nor does cast() allow to convert a py_object to a c_void_p
# (cast(py_object(obj), c_void_p) fails). Therefore we need this odd way of
# converting a python object pointer to c_void_p.

def pvoid_from_obj(obj):
    return PVOID.from_buffer(ctypes.py_object(obj))

# On the other hand: As long as CPython keeps using the object address as the
# return value for `id()`, you can simply use `id(obj)` instead of
# `pvoid_from_obj(obj)`.

################################################################################

class ArgcArgvFromArgs():
    """Converts a list of strings into a buffer that contains the strings
    and an array of pointers to these strings. The number of strings and the
    address of the pointer array are provided by the attributes `argc` and
    `argv`.
    """
    def __init__(self, args):
        if not args:
            self._argc = 0
            self._argv = None
        else:
            self._argc = len(args)
            chain = "\0".join(args) + "\0"

            class ArgumentBuffer(ctypes.Structure):
                _fields_ = (
                    ("pointers", PWSTR * self._argc),
                    ("strings", WCHAR * len(chain)),
                    )

            self._buffer = ArgumentBuffer(strings=chain)
            self._argv = ctypes.addressof(self._buffer)
            str_addr = self._argv + ArgumentBuffer.strings.offset
            for i, arg in enumerate(args):
                self._buffer.pointers[i] = str_addr
                str_addr += WCHAR_SIZE * (len(arg) + 1)

    @property
    def argc(self):
        return self._argc

    @property
    def argv(self):
        return self._argv

################################################################################

class UNICODE_STRING(ctypes.Structure):
    _fields_ = (
        ("Length", WORD),
        ("MaximumLength", WORD),
        ("Buffer", PWSTR),
        )

    def __str__(self):
        return ctypes.wstring_at(
            self.Buffer,
            self.Length // WCHAR_SIZE
            )

PUNICODE_STRING = POINTER(UNICODE_STRING)

################################################################################

def UnicodeStrFromStr(init):
    ws = wchar_len_sz(init)

    class SELF_CONTAINED_US(ctypes.Structure):
        _fields_ = (
            ("us", UNICODE_STRING),
            ("buf", WCHAR * ws),
            )

        def __init__(self, init):
            li = ws * WCHAR_SIZE
            baddr = ctypes.addressof(self) + __class__.buf.offset
            super().__init__((li - WCHAR_SIZE, li, baddr), init)

        @property
        def ptr(self):
            return PUNICODE_STRING(self.us)

    return SELF_CONTAINED_US(init)

################################################################################

def UnicodeStrArray(strings):
    num_strings = len(strings)
    chain = "\0".join(strings)
    buf_len = wchar_len_sz(chain)

    class SELF_CONTAINED_USA(ctypes.Structure):
        _fields_ = (
            ("us", UNICODE_STRING * num_strings),
            ("buf", WCHAR * buf_len),
            )

        def __init__(self, strings, chain):
            super().__init__(buf=chain)
            addr = ctypes.addressof(self) + __class__.buf.offset
            for i, s in enumerate(strings):
                max_len = wchar_len_sz(s) * WCHAR_SIZE
                self.us[i].Length = max_len - WCHAR_SIZE
                self.us[i].MaximumLength = max_len
                self.us[i].Buffer = addr
                addr += max_len

        @property
        def ptr(self):
            return PUNICODE_STRING(self.us)

    return SELF_CONTAINED_USA(strings, chain)

################################################################################
