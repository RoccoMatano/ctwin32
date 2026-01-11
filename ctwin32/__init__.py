################################################################################
#
# Copyright 2021-2025 Rocco Matano
# SPDX-License-Identifier: MIT
#
################################################################################

import sys as _sys
from types import SimpleNamespace as _namespace
import _ctypes
import ctypes
from ._constants import * # noqa: F403
from .wtypes import DWORD, PWSTR, WCHAR_SIZE, WinError
from . import kuser_shared_data as _kusd
ref = ctypes.byref

################################################################################

__version__ = "4.0.0"

################################################################################

class _ApiFuncPtr(_ctypes.CFuncPtr):
    _flags_ = _ctypes.FUNCFLAG_STDCALL | _ctypes.FUNCFLAG_USE_LASTERROR
    _restype_ = DWORD


class ApiDll:
    def __init__(self, name):
        # ATTENTION: The use of the attribute named '_handle' is hard-coded
        # in ctypes' C code -> don't change its name!
        self._handle = _ctypes.LoadLibrary(
            name,
            LOAD_LIBRARY_SEARCH_DEFAULT_DIRS # noqa: F405 from _constants
            )  & (_sys.maxsize * 2 + 1)
        self._name = name

    def __repr__(self):
        cls = self.__class__.__name__
        adr = id(self) & (_sys.maxsize * 2 + 1)
        return f"<{cls} '{self._name}', handle {self._handle:#x} at {adr:#x}>"

    def __getattr__(self, name):
        func = _ApiFuncPtr((name, self))
        setattr(self, name, func)
        return func

    def fun_fact(self, name, signature):
        func = getattr(self, name)
        func.restype = signature[0]
        func.argtypes = signature[1:]
        return func

################################################################################

def raise_if(condition):
    if condition:
        raise WinError()

################################################################################

def raise_on_zero(value):
    if value == 0 or getattr(value, "value", 1) is None:
        raise WinError()

################################################################################

def raise_on_err(err):
    if err:
        raise WinError(err)

################################################################################

def raise_on_hr(hr):
    if hr < 0:
        raise WinError(hr)

################################################################################

# similar to contextlib.suppress

class suppress_winerr:
    def __init__(self, *err_codes):
        self._err_codes = err_codes

    def __enter__(self):
        return self

    def __exit__(self, exctype, excinst, exctb):
        return (
            exctype is not None and
            issubclass(exctype, OSError) and
            excinst.winerror in self._err_codes
            )

################################################################################

def multi_str_from_str(_str):
    idx = _str.find("\0\0")
    _str = _str[:idx] if idx != -1 else _str.rstrip("\0")
    return [] if not _str else _str.split("\0")

################################################################################

def multi_str_from_addr(addr):
    end = addr
    while True:
        if slen := len(ctypes.cast(end, PWSTR).value):
            end += (slen + 1) * WCHAR_SIZE
        else:
            # +WCHAR_SIZE for final null
            size = (end + WCHAR_SIZE - addr) // WCHAR_SIZE
            return multi_str_from_str(ctypes.wstring_at(addr, size))

################################################################################

def multi_str_from_ubuf(buf, size=-1):
    if size >= 0:
        return multi_str_from_str(buf[:size])
    return multi_str_from_addr(ctypes.addressof(buf))

################################################################################

def cmdline_from_args(args):
    BS = "\\"
    parts = []
    for arg in map(str, args):
        bs_accu = []
        if parts:
            parts.append(" ")
        if need_qmark := (" " in arg) or ("\t" in arg) or not arg:
            parts.append('"')
        for c in arg:
            if c == BS:
                bs_accu.append(c)
            elif c == '"':
                parts.append(BS * len(bs_accu) * 2)
                bs_accu = []
                parts.append(r'\"')
            else:
                if bs_accu:
                    parts.extend(bs_accu)
                    bs_accu = []
                parts.append(c)
        if bs_accu:
            parts.extend(bs_accu)
        if need_qmark:
            parts.extend(bs_accu)
            parts.append('"')
    return "".join(parts)

################################################################################

def ns_from_struct(ctypes_aggregation):
    fields = {}
    for k, *_ in ctypes_aggregation._fields_:
        v = getattr(ctypes_aggregation, k)
        if isinstance(v, ctypes.Structure | ctypes.Union):
            v = ns_from_struct(v)
        elif isinstance(v, ctypes.Array):
            if len(v) and isinstance(v[0], ctypes.Structure | ctypes.Union):
                v = [ns_from_struct(e) for e in v]
            else:
                v = list(v)
        fields[k] = v
    # modify the class name for nicer repr
    class NiceName(_namespace):
        pass
    NiceName.__name__ = type(ctypes_aggregation).__name__
    return NiceName(**fields)

################################################################################

def _warn_win_ver():
    if _kusd.get_ref().NtMajorVersion < 10:
        import warnings # noqa: PLC0415
        msg = (
            "ctwin32 does not intend to support old Windows versions "
            "(< Windows 10). Be happy if it still works ;-)"
            )
        warnings.warn(msg, stacklevel=3)

_warn_win_ver()

################################################################################

def CTL_CODE(dev_type, func, method, access):
    return (dev_type << 16) | (access << 14) | (func << 2) | method

################################################################################

def LOWORD(dw):
    return dw & 0xffff

def HIWORD(dw):
    return (dw >> 16) & 0xffff

################################################################################
