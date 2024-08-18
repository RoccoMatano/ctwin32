################################################################################
#
# Copyright 2021-2024 Rocco Matano
# SPDX-License-Identifier: MIT
#
################################################################################

import ctypes
from .wtypes import (
    byte_buffer,
    BOOL,
    DWORD,
    PDWORD,
    PPVOID,
    PUINT,
    PVOID,
    PWSTR,
    UINT,
    WORD,
    )
from . import (
    ref,
    raise_on_zero,
    suppress_winerr,
    fun_fact,
    ns_from_struct,
    ERROR_RESOURCE_TYPE_NOT_FOUND,
    )

_ver = ctypes.WinDLL("version.dll", use_last_error=True)

################################################################################

class VS_FIXEDFILEINFO(ctypes.Structure):
    _fields_ = (
        ("dwSignature", DWORD),
        ("dwStrucVersion", DWORD),
        ("dwFileVersionMS", DWORD),
        ("dwFileVersionLS", DWORD),
        ("dwProductVersionMS", DWORD),
        ("dwProductVersionLS", DWORD),
        ("dwFileFlagsMask", DWORD),
        ("dwFileFlags", DWORD),
        ("dwFileOS", DWORD),
        ("dwFileType", DWORD),
        ("dwFileSubtype", DWORD),
        ("dwFileDateMS", DWORD),
        ("dwFileDateLS", DWORD),
        )

################################################################################

_GetFileVersionInfoSize = fun_fact(
    _ver.GetFileVersionInfoSizeW, (DWORD, PWSTR, PDWORD)
    )

def GetFileVersionInfoSize(fname):
    dummy = DWORD()
    res = _GetFileVersionInfoSize(fname, ref(dummy))
    raise_on_zero(res)
    return res

################################################################################

_GetFileVersionInfo = fun_fact(
    _ver.GetFileVersionInfoW, (BOOL, PWSTR, DWORD, DWORD, PVOID)
    )

def GetFileVersionInfo(fname, size=0):
    if size == 0:
        size = GetFileVersionInfoSize(fname)
    buf = byte_buffer(size)
    raise_on_zero(_GetFileVersionInfo(fname, 0, size, buf))
    return buf.raw

################################################################################

_VerQueryValue = fun_fact(
    _ver.VerQueryValueW, (BOOL, PVOID, PWSTR, PPVOID, PUINT)
    )

def VerQueryValue(block, subblock):
    value = PVOID()
    size = UINT()
    raise_on_zero(_VerQueryValue(block, subblock, ref(value), ref(size)))
    if "StringFileInfo" in subblock:
        return ctypes.wstring_at(value.value, size.value).strip("\0")
    return ctypes.string_at(value.value, size.value)

################################################################################

def get_binary_info(fname, block=None):
    if block is None:
        block = GetFileVersionInfo(fname)
    return ns_from_struct(
        VS_FIXEDFILEINFO.from_buffer_copy(VerQueryValue(block, "\\"))
        )

################################################################################

_str_info_names = [
    "CompanyName",
    "ProductName",
    "ProductVersion",
    "FileDescription",
    "FileVersion",
    "InternalName",
    "OriginalFilename",
    "LegalCopyright",
    "LegalTrademarks",
    "Comments",
    "PrivateBuild",
    "SpecialBuild",
    ]

class _LANG_CP(ctypes.Structure):
    _fields_ = (
        ("lang", WORD),
        ("cp", WORD),
        )

################################################################################

def get_string_info(fname, block=None):

    if block is None:
        block = GetFileVersionInfo(fname)

    lc_array = VerQueryValue(block, r"\VarFileInfo\Translation")
    if (len(lc_array) % ctypes.sizeof(_LANG_CP)) != 0:
        raise ValueError("invalid version resource")

    # just take the first language
    lc = _LANG_CP.from_buffer_copy(lc_array)
    lang = f"\\StringFileInfo\\{lc.lang:04x}{lc.cp:04x}\\"

    result = {}
    for k in _str_info_names:
        with suppress_winerr(ERROR_RESOURCE_TYPE_NOT_FOUND):
            result[k] = VerQueryValue(block, lang + k)
    return result

################################################################################
