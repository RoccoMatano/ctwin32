################################################################################
#
# Copyright 2021-2024 Rocco Matano
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

import ctypes
from .wtypes import (
    BOOL,
    DWORD,
    HANDLE,
    HMODULE,
    PDWORD,
    POINTER,
    PVOID,
    PWSTR,
    )
from . import (
    ref,
    ntdll,
    kernel,
    raise_on_zero,
    fun_fact,
    ns_from_struct,
    LIST_MODULES_DEFAULT,
    ERROR_PARTIAL_COPY,
    )

_psa = ctypes.WinDLL("psapi.dll")

################################################################################

_EnumProcessModulesEx = fun_fact(
    _psa.EnumProcessModulesEx, (BOOL, HANDLE, PVOID, DWORD, PDWORD, DWORD)
    )

def EnumProcessModulesEx(hdl, filter):
    HSIZE = ctypes.sizeof(HMODULE)
    needed = DWORD(128 * HSIZE)
    size = DWORD(0)
    while needed.value > size.value:
        size.value = needed.value
        mods = (HMODULE * (size.value // HSIZE))()
        if not _EnumProcessModulesEx(hdl, ref(mods), size, ref(needed), filter):
            if (err := kernel.GetLastError()) != ERROR_PARTIAL_COPY:
                raise ctypes.WinError(err)
    return mods[:needed.value // HSIZE]

################################################################################

def EnumProcessModules(hdl):
    return EnumProcessModulesEx(hdl, LIST_MODULES_DEFAULT)

################################################################################

def EnumProcesses():
    return [p.pid for p in ntdll.enum_processes()]

################################################################################

_GetMappedFileName = fun_fact(
    _psa.GetMappedFileNameW, (DWORD, HANDLE, PVOID, PWSTR, DWORD)
    )

def GetMappedFileName(hdl, addr):
    size = 128
    length = size
    while length == size:
        size *= 2
        name = ctypes.create_unicode_buffer(size)
        length = _GetMappedFileName(hdl, addr, name, size)
    return ntdll._resolve_device_prefix(name.value)

################################################################################

_GetModuleFileNameEx = fun_fact(
    _psa.GetModuleFileNameExW, (DWORD, HANDLE, PVOID, PWSTR, DWORD)
    )

def GetModuleFileNameEx(hdl, mod):
    size = 128
    length = size
    while length == size:
        size *= 2
        name = ctypes.create_unicode_buffer(size)
        length = _GetModuleFileNameEx(hdl, mod, name, size)
        raise_on_zero(length)
    return name.value

################################################################################

class MODULEINFO(ctypes.Structure):
    _fields_ = (
        ("lpBaseOfDll", PVOID),
        ("SizeOfImage", DWORD),
        ("EntryPoint", PVOID),
        )

PMODULEINFO = POINTER(MODULEINFO)

_GetModuleInformation = fun_fact(
    _psa.GetModuleInformation, (BOOL, HANDLE, PVOID, PMODULEINFO, DWORD)
    )

def GetModuleInformation(hdl, mod):
    info = MODULEINFO()
    raise_on_zero(
        _GetModuleInformation(hdl, mod, ref(info), ctypes.sizeof(info))
        )
    return ns_from_struct(info)

################################################################################
