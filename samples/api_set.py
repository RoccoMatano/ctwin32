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
#
# This sample demonstrates the use API sets. It only supports version
# 6 API sets (Windows >= 10). You can either dump all entries by not
# supplying any argument or you can lookup an Api set DLL name (e.g.
# api-ms-win-base-util-l1-1-0.dll) by supplying such a name as a single
# argument.
#
################################################################################

import sys
import ctypes
from ctwin32 import ntdll
from ctwin32.wtypes import ULONG, PVOID, WCHAR

################################################################################

class API_SET_NAMESPACE(ctypes.Structure):
    _fields_ = (
        ("Version", ULONG),
        ("Size", ULONG),
        ("Flags", ULONG),
        ("Count", ULONG),
        ("EntryOffset", ULONG),
        ("HashOffset", ULONG),
        ("HashFactor", ULONG),
        )

class API_SET_NAMESPACE_ENTRY(ctypes.Structure):
    _fields_ = (
        ("Flags", ULONG),
        ("NameOffset", ULONG),
        ("NameLength", ULONG),
        ("HashedLength", ULONG),
        ("ValueOffset", ULONG),
        ("ValueCount", ULONG),
        )

class API_SET_VALUE_ENTRY(ctypes.Structure):
    _fields_ = (
        ("Flags", ULONG),
        ("NameOffset", ULONG),
        ("NameLength", ULONG),
        ("ValueOffset", ULONG),
        ("ValueLength", ULONG),
        )

################################################################################

class ApiSet():
    def __init__(self):
        offs = 0x68 if sys.maxsize > 4294967295 else 0x38
        base = PVOID.from_address(ntdll.RtlGetCurrentPeb() + offs).value
        apiset = API_SET_NAMESPACE.from_address(base)
        self.ok = (apiset.Version == 6)
        if self.ok:
            self.base = base
            self.count = apiset.Count
            self.entry_addr = base + apiset.EntryOffset
        else:
            self.base = self.count = self.entry_addr = None

    ############################################################################

    def _get_entry_info(self, idx, for_lookup):
        ENTRY_SIZE = ctypes.sizeof(API_SET_NAMESPACE_ENTRY)
        addr = self.entry_addr + idx * ENTRY_SIZE
        entry = API_SET_NAMESPACE_ENTRY.from_address(addr)
        str_len = (
            entry.HashedLength if for_lookup else entry.NameLength
            ) // ctypes.sizeof(WCHAR)
        str_addr = self.base + entry.NameOffset
        return entry, ctypes.wstring_at(str_addr, str_len)

    ############################################################################

    def _enum_values(self, entry):
        value_addr = self.base + entry.ValueOffset
        for _ in range(entry.ValueCount):
            value = API_SET_VALUE_ENTRY.from_address(value_addr)
            if value.ValueLength:
                res_len = value.ValueLength // ctypes.sizeof(WCHAR)
                res_addr = self.base + value.ValueOffset
                yield ctypes.wstring_at(res_addr, res_len)
            value_addr += ctypes.sizeof(API_SET_VALUE_ENTRY)

    ############################################################################

    def enum_entries(self):
        if self.base:
            for i in range(self.count):
                entry, name = self._get_entry_info(i, False)
                yield (name, list(self._enum_values(entry)))

    ############################################################################

    def lookup(self, dllname):
        if self.base:
            dllname = dllname.lower()
            # entries are sorted -> binary search
            mini = 0
            maxi = self.count - 1
            while mini <= maxi:
                curi = (mini + maxi) // 2
                entry, name = self._get_entry_info(curi, True)
                if dllname.startswith(name):
                    for value in self._enum_values(entry):
                        return value
                if dllname < name:
                    maxi = curi - 1
                else:
                    mini = curi + 1

        return ""

################################################################################

if __name__ == "__main__":
    api_set = ApiSet()
    if not api_set.ok:
        print("Api set not present or unsupported version.")
    elif len(sys.argv) > 1:
        print(f"{sys.argv[1]} -> {api_set.lookup(sys.argv[1])}")
    else:
        for entry, targets in api_set.enum_entries():
            print(f"{entry:>58} -> {', '.join(targets)}")

################################################################################
