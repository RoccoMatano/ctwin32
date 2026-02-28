################################################################################
#
# Copyright 2021-2026 Rocco Matano
# SPDX-License-Identifier: MIT
#
################################################################################

import ctypes
from . import (
    kernel,
    ntdll,
    ERROR_BAD_EXE_FORMAT,
    ERROR_INVALID_DATA,
    FILE_MAP_READ,
    GENERIC_READ,
    IMAGE_DOS_SIGNATURE,
    IMAGE_NT_SIGNATURE,
    IMAGE_NT_OPTIONAL_HDR64_MAGIC,
    IMAGE_NUMBEROF_DIRECTORIES,
    IMAGE_SIZEOF_SHORT_NAME,
    PAGE_READONLY,
    )
from .wtypes import (
    BYTE,
    Struct,
    Union,
    DWORD,
    PTR_HAS_64_BITS,
    PVOID,
    ULONG,
    ULONGLONG,
    WCHAR_SIZE,
    WinError,
    WORD,
    )

################################################################################

class IMAGE_FILE_HEADER(Struct):
    _fields_ = (
        ("Machine", WORD),
        ("NumberOfSections", WORD),
        ("TimeDateStamp", DWORD),
        ("PointerToSymbolTable", DWORD),
        ("NumberOfSymbols", DWORD),
        ("SizeOfOptionalHeader", WORD),
        ("Characteristics", WORD),
        )

################################################################################

class IMAGE_DATA_DIRECTORY(Struct):
    _fields_ = (
        ("VirtualAddress", DWORD),
        ("Size", DWORD),
        )

################################################################################

class IMAGE_OPTIONAL_HEADER32(Struct):
    _fields_ = (
        ("Magic", WORD),
        ("MajorLinkerVersion", BYTE),
        ("MinorLinkerVersion", BYTE),
        ("SizeOfCode", DWORD),
        ("SizeOfInitializedData", DWORD),
        ("SizeOfUninitializedData", DWORD),
        ("AddressOfEntryPoint", DWORD),
        ("BaseOfCode", DWORD),
        ("BaseOfData", DWORD),
        ("ImageBase", DWORD),
        ("SectionAlignment", DWORD),
        ("FileAlignment", DWORD),
        ("MajorOperatingSystemVersion", WORD),
        ("MinorOperatingSystemVersion", WORD),
        ("MajorImageVersion", WORD),
        ("MinorImageVersion", WORD),
        ("MajorSubsystemVersion", WORD),
        ("MinorSubsystemVersion", WORD),
        ("Win32VersionValue", DWORD),
        ("SizeOfImage", DWORD),
        ("SizeOfHeaders", DWORD),
        ("CheckSum", DWORD),
        ("Subsystem", WORD),
        ("DllCharacteristics", WORD),
        ("SizeOfStackReserve", DWORD),
        ("SizeOfStackCommit", DWORD),
        ("SizeOfHeapReserve", DWORD),
        ("SizeOfHeapCommit", DWORD),
        ("LoaderFlags", DWORD),
        ("NumberOfRvaAndSizes", DWORD),
        ("DataDirectory", IMAGE_DATA_DIRECTORY * IMAGE_NUMBEROF_DIRECTORIES),
        )

################################################################################

class IMAGE_OPTIONAL_HEADER64(Struct):
    _fields_ = (
        ("Magic", WORD),
        ("MajorLinkerVersion", BYTE),
        ("MinorLinkerVersion", BYTE),
        ("SizeOfCode", DWORD),
        ("SizeOfInitializedData", DWORD),
        ("SizeOfUninitializedData", DWORD),
        ("AddressOfEntryPoint", DWORD),
        ("BaseOfCode", DWORD),
        ("ImageBase", ULONGLONG),
        ("SectionAlignment", DWORD),
        ("FileAlignment", DWORD),
        ("MajorOperatingSystemVersion", WORD),
        ("MinorOperatingSystemVersion", WORD),
        ("MajorImageVersion", WORD),
        ("MinorImageVersion", WORD),
        ("MajorSubsystemVersion", WORD),
        ("MinorSubsystemVersion", WORD),
        ("Win32VersionValue", DWORD),
        ("SizeOfImage", DWORD),
        ("SizeOfHeaders", DWORD),
        ("CheckSum", DWORD),
        ("Subsystem", WORD),
        ("DllCharacteristics", WORD),
        ("SizeOfStackReserve", ULONGLONG),
        ("SizeOfStackCommit", ULONGLONG),
        ("SizeOfHeapReserve", ULONGLONG),
        ("SizeOfHeapCommit", ULONGLONG),
        ("LoaderFlags", DWORD),
        ("NumberOfRvaAndSizes", DWORD),
        ("DataDirectory", IMAGE_DATA_DIRECTORY * IMAGE_NUMBEROF_DIRECTORIES),
        )

################################################################################

class IMAGE_SECTION_HEADER(Struct):
    _fields_ = (
        ("Name", BYTE * IMAGE_SIZEOF_SHORT_NAME),
        ("VirtualSize", DWORD),
        ("VirtualAddress", DWORD),
        ("SizeOfRawData", DWORD),
        ("PointerToRawData", DWORD),
        ("PointerToRelocations", DWORD),
        ("PointerToLinenumbers", DWORD),
        ("NumberOfRelocations", WORD),
        ("NumberOfLinenumbers", WORD),
        ("Characteristics", DWORD),
        )

################################################################################

class IMAGE_EXPORT_DIRECTORY(Struct):
    _fields_ = (
        ("Characteristics", DWORD),
        ("TimeDateStamp", DWORD),
        ("MajorVersion", WORD),
        ("MinorVersion", WORD),
        ("Name", DWORD),
        ("Base", DWORD),
        ("NumberOfFunctions", DWORD),
        ("NumberOfNames", DWORD),
        ("AddressOfFunctions", DWORD),
        ("AddressOfNames", DWORD),
        ("AddressOfNameOrdinals", DWORD),
        )

################################################################################

class IID_UNION(Union):
    _fields_ = (
        ("Characteristics", DWORD),
        ("OriginalFirstThunk", DWORD),
        )

class IMAGE_IMPORT_DESCRIPTOR(Struct):
    _anonymous_ = ("anon",)
    _fields_ = (
        ("anon", IID_UNION),
        ("TimeDateStamp", DWORD),
        ("ForwarderChain", DWORD),
        ("Name", DWORD),
        ("FirstThunk", DWORD),
        )

################################################################################

class IMAGE_DELAYLOAD_DESCRIPTOR(Struct):
    _fields_ = (
        ("Attributes", DWORD),
        ("DllNameRVA", DWORD),
        ("ModuleHandleRVA", DWORD),
        ("ImportAddressTableRVA", DWORD),
        ("ImportNameTableRVA", DWORD),
        ("BoundImportAddressTableRVA", DWORD),
        ("UnloadInformationTableRVA", DWORD),
        ("TimeDateStamp", DWORD),
        )

dlattrRva = 0x1

################################################################################

class NotPeError(OSError):
    def __init__(self, name, code=None):
        code = code or ERROR_BAD_EXE_FORMAT
        super().__init__(0, "not a PE file", str(name), code)

################################################################################

class pemap:
    E_MAGIC = 0     # file offset of 'MZ' magic
    E_LFANEW = 60   # file offset of NT header offset

    def __init__(self, fname, *, convert_open_err=False):
        try:
            with kernel.create_file(str(fname), GENERIC_READ) as f:
                self.size = kernel.GetFileSize(f)
                if self.size < (self.E_LFANEW + 4):
                    raise NotPeError(fname)
                with kernel.CreateFileMapping(f, None, PAGE_READONLY, 0) as m:
                    self.view = kernel.MapViewOfFile(m, FILE_MAP_READ, 0, 0)
        except OSError as e:
            if convert_open_err:
                raise NotPeError(fname, e.winerror) from e
            raise

        if fhaddr := self._file_header_addr():
            self.name = fname
            self.key = str(fname).split("\\")[-1].lower()
            self.file_hdr = IMAGE_FILE_HEADER.from_address(fhaddr)
            ohaddr = fhaddr + IMAGE_FILE_HEADER._size_
            self.opt_hdr = IMAGE_OPTIONAL_HEADER64.from_address(ohaddr)
            self.is64bit = True
            if self.opt_hdr.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC:
                self.is64bit = False
                self.opt_hdr = IMAGE_OPTIONAL_HEADER32.from_address(ohaddr)

            secaddr = ohaddr + self.file_hdr.SizeOfOptionalHeader
            size = IMAGE_SECTION_HEADER._size_
            self.sections = [
                IMAGE_SECTION_HEADER.from_address(secaddr + i * size)
                for i in range(self.file_hdr.NumberOfSections)
                ]
        else:
            self.close()
            raise NotPeError(fname)

    ############################################################################

    def close(self):
        kernel.UnmapViewOfFile(self.view)
        self.view = self.file_hdr = self.opt_hdr = self.sections = None

    @property
    def closed(self):
        return self.view is None

    ############################################################################

    def __enter__(self):
        return self

    ############################################################################

    def __exit__(self, *args):
        self.close()

    ############################################################################

    def u8(self, offs, idx=0):
        return ctypes.c_uint8.from_address(self.view + offs + idx).value

    ############################################################################

    def u16(self, offs, idx=0):
        return ctypes.c_uint16.from_address(self.view + offs + idx * 2).value

    ############################################################################

    def u32(self, offs, idx=0):
        return ctypes.c_uint32.from_address(self.view + offs + idx * 4).value

    ############################################################################

    def u64(self, offs, idx=0):
        return ctypes.c_uint64.from_address(self.view + offs + idx * 8).value

    ############################################################################

    _std_uint_getters = {1: u8, 2: u16, 4: u32, 8: u64}

    def uint(self, size, offs, idx=0):
        if getter := self._std_uint_getters.get(size, None):
            return getter(self, offs, idx)
        addr = self.view + offs + idx * size
        return int.from_bytes(ctypes.string_at(addr, size), byteorder="little")

    ############################################################################

    def ctypes_obj(self, cls, offs, idx=0):
        return cls.from_address(self.view + offs + idx * ctypes.sizeof(cls))

    ############################################################################

    def __getitem__(self, key):
        if isinstance(key, int):
            if key < 0:
                key += self.size
            if 0 <= key < self.size:
                return ctypes.c_uint8.from_address(self.view + key).value
            raise IndexError
        if isinstance(key, slice):
            start, stop, step = key.indices(self.size)
            return ctypes.string_at(self.view + start, stop - start)[::step]
        raise TypeError

    ############################################################################

    def bstring(self, offs, enc="ascii", err="backslashreplace"):
        return ctypes.string_at(self.view + offs).decode(enc, err)

    ############################################################################

    def string(self, offs):
        return ctypes.wstring_at(self.view + offs)

    ############################################################################

    def _file_header_addr(self):
        if self.u16(self.E_MAGIC) == IMAGE_DOS_SIGNATURE:
            offs = self.u32(self.E_LFANEW)
            if self.u32(offs) == IMAGE_NT_SIGNATURE:
                # len(IMAGE_NT_SIGNATURE) == 4
                return self.view + offs + 4
        return None

    ############################################################################

    def section_from_rva(self, rva):
        for s in self.sections:
            size = s.VirtualSize or s.SizeOfRawData
            if s.VirtualAddress <= rva < s.VirtualAddress + size:
                return s
        return None

    ############################################################################

    def offs_from_rva(self, rva):
        if s := self.section_from_rva(rva):
            return rva - (s.VirtualAddress - s.PointerToRawData)
        return None

    ############################################################################

    def img_dir(self, idx):
        if 0 <= idx < self.opt_hdr.NumberOfRvaAndSizes:
            dd = self.opt_hdr.DataDirectory[idx]
            return dd.VirtualAddress, dd.Size
        raise IndexError

    ############################################################################

    def is_wow(self):
        host_arch = kernel.get_wow64_info(kernel.GetCurrentProcess())[0]
        return host_arch != self.file_hdr.Machine

################################################################################

class API_SET_NAMESPACE(Struct):
    _fields_ = (
        ("Version", ULONG),
        ("Size", ULONG),
        ("Flags", ULONG),
        ("Count", ULONG),
        ("EntryOffset", ULONG),
        ("HashOffset", ULONG),
        ("HashFactor", ULONG),
        )

class API_SET_NAMESPACE_ENTRY(Struct):
    _fields_ = (
        ("Flags", ULONG),
        ("NameOffset", ULONG),
        ("NameLength", ULONG),
        ("HashedLength", ULONG),
        ("ValueOffset", ULONG),
        ("ValueCount", ULONG),
        )

class API_SET_VALUE_ENTRY(Struct):
    _fields_ = (
        ("Flags", ULONG),
        ("NameOffset", ULONG),
        ("NameLength", ULONG),
        ("ValueOffset", ULONG),
        ("ValueLength", ULONG),
        )

class API_SET_HASH_ENTRY(Struct):
    _fields_ = (
        ("Hash", ULONG),
        ("Index", ULONG),
        )

################################################################################

class ApiSet():
    def __init__(self):
        offs = 0x68 if PTR_HAS_64_BITS else 0x38
        base = PVOID.from_address(ntdll.RtlGetCurrentPeb() + offs).value
        apiset = API_SET_NAMESPACE.from_address(base)
        if apiset.Version == 6:
            self.base = base
            self.count = apiset.Count
            self.hash_fact = apiset.HashFactor
            self.hash_addr = base + apiset.HashOffset
            self.entry_addr = base + apiset.EntryOffset
        else:
            raise WinError(ERROR_INVALID_DATA)

    ############################################################################

    def _hash_at(self, idx):
        ENTRY_SIZE = API_SET_HASH_ENTRY._size_
        addr = self.hash_addr + idx * ENTRY_SIZE
        hsh = API_SET_HASH_ENTRY.from_address(addr)
        return hsh.Hash, hsh.Index

    ############################################################################

    def _get_entry_info(self, idx, for_lookup):
        ENTRY_SIZE = API_SET_NAMESPACE_ENTRY._size_
        addr = self.entry_addr + idx * ENTRY_SIZE
        entry = API_SET_NAMESPACE_ENTRY.from_address(addr)
        str_len = (
            entry.HashedLength if for_lookup else entry.NameLength
            ) // WCHAR_SIZE
        str_addr = self.base + entry.NameOffset
        return entry, ctypes.wstring_at(str_addr, str_len)

    ############################################################################

    def _enum_values(self, entry):
        value_addr = self.base + entry.ValueOffset
        for _ in range(entry.ValueCount):
            value = API_SET_VALUE_ENTRY.from_address(value_addr)
            if value.ValueLength:
                res_len = value.ValueLength // WCHAR_SIZE
                res_addr = self.base + value.ValueOffset
                yield ctypes.wstring_at(res_addr, res_len)
            value_addr += API_SET_VALUE_ENTRY._size_

    ############################################################################

    def enum_entries(self):
        if self.base:
            for i in range(self.count):
                entry_hsh, entry_idx = self._hash_at(i)
                entry, name = self._get_entry_info(entry_idx, False)
                yield (name, entry_hsh, list(self._enum_values(entry)))

    ############################################################################

    def lookup(self, dllname, importer=None):

        def pick_name(entry, importer):
            result = ""
            names = list(self._enum_values(entry))
            if not names:
                return result
            result = names[0]
            if importer:
                importer = importer.lower()
                for n in names:
                    if n == importer:
                        result = n
                        break
            return result

        if not self.base:
            return ""

        norm = dllname.lower().rsplit("-", 1)[0]
        target = 0
        U32 = 0xffffffff
        for c in norm:
            target = (((target * self.hash_fact) & U32) + ord(c)) & U32

        # entries are sorted -> binary search
        mini = 0
        maxi = self.count - 1
        while mini <= maxi:
            curi = (mini + maxi) // 2
            entry_hsh, entry_idx = self._hash_at(curi)

            if target < entry_hsh:
                maxi = curi - 1
            elif target > entry_hsh:
                mini = curi + 1
            else:
                # candidate: verify the actual name (up to HashedLength)
                entry, name = self._get_entry_info(entry_idx, True)
                if norm == name:
                    return pick_name(entry, importer)

                # Hash collision is rare -> scan neighbors with the same hash

                # scan left
                left = curi - 1
                while left >= 0:
                    entry_hsh, entry_idx = self._hash_at(left)
                    if entry_hsh != target:
                        break
                    entry, name = self._get_entry_info(entry_idx, True)
                    if norm == name:
                        return pick_name(entry, importer)
                    left -= 1

                # scan right
                right = curi + 1
                while right < self.count:
                    entry_hsh, entry_idx = self._hash_at(right)
                    if entry_hsh != target:
                        break
                    entry, name = self._get_entry_info(entry_idx, True)
                    if norm == name:
                        return pick_name(entry, importer)
                    right += 1

                break

        return ""

################################################################################
