################################################################################
#
# Copyright 2021-2024 Rocco Matano
# SPDX-License-Identifier: MIT
#
################################################################################

import ctypes
from . import (
    kernel,
    ntdll,
    ERROR_BAD_EXE_FORMAT,
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
    DWORD,
    PTR_64_BIT,
    PVOID,
    ULONG,
    ULONGLONG,
    WCHAR_SIZE,
    WORD,
    )

################################################################################

class classproperty(property):
    def __get__(self, owner, owner_type):
        return self.fget(owner_type)

################################################################################

class SizedStruct(ctypes.Structure):
    @classproperty
    def _size_(cls): # noqa: N805 this IS a class method
        return ctypes.sizeof(cls)

################################################################################

class IMAGE_FILE_HEADER(SizedStruct):
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

class IMAGE_DATA_DIRECTORY(SizedStruct):
    _fields_ = (
        ("VirtualAddress", DWORD),
        ("Size", DWORD),
        )

################################################################################

class IMAGE_OPTIONAL_HEADER32(SizedStruct):
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

class IMAGE_OPTIONAL_HEADER64(SizedStruct):
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

class IMAGE_SECTION_HEADER(SizedStruct):
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

class IMAGE_EXPORT_DIRECTORY(SizedStruct):
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

class IID_UNION(ctypes.Union):
    _fields_ = (
        ("Characteristics", DWORD),
        ("OriginalFirstThunk", DWORD),
        )

class IMAGE_IMPORT_DESCRIPTOR(SizedStruct):
    _anonymous_ = ("anon",)
    _fields_ = (
        ("anon", IID_UNION),
        ("TimeDateStamp", DWORD),
        ("ForwarderChain", DWORD),
        ("Name", DWORD),
        ("FirstThunk", DWORD),
        )

################################################################################

class ImgDelayDescr(SizedStruct):
    _fields_ = (
        ("grAttrs", DWORD),
        ("rvaDLLName", DWORD),
        ("rvaHmod", DWORD),
        ("rvaIAT", DWORD),
        ("rvaINT", DWORD),
        ("rvaBoundIAT", DWORD),
        ("rvaUnloadIAT", DWORD),
        ("dwTimeStamp", DWORD),
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
            f = kernel.create_file(str(fname), GENERIC_READ)
        except OSError as e:
            if convert_open_err:
                raise NotPeError(fname, e.winerror) from e
            raise

        with f:
            self.size = kernel.GetFileSize(f)
            if self.size < (self.E_LFANEW + 4):
                raise NotPeError(fname)
            with kernel.CreateFileMapping(f, None, PAGE_READONLY, 0) as m:
                self.view = kernel.MapViewOfFile(m, FILE_MAP_READ, 0, 0)

        if fhaddr := self._file_header_addr():
            self.name = fname
            self.file_hdr = IMAGE_FILE_HEADER.from_address(fhaddr)
            ohaddr = fhaddr + ctypes.sizeof(IMAGE_FILE_HEADER)
            self.opt_hdr = IMAGE_OPTIONAL_HEADER64.from_address(ohaddr)
            self.is64bit = True
            if self.opt_hdr.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC:
                self.is64bit = False
                self.opt_hdr = IMAGE_OPTIONAL_HEADER32.from_address(ohaddr)

            secaddr = ohaddr + self.file_hdr.SizeOfOptionalHeader
            size = ctypes.sizeof(IMAGE_SECTION_HEADER)
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

################################################################################

class API_SET_NAMESPACE(SizedStruct):
    _fields_ = (
        ("Version", ULONG),
        ("Size", ULONG),
        ("Flags", ULONG),
        ("Count", ULONG),
        ("EntryOffset", ULONG),
        ("HashOffset", ULONG),
        ("HashFactor", ULONG),
        )

class API_SET_NAMESPACE_ENTRY(SizedStruct):
    _fields_ = (
        ("Flags", ULONG),
        ("NameOffset", ULONG),
        ("NameLength", ULONG),
        ("HashedLength", ULONG),
        ("ValueOffset", ULONG),
        ("ValueCount", ULONG),
        )

class API_SET_VALUE_ENTRY(SizedStruct):
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
        offs = 0x68 if PTR_64_BIT else 0x38
        base = PVOID.from_address(ntdll.RtlGetCurrentPeb() + offs).value
        apiset = API_SET_NAMESPACE.from_address(base)
        if apiset.Version == 6:
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
