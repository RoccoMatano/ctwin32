################################################################################
#
# Copyright 2021-2024 Rocco Matano
# SPDX-License-Identifier: MIT
#
################################################################################
#
# This script lists the DLL dependencies of an executable PE file.
#
################################################################################

import os
from pathlib import Path
from contextlib import suppress
import xml.etree.ElementTree as ET
from argparse import ArgumentParser
from types import SimpleNamespace as nspace

from ctwin32 import (
    DIRECTORY_QUERY,
    IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT,
    IMAGE_DIRECTORY_ENTRY_IMPORT,
    kernel,
    ntdll,
    wtypes,
    )
from ctwin32.pemap import (
    ApiSet,
    dlattrRva,
    IMAGE_IMPORT_DESCRIPTOR,
    ImgDelayDescr,
    NotPeError,
    pemap,
    )

API_SET = ApiSet()

################################################################################

def get_known_dlls(for_wow=False):
    sdir = Path(
        kernel.GetSystemDirectory() if not for_wow
        else kernel.GetSystemWow64Directory()
        )
    odir = r"\KnownDlls32" if for_wow else r"\KnownDlls"
    kd = wtypes.UnicodeStrFromStr(odir)
    oa = ntdll.OBJECT_ATTRIBUTES(ObjectName = kd.ptr)
    with ntdll.NtOpenDirectoryObject(DIRECTORY_QUERY, oa) as hdir:
        name_type_lst = ntdll.NtQueryDirectoryObject(hdir)
    return {
        name.lower(): str(sdir / name)
        for name, typ in sorted(name_type_lst) if typ == "Section"
        }

################################################################################

def get_dll_search_dirs(mod_path, for_wow=False):
    nodup = set()
    result = []
    def append(sd):
        sd = str(sd)
        sdl = sd.lower()
        if sdl not in nodup:
            nodup.add(sdl)
            result.append(sd)
    append(mod_path)
    append(kernel.GetCurrentDirectory())
    append(
        kernel.GetSystemDirectory() if not for_wow
        else kernel.GetSystemWow64Directory()
        )
    append(kernel.GetWindowsDirectory())
    for p in os.environ["PATH"].split(";"):
        append(p)

    return result

################################################################################

class Imports():
    def __init__(self, key, path):
        pl = Path(path).name.lower()
        self.tree = ET.Element(pl, {"path": path})
        self.mods = {pl: nspace(elem=self.tree, resolved=False)}

    def add_dll(self, dependant, dll, path, is_delayed):
        # let this fail if dependant is unknown!
        dep = self.mods[dependant.lower()].elem
        dll = dll.lower()
        if (se := dep.find(dll)) is None:
            if path is None:
                path = "<NOT FOUND>"
                resolved = True
            else:
                resolved = False
            se = ET.SubElement(dep, dll, {"path": path})
            if dll not in self.mods:
                self.mods[dll] = nspace(elem=se, resolved=resolved)

    def get_unresolved(self):
        mods = self.mods
        return [
            e.get("path")
            for e in self.tree.iter()
            if not mods[e.tag].resolved
            ]

    def mark_resolved(self, tag):
        self.mods[tag].resolved = True

    def __str__(self):
        ET.indent(self.tree)
        return ET.tostring(self.tree).decode()

################################################################################

def find_dll_path(name, search_info):
    known_dlls, search_dirs = search_info
    try:
        return known_dlls[name.lower()]
    except KeyError:
        for d in search_dirs:
            p = Path(d) / name
            if p.exists():
                return str(p)
        return None

################################################################################

def get_imported_mod(pe, rva_name, search_info):
    mod_name = pe.bstring(pe.offs_from_rva(rva_name)).lower()
    if api := API_SET.lookup(mod_name):
        mod_name = api
    return mod_name, find_dll_path(mod_name, search_info)

################################################################################

def find_static_imports(pe, search_info, imps):
    im_rva, _ = pe.img_dir(IMAGE_DIRECTORY_ENTRY_IMPORT)
    if not im_rva:
        return
    iid_offs = pe.offs_from_rva(im_rva)
    idx = 0
    while True:
        iid = pe.ctypes_obj(IMAGE_IMPORT_DESCRIPTOR, iid_offs, idx)
        idx += 1
        if iid.TimeDateStamp == 0 and iid.Name == 0:
            # end of imports
            break
        dll, path = get_imported_mod(pe, iid.Name, search_info)
        imps.add_dll(pe.key, dll, path, False)


################################################################################

def find_delay_imports(pe, search_info, imps):
    rva, size = pe.img_dir(IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT)
    if not rva:
        return
    offs = pe.offs_from_rva(rva)
    if not offs:
        return
    for i in range(size // ImgDelayDescr._size_):
        idd = pe.ctypes_obj(ImgDelayDescr, offs, i)
        if not idd.rvaDLLName:
            break
        if not (idd.grAttrs & dlattrRva):
            continue
        dll, path = get_imported_mod(pe, idd.rvaDLLName, search_info)
        imps.add_dll(pe.key, dll, path, True)

################################################################################

def get_dep_tree(filename, delayed):
    with pemap(filename, convert_open_err=True) as pe:
        imps = Imports(pe.key, pe.name)
        search_info = (
            get_known_dlls(pe.is_wow()),
            get_dll_search_dirs(Path(pe.name).parent, pe.is_wow())
            )
        find_static_imports(pe, search_info, imps)
        if delayed:
            find_delay_imports(pe, search_info, imps)
        imps.mark_resolved(pe.key)
    while True:
        unresolved = imps.get_unresolved()
        if not unresolved:
            break
        for pth in unresolved:
            with suppress(NotPeError), pemap(pth, convert_open_err=True) as pe:
                find_static_imports(pe, search_info, imps)
                if delayed:
                    find_delay_imports(pe, search_info, imps)
                imps.mark_resolved(pe.key)

    print(len(imps.mods))
    return imps

################################################################################

def dep_tree():
    ape = ArgumentParser(description="determine dependency tree")
    ape.add_argument(
        "-d",
        "--delay",
        action="store_true",
        help="include delayed imports"
        )
    ape.add_argument("filename", help="name of file to examine")
    args = ape.parse_args()
    res = get_dep_tree(args.filename, args.delay)
    print(res)

################################################################################

if __name__ == "__main__":
    dep_tree()

################################################################################
