################################################################################
#
# Copyright 2021-2025 Rocco Matano
# SPDX-License-Identifier: MIT
#
################################################################################
#
# This script lists the DLL dependencies of an executable PE file.
#
################################################################################

import os
from pathlib import Path
from argparse import ArgumentParser
from types import SimpleNamespace as nspace

from ctwin32 import (
    DIRECTORY_QUERY,
    IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT,
    IMAGE_DIRECTORY_ENTRY_IMPORT,
    kernel,
    ntdll,
    )
from ctwin32.pemap import (
    ApiSet,
    dlattrRva,
    IMAGE_IMPORT_DESCRIPTOR,
    IMAGE_DELAYLOAD_DESCRIPTOR,
    pemap,
    )

API_SET = ApiSet()

################################################################################

def get_known_dlls(for_wow=False):
    sdir = Path(
        kernel.GetSystemDirectory() if not for_wow
        else kernel.GetSystemWow64Directory()
        )
    oa = ntdll.obj_attr(r"\KnownDlls32" if for_wow else r"\KnownDlls")
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
        self.tree = nspace(name=key, children=[])
        self.mods = {key: nspace(elem=self.tree, path=path, resolved=False)}

    def add_dll(self, dependant, dll, path, is_delayed):
        dep = self.mods[dependant.lower()].elem
        dll = dll.lower()
        if dll in (c.name for c in dep.children):
            return
        child = nspace(name=dll, children=[])
        dep.children.append(child)
        if dll not in self.mods:
            if path is None:
                path = "<NOT FOUND>"
                resolved = True
            else:
                resolved = False
            self.mods[dll] = nspace(elem=child, path=path, resolved=resolved)

    def get_unresolved(self):
        return [m.path for m in self.mods.values() if not m.resolved]

    def mark_resolved(self, key):
        self.mods[key].resolved = True

    def _fmt_nodes(self, node=None, level=0, indent=4):
        res = []
        if node is None:
            node = self.tree
        res.append(f"{' ' * level * indent}{node.name}")
        for c in node.children:
            res.extend(self._fmt_nodes(c, level + 1, indent))
        return res

    def get_results(self):
        lines = self._fmt_nodes()
        mlst = [(k, v.path) for k, v in self.mods.items()]
        return mlst, self.tree, "\n".join(lines)

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
    mpath = find_dll_path(mod_name, search_info)
    if mpath is None and "." not in mod_name:
        mname = mod_name + ".dll"
        if mpath := find_dll_path(mname, search_info):
            mod_name = mname
    return mod_name, mpath

################################################################################

def add_static_imports(imports, pe, search_info):
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
        imports.add_dll(pe.key, dll, path, False)

################################################################################

def add_delay_imports(imports, pe, search_info):
    rva, size = pe.img_dir(IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT)
    if not rva:
        return
    offs = pe.offs_from_rva(rva)
    if not offs:
        return
    idx = 0
    while True:
        idd = pe.ctypes_obj(IMAGE_DELAYLOAD_DESCRIPTOR, offs, idx)
        idx += 1
        if idd.DllNameRVA == 0 or (idd.Attributes & dlattrRva) == 0:
            break
        dll, path = get_imported_mod(pe, idd.DllNameRVA, search_info)
        imports.add_dll(pe.key, dll, path, True)

################################################################################

def get_dep_tree(filename, delayed):
    with pemap(filename) as pe:
        imports = Imports(pe.key, pe.name)
        search_info = (
            get_known_dlls(pe.is_wow()),
            get_dll_search_dirs(Path(pe.name).parent, pe.is_wow())
            )
    while unresolved := imports.get_unresolved():
        for path in unresolved:
            with pemap(path) as pe:
                add_static_imports(imports, pe, search_info)
                if delayed:
                    add_delay_imports(imports, pe, search_info)
                imports.mark_resolved(pe.key)

    return imports.get_results()

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

    mod_list, tree, formatted_tree = get_dep_tree(args.filename, args.delay)

    max_name_len = max(len(n) for n, _ in mod_list) + 1
    print(f"\nlist of modules ({len(mod_list)}):\n")
    for name, path in mod_list:
        print(f"{name:{max_name_len}}: {path}")
    print("\n\ndependency tree:\n")
    print(formatted_tree)

################################################################################

if __name__ == "__main__":
    dep_tree()

################################################################################
