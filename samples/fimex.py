################################################################################
#
# Copyright 2021-2024 Rocco Matano
# SPDX-License-Identifier: MIT
#
################################################################################
#
# This script can list imported and exported functions of executable PE files.
#
################################################################################

from argparse import ArgumentParser
from contextlib import suppress
from pathlib import Path

from ctwin32 import (
    IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT,
    IMAGE_DIRECTORY_ENTRY_EXPORT,
    IMAGE_DIRECTORY_ENTRY_IMPORT,
    IMAGE_ORDINAL_FLAG32,
    IMAGE_ORDINAL_FLAG64,
    )
from ctwin32.pemap import (
    ApiSet,
    dlattrRva,
    IMAGE_EXPORT_DIRECTORY,
    IMAGE_IMPORT_DESCRIPTOR,
    ImgDelayDescr,
    NotPeError,
    pemap,
    )

################################################################################

API_SET = ApiSet()

PM_STANDARD = 0
PM_EXP_ONLY = 1
PM_IMP_ONLY = 2
PM_IMP_ONLY_MOD_ONLY = 3
PM_IMP_OF_MOD_ONLY = 4

################################################################################

def name_in_names(name, names, src, indent, extra=None):
    for n in names:
        if n == "*" or n.lower() == name.lower():
            iname = f"{indent * ' '}{name}"
            return f"{iname} ({src} {extra})" if extra else f"{iname} ({src})"
    return None

################################################################################

def find_imp_funcs_one_mod(pe, offs_INT, names, src):
    result = []
    idx = 0
    if pe.is64bit:
        get_rva = pe.u64
        mask = IMAGE_ORDINAL_FLAG64
    else:
        get_rva = pe.u32
        mask = IMAGE_ORDINAL_FLAG32
    while True:
        rva = get_rva(offs_INT, idx)
        idx += 1
        if not rva:
            break
        if (mask & rva) == 0:
            # IMAGE_IMPORT_BY_NAME.Name
            name = pe.bstring(pe.offs_from_rva(rva) + 2)
        else:
            name = f"#{rva & 0xffff}"
        if found := name_in_names(name, names, src, 8):
            result.append(found)

    return result

################################################################################

def find_imports_one_mod(pe, mode, names, rva_name, rva_INT, src):
    mod_name = pe.bstring(pe.offs_from_rva(rva_name))
    mod_eq_n0 = names and mod_name.lower() == names[0].lower()
    if lu := API_SET.lookup(mod_name):
        mod_name = f"{mod_name} -> {lu}"
    if mode == PM_IMP_OF_MOD_ONLY:
        if mod_eq_n0:
            names = ["*"]
        else:
            return []
    elif mode == PM_IMP_ONLY_MOD_ONLY:
        return [f"    {src} {mod_name}"]

    if offs_INT := pe.offs_from_rva(rva_INT):
        if mod_res := find_imp_funcs_one_mod(pe, offs_INT, names, src):
            return [f"    {mod_name}", *mod_res]
    return []

################################################################################

def find_imports(pe, mode, names):
    result = []
    src = "import"
    im_rva, _ = pe.img_dir(IMAGE_DIRECTORY_ENTRY_IMPORT)
    if not im_rva:
        return result
    iid_offs = pe.offs_from_rva(im_rva)
    idx = 0
    while True:
        iid = pe.ctypes_obj(IMAGE_IMPORT_DESCRIPTOR, iid_offs, idx)
        idx += 1
        if iid.TimeDateStamp == 0 and iid.Name == 0:
            # end of imports
            break

        result.extend(
            find_imports_one_mod(
                pe,
                mode,
                names,
                iid.Name,
                iid.OriginalFirstThunk or iid.FirstThunk,
                src
                )
            )

    return result

################################################################################

def find_delay_imports(pe, mode, names):
    result = []
    src = "delay import"
    rva, size = pe.img_dir(IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT)
    if not rva:
        return result
    offs = pe.offs_from_rva(rva)
    if not offs:
        return result
    for i in range(size // ImgDelayDescr._size_):
        idd = pe.ctypes_obj(ImgDelayDescr, offs, i)
        if not idd.rvaDLLName:
            break
        if not (idd.grAttrs & dlattrRva):
            continue

        result.extend(
            find_imports_one_mod(
                pe,
                mode,
                names,
                idd.rvaDLLName,
                idd.rvaINT,
                src
                )
            )

    return result

################################################################################

def find_exports(pe, names):
    result = []
    ex_rva, ex_size = pe.img_dir(IMAGE_DIRECTORY_ENTRY_EXPORT)
    ex_end = ex_rva + ex_size
    if not ex_rva:
        return result
    exd = pe.ctypes_obj(IMAGE_EXPORT_DIRECTORY, pe.offs_from_rva(ex_rva))
    func = pe.offs_from_rva(exd.AddressOfFunctions)
    ords = pe.offs_from_rva(exd.AddressOfNameOrdinals)
    fnames = pe.offs_from_rva(exd.AddressOfNames)

    for i in range(exd.NumberOfNames):
        ord_mb = pe.u16(ords, i)
        name = pe.bstring(pe.offs_from_rva(pe.u32(fnames , i)))
        ep = pe.u32(func,  ord_mb)
        fwd = None
        if ex_rva <= ep < ex_end:
            dst = pe.bstring(pe.offs_from_rva(ep))
            fwd = f"forwarder -> {dst}"
        if found := name_in_names(name, names, "export", 4, fwd):
            result.append(found)

    return result

################################################################################

def fimex_in_file(path, mode, names):
    mode_exp = mode in (PM_STANDARD, PM_EXP_ONLY)
    mode_imp = mode in (
        PM_STANDARD,
        PM_IMP_ONLY,
        PM_IMP_ONLY_MOD_ONLY,
        PM_IMP_OF_MOD_ONLY
        )
    with suppress(NotPeError), pemap(path, convert_open_err=True) as pe:
        result = []
        if mode_exp:
            result.extend(find_exports(pe, names))
        if mode_imp:
            ires = find_imports(pe, mode, names)
            ires.extend(find_delay_imports(pe, mode, names))
            if ires and result:
                result.append("")
            result.extend(ires)
        if result:
            result.insert(0, str(path))
            result.append("")
            print("\n".join(result))

################################################################################

def parse_fimex_args():

    ape = ArgumentParser(description="find imports/exports")
    group = ape.add_mutually_exclusive_group()
    g = group.add_argument
    g("-e", "--exp", action="store_true", help="exports only")
    g("-i", "--imp", action="store_true", help="imports only")
    g("-I", "--imo", action="store_true", help="imported modules only")
    g("-m", "--mod", action="store_true", help="imports of module only")
    ape.add_argument("-p", "--path", help="path to search (default: current)")
    help="function names (default: any), in case of -m: module name"
    ape.add_argument("names", nargs="*", help=help)
    args = ape.parse_args()

    mode = PM_STANDARD
    if args.exp:
        mode = PM_EXP_ONLY
    elif args.imp:
        mode = PM_IMP_ONLY
    elif args.imo:
        mode = PM_IMP_ONLY_MOD_ONLY
    elif args.mod:
        mode = PM_IMP_OF_MOD_ONLY
    return Path("." if not args.path else args.path), mode, args.names

################################################################################

def fimex_main():
    path, mode, names = parse_fimex_args()
    if not names:
        names = ["*"]
    for root, _, files in path.walk():
        for f in files:
            fimex_in_file(root / f, mode, names)

################################################################################

if __name__ == "__main__":
    fimex_main()

################################################################################
