################################################################################
#
# Copyright 2021-2025 Rocco Matano
# SPDX-License-Identifier: MIT
#
################################################################################
#
# This sample illustrates the NT object namespace by printing the contents of
# of the root directory recursively,
#
################################################################################

from ctwin32 import (
    ntdll,
    suppress_winerr,
    DIRECTORY_QUERY,
    ERROR_ACCESS_DENIED,
    GENERIC_READ,
    )

################################################################################

def open_obj_dir(dir_name, access):
    return ntdll.NtOpenDirectoryObject(access, ntdll.obj_attr(dir_name))

################################################################################

def directory_contents(dir_name):
    with open_obj_dir(dir_name, DIRECTORY_QUERY) as hdir:
        return ntdll.NtQueryDirectoryObject(hdir)

################################################################################

def resolve_link(dir_name, link_name):
    with suppress_winerr(ERROR_ACCESS_DENIED):
        with open_obj_dir(dir_name, GENERIC_READ) as hdir:
            al = ntdll.obj_attr(link_name, hdir)
            with ntdll.NtOpenSymbolicLinkObject(GENERIC_READ, al) as hl:
                return ntdll.NtQuerySymbolicLinkObject(hl)
    return ""

################################################################################

def print_directory(dname, indent=""):
    try:
        info = directory_contents(dname)
    except OSError as e:
        if e.winerror == ERROR_ACCESS_DENIED:
            print(f"{indent}access denied (try running elevated)")
            return
        raise

    for oname, typ in info:
        lnk = "" if typ != "SymbolicLink" else resolve_link(dname, oname)
        print(f"{indent}{oname:<30} {typ:<20} {lnk}")
        if typ == "Directory":
            sub = f"{dname}\\{oname}" if len(dname) > 1 else f"\\{oname}"
            print_directory(sub, indent + "    ")

################################################################################

if __name__ == "__main__":
    print_directory("\\")

################################################################################
