################################################################################
#
# Copyright 2021-2024 Rocco Matano
# SPDX-License-Identifier: MIT
#
################################################################################

# inspired by
# https://randomascii.wordpress.com/2018/02/11/zombie-processes-are-eating-your-memory/

import sys
import collections
from ctwin32 import (
    ntdll,
    kernel,
    PROCESS_QUERY_LIMITED_INFORMATION,
    SE_DEBUG_PRIVILEGE
    )

################################################################################

def get_zombies(verbose):
    zombies = {}
    is_deleting = ntdll.PROCESS_EXTENDED_BASIC_FLAGS.IsProcessDeleting
    add_lf = False

    hdl = ntdll.NtGetNextProcess(None, PROCESS_QUERY_LIMITED_INFORMATION)
    while hdl:
        close_me = hdl
        try:
            pebi = ntdll.get_proc_ext_basic_info(hdl)
        except OSError as e:
            print(e)
        else:
            if (pebi.Flags & is_deleting) != 0:
                path = ntdll.proc_path_from_handle(hdl)
                zombies[hdl] = path
                close_me = None
                if verbose:
                    zpid = pebi.BasicInfo.UniqueProcessId
                    ppid = pebi.BasicInfo.InheritedFromUniqueProcessId
                    print(f"zpid = {zpid:5}, ppid = {ppid:5}, {path}")
                    add_lf = True
        hdl = ntdll.NtGetNextProcess(hdl, PROCESS_QUERY_LIMITED_INFORMATION)
        # only keep handles of zombies open
        if close_me:
            ntdll.NtClose(close_me)
    if add_lf:
        print()
    return zombies

################################################################################

def get_zombie_object_addresses(verbose):
    z = get_zombies(verbose)
    handles = ntdll.get_handles(kernel.GetCurrentProcessId())
    res = {h.Object: z[h.HandleValue] for h in handles if h.HandleValue in z}
    # Close the handles to the zombies so that we do not report that we ourself
    # hold on to them.
    for h in z:
        ntdll.NtClose(h)
    return res

################################################################################

def main():

    try:
        ntdll.RtlAdjustPrivilege(SE_DEBUG_PRIVILEGE, True)
    except OSError:
        print("\nFailed to enable privilege. Some results may be missing.\n")

    verbose = "-v" in sys.argv or "--verbose" in sys.argv

    def cnt2str(cnt):
        return f"{cnt} zombie{'s' if cnt > 1 else ''}"

    zombies = get_zombie_object_addresses(verbose)
    if len(zombies):
        print(f"Found {cnt2str(len(zombies))}.")
    else:
        print("No zombies found.")

    pids_and_paths = []
    gh = ntdll.get_grouped_handles()
    for pid, infos in gh.items():
        paths = []
        for info in infos:
            path = zombies.get(info.Object, "")
            if path:
                paths.append(path)
                del zombies[info.Object]
        if paths:
            pids_and_paths.append((pid, paths))

    for pid, zpaths in pids_and_paths:
        hpath = ntdll.proc_path_from_pid(pid)
        print(f"\n{cnt2str(len(zpaths))} held by {hpath} ({pid})")
        counted_zombies = collections.defaultdict(int)
        for p in zpaths:
            counted_zombies[p] += 1
        for path, cnt in counted_zombies.items():
            print(f"    {cnt2str(cnt)} of {path}")

    if zombies:
        print("\nFound no owner for:")
        for z in zombies.values():
            print(f"    {z}")

################################################################################

if __name__ == "__main__":
    main()

################################################################################
