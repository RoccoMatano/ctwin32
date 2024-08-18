################################################################################
#
# Copyright 2021-2024 Rocco Matano
# SPDX-License-Identifier: MIT
#
################################################################################
#
# This sample shows how to find files with hardlinks - or to be more precise -
# files with more than one hardlink.
#
################################################################################

import os
import uuid
from pathlib import Path
from ctwin32 import (
    kernel,
    suppress_winerr,
    ERROR_SHARING_VIOLATION,
    GENERIC_READ,
    ERROR_ACCESS_DENIED,
    )

################################################################################

def walk_files(pth):
    for root, _, files in pth.walk():
        for f in files:
            yield root / f

################################################################################

def get_file_id(name):
    with suppress_winerr(ERROR_ACCESS_DENIED):
        with kernel.create_file(str(name), GENERIC_READ) as hdl:
            info = kernel.GetFileInformationByHandle(hdl)
        return (info.nFileIndexHigh << 32) | info.nFileIndexLow
    return int.from_bytes(uuid.uuid4().bytes)

################################################################################

def hardlinks(name):
    drive = Path(name).resolve().drive
    try:
        hl = [f"{drive}{n}" for n in kernel.find_all_filenames(str(name))]
    except OSError as e:
        print(e, name)
        hl = [str(name)]
    fid = 0 if len(hl) < 2 else get_file_id(name)
    return fid, sorted(hl, key=len)

################################################################################

if __name__ == "__main__":

    seen = set()
    for name in walk_files(Path(os.environ["SYSTEMDRIVE"] + "\\")):
        with suppress_winerr(ERROR_SHARING_VIOLATION):
            fid, h = hardlinks(name)
            if len(h) > 1 and fid not in seen:
                seen.add(fid)
                print(h[0])
                for n in h[1:]:
                    print(f"    {n}")
                print()

    print(f"{len(seen)} files with more than one hardlink")

################################################################################
