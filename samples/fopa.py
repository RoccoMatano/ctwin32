################################################################################
#
# Copyright 2021-2024 Rocco Matano
# SPDX-License-Identifier: MIT
#
################################################################################

from ctwin32 import shell, wtypes

E_FILE_NOT_FOUND = wtypes.LONG(0x80070002).value

for name in shell.__dict__:
    if name.startswith("CSIDL_"):
        csidl = getattr(shell, name)
        if (csidl & shell.CSIDL_FLAG_MASK) == 0:
            try:
                folder = shell.SHGetFolderPath(csidl)
            except OSError as e:
                if e.winerror == E_FILE_NOT_FOUND:
                    nvid = csidl | shell.CSIDL_FLAG_DONT_VERIFY
                    try:
                        folder = "* " + shell.SHGetFolderPath(nvid)
                    except OSError as e:
                        folder = str(e)
                else:
                    folder = str(e)
            print(f"{name:30} {csidl:4x} = {folder}")

print("\n* : non-existent")
