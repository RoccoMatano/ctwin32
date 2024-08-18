################################################################################
#
# Copyright 2021-2024 Rocco Matano
# SPDX-License-Identifier: MIT
#
################################################################################

# This sample demonstrates how to get the version information from the resource
# resource section of a PE file. It simply takes the python executuble as its
# test object.

import sys
import collections
import ctwin32.version

################################################################################

def extract_py_ver(fver_ms, fver_ls):
    major = fver_ms >> 16
    minor = fver_ms & 0xffff
    field3 = fver_ls >> 16
    api_ver = fver_ls & 0xffff

    # see https://github.com/python/cpython/blob/main/PCbuild/field3.py
    micro, remainder = divmod(field3, 1000)
    level, serial = divmod(remainder, 10)
    level = {
        0xa: "alpha",
        0xb: "beta",
        0xc: "candidate",
        0xf: "final"
        }[level]
    ver_info = collections.namedtuple(
        "version_info",
        ["major", "minor", "micro", "releaselevel", "serial"]
        )(major, minor, micro, level, serial)
    return ver_info, api_ver

################################################################################

if __name__ == "__main__":

    # get binary version info from the executable file
    bin_info = ctwin32.version.get_binary_info(sys.executable)

    # extract the interesting values
    extr_ver_info, extr_api_ver = extract_py_ver(
        bin_info.dwFileVersionMS,
        bin_info.dwFileVersionLS
        )
    print(extr_ver_info)

    # compare those values with infos from sys
    if extr_ver_info != sys.version_info:
        raise ValueError("extracted version does not match sys.version_info")
    if extr_api_ver != sys.api_version:
        raise ValueError("extracted API version does not match sys.api_version")

    # just print the string infos
    print()
    str_info = ctwin32.version.get_string_info(sys.executable)
    for i in sorted(str_info):
        print(f"{i:16} : {str_info[i]}")

################################################################################
