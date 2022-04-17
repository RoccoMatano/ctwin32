################################################################################
#
# Copyright 2021-2022 Rocco Matano
#
# Permission is hereby granted, free of charge, to any person obtaining a
# copy of this software and associated documentation files (the "Software"),
# to deal in the Software without restriction, including without limitation
# the rights to use, copy, modify, merge, publish, distribute, sublicense,
# and/or sell copies of the Software, and to permit persons to whom the
# Software is furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included
# in all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
# THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
# FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
# DEALINGS IN THE SOFTWARE.
#
################################################################################

# This sample demonstrates how to get the version information from the resource
# section of a PE file. It simply takes the python executuble as its test object.

import sys
import collections
from ctwin32 import version_info

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
        0xa: 'alpha',
        0xb: 'beta',
        0xc: 'candidate',
        0xf: 'final'
        }[level]
    ver_info = collections.namedtuple(
        'version_info',
        ["major", "minor", "micro", "releaselevel", "serial"]
        )(major, minor, micro, level, serial)
    return ver_info, api_ver

################################################################################

if __name__ == "__main__":

    # get binary version info from the executable file
    bin_info = version_info.get_binary_info(sys.executable)

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
    str_info = version_info.get_string_info(sys.executable)
    for i in sorted(str_info):
        print(f"{i:16} : {str_info[i]}")

################################################################################
