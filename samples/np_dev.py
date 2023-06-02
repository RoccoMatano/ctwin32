################################################################################
#
# Copyright 2021-2023 Rocco Matano
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

import sys
from ctwin32 import advapi, shell
from ctwin32.setupapi import (
    get_non_present_info_set,
    enum_info_set,
    remove_non_present_devices,
    SetupDiGetDeviceInstanceId,
    desc_from_info_set,
    )

################################################################################

def print_non_present():
    print("non present devices:")
    for iset, ddat in enum_info_set(get_non_present_info_set()):
        desc = desc_from_info_set(iset, ddat)
        iid = SetupDiGetDeviceInstanceId(iset, ddat)
        print(f"{desc:40s} {iid}")

################################################################################

do_remove = len(sys.argv) > 1 and sys.argv[1] == "-r"
have_to_elevate = do_remove and not advapi.running_as_admin()

if have_to_elevate:
    shell.elevate(f'"{sys.executable}"', f'"{__file__}"', "-r")
else:
    print_non_present()
    if do_remove:
        print("\nremoving non present devices ...\n")
        remove_non_present_devices()
        print_non_present()
