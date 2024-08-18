################################################################################
#
# Copyright 2021-2024 Rocco Matano
# SPDX-License-Identifier: MIT
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
