################################################################################
#
# Copyright 2021-2024 Rocco Matano
# SPDX-License-Identifier: MIT
#
################################################################################

# demonstrate device enumerators from setupapi

from ctwin32.setupapi import (
    enum_info_set,
    SetupDiGetClassDevs,
    SetupDiGetDeviceInstanceId,
    get_device_enumerators,
    get_device_classes,
    SetupDiClassNameFromGuid,
    desc_from_info_set,
    )

for e in get_device_enumerators():
    print(f"\nEnumerator {e}:")
    for iset, ddat in enum_info_set(SetupDiGetClassDevs(enumerator=e)):
        try:
            desc = desc_from_info_set(iset, ddat)
        except OSError:
            desc = "UNKNOWN"
        iid = SetupDiGetDeviceInstanceId(iset, ddat)
        print(f"  {desc:50s} {iid}")

for g in get_device_classes():
    cn = SetupDiClassNameFromGuid(g)
    print(f"\nDevice class {g}, {cn}:")
    for iset, ddat in enum_info_set(SetupDiGetClassDevs(guid=g)):
        try:
            desc = desc_from_info_set(iset, ddat)
        except OSError:
            desc = "UNKNOWN"
        iid = SetupDiGetDeviceInstanceId(iset, ddat)
        print(f"  {desc:50s} {iid}")
