################################################################################
#
# Copyright 2021-2024 Rocco Matano
# SPDX-License-Identifier: MIT
#
################################################################################

# get_host_interfaces offers similar functionality as netifaces

from ctwin32.iphlpapi import (
    get_host_interfaces,
    ConvertInterfaceGuidToLuid,
    ConvertInterfaceLuidToAlias,
    ConvertInterfaceIndexToLuid,
    )

print("\nAdapters by index:\n")
idx = 1
while True:
    try:
        alias = ConvertInterfaceLuidToAlias(ConvertInterfaceIndexToLuid(idx))
        print(f"{idx:3}: {alias}")
        idx += 1
    except OSError:
        break

print("\n\nInterfaces by adapter:")
for guid, ifaces in get_host_interfaces(None, True).items():
    alias = ConvertInterfaceLuidToAlias(ConvertInterfaceGuidToLuid(guid))
    print(f"\nAdapter: {alias}, {guid}")
    for nif in ifaces:
        print(f"    {nif!r}")
