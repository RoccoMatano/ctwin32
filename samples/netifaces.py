################################################################################
#
# Copyright 2021-2026 Rocco Matano
# SPDX-License-Identifier: MIT
#
################################################################################

# get_host_interfaces offers similar functionality as netifaces

from ctwin32.iphlpapi import (
    get_host_interfaces,
    netifaces,
    gateways,
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
for guid, ifaces in get_host_interfaces(None, include_loopback=True).items():
    alias = ConvertInterfaceLuidToAlias(ConvertInterfaceGuidToLuid(guid))
    print(f"\nAdapter: {alias}, {guid}")
    for nif in ifaces:
        print(f"    {nif!r}")


print("\n\nnetifaces:")
for ifaces in netifaces(None, include_loopback=True):
    print(f"\nIndex: {ifaces.idx}, Adapter: {ifaces.alias}, {ifaces.guid}")
    if ifaces.phys_addr:
        mac = ":".join(f"{b:02X}" for b in ifaces.phys_addr)
        print(f"    MAC: {mac}")
    for nif in ifaces.ifaces:
        print(f"    {nif!r}")

print("\n\ngateways:\n")
for luid, gw in gateways().items():
    print(f"    {ConvertInterfaceLuidToAlias(luid)}")
    for g in gw:
        print(f"        {g!r}")
