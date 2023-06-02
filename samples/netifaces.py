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
