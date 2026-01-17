################################################################################
#
# Copyright 2021-2026 Rocco Matano
# SPDX-License-Identifier: MIT
#
################################################################################

import sys
from ctwin32 import (
    advapi,
    ntdll,
    SE_SYSTEM_ENVIRONMENT_PRIVILEGE,
    shell,
    SystemEnvironmentValueInformation,
    )

################################################################################

_ascii_trans = bytes([i if 32 <= i < 128 else ord(".") for i in range(256)])

def hexdump(data, bytes_per_line=16):
    lines = []
    hex_chars = bytes_per_line * 3 - 1
    length = len(data)
    offset = 0
    while offset < length:
        chunk_len = min(length - offset, bytes_per_line)
        chunk = data[offset : offset + chunk_len]
        ascii = chunk.translate(_ascii_trans).decode('ascii')
        hexa = " ".join([f"{c:02x}" for c in chunk]).ljust(hex_chars)
        lines.append(f"{offset:08x} | {hexa} | {ascii}")
        offset += chunk_len
    return "\n".join(lines)

################################################################################

def main():
    ntdll.RtlAdjustPrivilege(SE_SYSTEM_ENVIRONMENT_PRIVILEGE, True)
    info_cls = SystemEnvironmentValueInformation
    res = ntdll.NtEnumerateSystemEnvironmentValuesEx(info_cls)
    for guid, attrib, name, value in res:
        print(f"vendor GUID: {guid}")
        print(f"attributes: {attrib:#x}")
        print(f"name: {name}")
        print(hexdump(value), "\n")

################################################################################

if __name__ == "__main__":

    # accessing firmware variables requires administrative privileges.
    if not advapi.running_as_admin():
        shell.elevate(sys.executable, __file__)
    else:
        main()

################################################################################
