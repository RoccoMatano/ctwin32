################################################################################
#
# Copyright 2021-2026 Rocco Matano
# SPDX-License-Identifier: MIT
#
################################################################################

from ctwin32 import (
    advapi,
    ntdll,
    SE_SYSTEM_ENVIRONMENT_PRIVILEGE,
    SystemEnvironmentValueInformation,
    )
from ctwin32.wtypes import GUID

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
        ascii = chunk.translate(_ascii_trans).decode("ascii")
        hexa = " ".join([f"{c:02x}" for c in chunk]).ljust(hex_chars)
        lines.append(f"{offset:08x} | {hexa} | {ascii}")
        offset += chunk_len
    return "\n".join(lines)

################################################################################

def main():
    ntdll.RtlAdjustPrivilege(SE_SYSTEM_ENVIRONMENT_PRIVILEGE, True)
    info_cls = SystemEnvironmentValueInformation
    known_guids = {
        GUID("{8BE4DF61-93CA-11D2-AA0D-00E098032B8C}") : "EFI_GLOBAL",
        GUID("{77FA9ABD-0359-4D32-BD60-28F4E78F784B}") : "Windows",
        GUID("{d719b2cb-3d3a-4596-a3bc-dad00e67656f}") : "SecurityDB",
        GUID("{4b3082a3-80c6-4d7e-9cd0-583917265df1}") : "SMBIOS",
        }

    res = ntdll.NtEnumerateSystemEnvironmentValuesEx(info_cls)
    for guid, name, attrib, value in res:
        gs = f" -> {known_guids[guid]}" if guid in known_guids else ""
        print(f"vendor GUID: {guid}{gs}")
        print(f"name: {name}")
        print(f"attributes: {attrib:#x}")
        print(hexdump(value))
        print()

################################################################################

if __name__ == "__main__":

    if not advapi.running_as_admin():
        print(
            "Accessing firmware variables requires administrative privileges."
            )
    else:
        main()

################################################################################
