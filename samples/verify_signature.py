################################################################################
#
# Copyright 2021-2026 Rocco Matano
# SPDX-License-Identifier: MIT
#
################################################################################
#
# This sample demonstrates how to verify the signature of an PE file.
#
################################################################################

import sys
from ctwin32 import wintrust

path = sys.argv[1] if len(sys.argv) >= 2 else sys.executable
status, msg, certs = wintrust.verify_embedded_signature(path)

print(f"\nConclusion for '{path}':")
print(f"{msg} ({status=})")
for c in certs:
    display_ts = c.timestamp.replace(microsecond=0, tzinfo=None)
    display_sn = " ".join(f"{b:02x}" for b in c.serial_number)
    print(f"\nSubject Name  : {c.subject_name}")
    print(f"Issuer Name   : {c.issuer_name}")
    print(f"Algorithm     : {c.algorithm}")
    print(f"Timestamp     : {display_ts}")
    print(f"Serial Number : {display_sn}")
