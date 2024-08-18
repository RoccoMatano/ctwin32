################################################################################
#
# Copyright 2021-2024 Rocco Matano
# SPDX-License-Identifier: MIT
#
################################################################################
#
# This sample demonstrates the use API sets. It only supports version
# 6 API sets (Windows >= 10). You can either dump all entries by not
# supplying any argument or you can lookup an Api set DLL name (e.g.
# api-ms-win-base-util-l1-1-0.dll) by supplying such a name as a single
# argument.
#
################################################################################

import sys
from ctwin32 import pemap

################################################################################

if __name__ == "__main__":
    api_set = pemap.ApiSet()
    if not api_set.count:
        print("Api set not present or unsupported version.")
    elif len(sys.argv) > 1:
        print(f"{sys.argv[1]} -> {api_set.lookup(sys.argv[1])}")
    else:
        for entry, targets in api_set.enum_entries():
            print(f"{entry:>58} -> {', '.join(targets)}")

################################################################################
