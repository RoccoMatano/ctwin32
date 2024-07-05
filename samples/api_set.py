################################################################################
#
# Copyright 2021-2024 Rocco Matano
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
