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

import sys
from ctwin32 import msi

################################################################################

def extract_binaries_from_msi(msi_path):
    with msi.MsiOpenDatabase(msi_path, msi.MSIDBOPEN_READONLY) as db:
        with msi.MsiDatabaseOpenView(db, "SELECT * FROM Binary") as view:
            msi.MsiViewExecute(view, None)
            for record in msi.view_enum_records(view):
                name = msi.MsiRecordGetString(record, msi.BIN_NAME_IDX)
                print(f"extracting '{name}'")
                data = msi.record_read_stream_all(record, msi.BIN_DATA_IDX)
                with open(name, "wb") as binfile:
                    binfile.write(data)

################################################################################

if __name__ == "__main__":
    if len(sys.argv) > 1:
        extract_binaries_from_msi(sys.argv[1])
    else:
        print("missing MSI path parameter", file=sys.stderr)
        sys.exit(1)

################################################################################
