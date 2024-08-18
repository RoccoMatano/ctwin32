################################################################################
#
# Copyright 2021-2024 Rocco Matano
# SPDX-License-Identifier: MIT
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
