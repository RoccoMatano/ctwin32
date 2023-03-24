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

from ctwin32 import shell, wtypes

E_FILE_NOT_FOUND = wtypes.LONG(0x80070002).value

for name in shell.__dict__:
    if name.startswith("CSIDL_"):
        csidl = getattr(shell, name)
        if (csidl & shell.CSIDL_FLAG_MASK) == 0:
            try:
                folder = shell.SHGetFolderPath(csidl)
            except OSError as e:
                if e.winerror == E_FILE_NOT_FOUND:
                    nvid = csidl | shell.CSIDL_FLAG_DONT_VERIFY
                    try:
                        folder = "* " + shell.SHGetFolderPath(nvid)
                    except OSError as e:
                        folder = str(e)
                else:
                    folder = str(e)
            print(f"{name:30} {csidl:4x} = {folder}")

print("\n* : non-existent")
