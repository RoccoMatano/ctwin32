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

# inspired by https://docs.microsoft.com/en-us/sysinternals/downloads/pipelist

from ctwin32 import ntdll, kernel

################################################################################

def list_pipes():
    with kernel.create_file("\\\\.\\Pipe\\") as pipes:
        print("Inst  Max  Pipe Name")
        print("----  ---  ---------")
        for info in ntdll.enum_directory_info(pipes):
            instances = info.EndOfFile
            max_inst = info.AllocationSize
            if max_inst == 2 ** 32 - 1:
                max_inst = -1
            print(f"{instances:4d}  {max_inst:3d}  {info.FileName}")

################################################################################

if __name__ == "__main__":
    list_pipes()
