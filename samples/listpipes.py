################################################################################
#
# Copyright 2021-2024 Rocco Matano
# SPDX-License-Identifier: MIT
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
            if (max_inst := info.AllocationSize) == 2 ** 32 - 1:
                max_inst = -1
            print(f"{instances:4d}  {max_inst:3d}  {info.FileName}")

################################################################################

if __name__ == "__main__":
    list_pipes()
