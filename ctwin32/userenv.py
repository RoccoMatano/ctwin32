################################################################################
#
# Copyright 2021-2025 Rocco Matano
# SPDX-License-Identifier: MIT
#
################################################################################

from .wtypes import (
    BOOL,
    DWORD,
    HANDLE,
    PDWORD,
    PPVOID,
    PVOID,
    PWSTR,
    string_buffer,
    )
from . import (
    ApiDll,
    ref,
    raise_on_zero,
    multi_str_from_addr,
    kernel,
    advapi,
    )

################################################################################

_ue = ApiDll("userenv.dll")

_DestroyEnvironmentBlock = _ue.fun_fact(
    "DestroyEnvironmentBlock",
    (BOOL, PVOID)
    )

_CreateEnvironmentBlock = _ue.fun_fact(
    "CreateEnvironmentBlock",
    (BOOL, PPVOID, HANDLE, BOOL)
    )

_GetUserProfileDirectory = _ue.fun_fact(
    "GetUserProfileDirectoryW",
    (BOOL, HANDLE, PWSTR, PDWORD)
    )

################################################################################

def CreateEnvironmentBlock(token=None, inherit=False):
    if token is None:
        token = advapi.GetCurrentProcessToken()
    ptr = PVOID()
    raise_on_zero(_CreateEnvironmentBlock(ref(ptr), token, inherit))
    try:
        return multi_str_from_addr(ptr.value)
    finally:
        raise_on_zero(_DestroyEnvironmentBlock(ptr))

################################################################################

def create_env_block_as_dict(token=None, inherit=False):
    return kernel.env_str_to_dict(CreateEnvironmentBlock(token, inherit))

################################################################################

def GetUserProfileDirectory(token=None):
    if token is None:
        token = advapi.GetCurrentProcessToken()
    size = DWORD(0)
    _GetUserProfileDirectory(token, None, ref(size))
    dname = string_buffer(size.value)
    raise_on_zero(_GetUserProfileDirectory(token, dname, ref(size)))
    return dname.value

################################################################################
