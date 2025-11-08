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
    WinError,
    string_buffer,
    )
from . import (
    ApiDll,
    ref,
    raise_on_zero,
    multi_str_from_addr,
    TOKEN_READ,
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

def _env_block_from_token(token, inherit):
    ptr = PVOID()
    raise_on_zero(_CreateEnvironmentBlock(ref(ptr), token, inherit))
    try:
        return multi_str_from_addr(ptr.value)
    finally:
        raise_on_zero(_DestroyEnvironmentBlock(ptr))

################################################################################

def _profile_directory_from_token(token):
    size = DWORD(0)
    if _GetUserProfileDirectory(token, None, ref(size)):
        raise WinError()
    dname = string_buffer(size.value)
    raise_on_zero(_GetUserProfileDirectory(token, dname, ref(size)))
    return dname.value

################################################################################

def _func_opt_token(func, token, *args):
    if token is None:
        with advapi.OpenProcessToken(
                kernel.GetCurrentProcess(),
                TOKEN_READ
                ) as t:
            return func(*(t, *args))
    else:
        return func(*(token, *args))

################################################################################

def CreateEnvironmentBlock(token=None, inherit=False):
    return _func_opt_token(_env_block_from_token, token, inherit)

################################################################################

def create_env_block_as_dict(token=None, inherit=False):
    return kernel.env_str_to_dict(CreateEnvironmentBlock(token, inherit))

################################################################################

def GetUserProfileDirectory(token=None):
    return _func_opt_token(_profile_directory_from_token, token)

################################################################################
