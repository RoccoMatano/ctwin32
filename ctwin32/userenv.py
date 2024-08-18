################################################################################
#
# Copyright 2021-2024 Rocco Matano
# SPDX-License-Identifier: MIT
#
################################################################################

import ctypes
from .wtypes import (
    BOOL,
    HANDLE,
    PPVOID,
    PVOID,
    )
from . import (
    ref,
    fun_fact,
    raise_on_zero,
    multi_str_from_addr,
    TOKEN_READ,
    kernel,
    advapi,
    )

################################################################################

_ue = ctypes.WinDLL("userenv.dll", use_last_error=True)

_DestroyEnvironmentBlock = fun_fact(
    _ue.DestroyEnvironmentBlock, (BOOL, PVOID)
    )

_CreateEnvironmentBlock = fun_fact(
    _ue.CreateEnvironmentBlock, (BOOL, PPVOID, HANDLE, BOOL)
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

def CreateEnvironmentBlock(token=None, inherit=False):
    if token is None:
        with advapi.OpenProcessToken(
                kernel.GetCurrentProcess(),
                TOKEN_READ
                ) as t:
            return _env_block_from_token(t, inherit)
    else:
        return _env_block_from_token(token, inherit)

################################################################################

def create_env_block_as_dict(token=None, inherit=False):
    return kernel.env_str_to_dict(CreateEnvironmentBlock(token, inherit))

################################################################################
