################################################################################
#
# Copyright 2021-2025 Rocco Matano
# SPDX-License-Identifier: MIT
#
################################################################################

from .wtypes import (
    BOOL,
    HANDLE,
    PPVOID,
    PVOID,
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
