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
