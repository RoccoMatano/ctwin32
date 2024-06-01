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
from .wtypes import string_buffer, DWORD, PWSTR
from . import fun_fact, raise_on_zero

################################################################################

_dbghlp = ctypes.WinDLL("dbghelp.dll", use_last_error=True)

UNDNAME_COMPLETE = 0x0000
UNDNAME_NO_LEADING_UNDERSCORES = 0x0001
UNDNAME_NO_MS_KEYWORDS = 0x0002
UNDNAME_NO_FUNCTION_RETURNS = 0x0004
UNDNAME_NO_ALLOCATION_MODEL = 0x0008
UNDNAME_NO_ALLOCATION_LANGUAGE = 0x0010
UNDNAME_NO_MS_THISTYPE = 0x0020
UNDNAME_NO_CV_THISTYPE = 0x0040
UNDNAME_NO_THISTYPE = 0x0060
UNDNAME_NO_ACCESS_SPECIFIERS = 0x0080
UNDNAME_NO_THROW_SIGNATURES = 0x0100
UNDNAME_NO_MEMBER_TYPE = 0x0200
UNDNAME_NO_RETURN_UDT_MODEL = 0x0400
UNDNAME_32_BIT_DECODE = 0x0800
UNDNAME_NAME_ONLY = 0x1000
UNDNAME_NO_ARGUMENTS = 0x2000
UNDNAME_NO_SPECIAL_SYMS = 0x4000

################################################################################

_UnDecorateSymbolName = fun_fact(
    _dbghlp.UnDecorateSymbolNameW, (DWORD, PWSTR, PWSTR, DWORD, DWORD)
    )

def UnDecorateSymbolName(sym_name, flags=UNDNAME_COMPLETE):
    size = 256
    while True:
        buf = string_buffer(size)
        result = _UnDecorateSymbolName(sym_name, buf, size, flags)
        raise_on_zero(result)
        if result <= size - 4:
            return buf.value
        size *= 2

################################################################################
