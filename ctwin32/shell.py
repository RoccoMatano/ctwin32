################################################################################
#
# Copyright 2021 Rocco Matano
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

import ctypes as _ct
import ctypes.wintypes as _wt

from . import INFINITE, SW_SHOW, SEE_MASK_NOCLOSEPROCESS, _raise_if, _fun_fact
from .kernel import WaitForSingleObject, CloseHandle

################################################################################

class SHELLEXECUTEINFOW(_ct.Structure):
    _fields_ = (
        ("cbSize", _wt.DWORD),
        ("fMask", _wt.DWORD),
        ("hwnd", _wt.HWND),
        ("lpVerb", _wt.LPCWSTR),
        ("lpFile", _wt.LPCWSTR),
        ("lpParameters", _wt.LPCWSTR),
        ("lpDirectory", _wt.LPCWSTR),
        ("nShow", _wt.INT),
        ("hInstApp", _wt.HINSTANCE),
        ("lpIDList", _wt.LPVOID),
        ("lpClass", _wt.LPCWSTR),
        ("hkeyClass", _wt.HKEY),
        ("dwHotKey", _wt.DWORD),
        ("hMonitor", _wt.HANDLE),
        ("hProcess", _wt.HANDLE),
        )
    def __init__(self, file, verb, param, direc, wait, show):
        self.cbSize = _ct.sizeof(self)
        self.lpVerb = verb
        self.lpFile = file
        self.lpParameters = param
        self.lpDirectory = direc
        self.nShow = show
        self.fMask = SEE_MASK_NOCLOSEPROCESS if wait else 0

################################################################################

_ShellExecuteExW = _fun_fact(
    _ct.windll.shell32.ShellExecuteExW,
    (_wt.BOOL, _ct.POINTER(SHELLEXECUTEINFOW))
    )

################################################################################

def ShellExecuteEx(
    file,
    verb=None,
    param=None,
    direc=None,
    wait=False,
    show=SW_SHOW
    ):
    sei = SHELLEXECUTEINFOW(file, verb, param, direc, wait, show)

    _raise_if(not _ShellExecuteExW(_ct.byref(sei)))

    if sei.hProcess is not None:
        WaitForSingleObject(sei.hProcess, INFINITE);
        CloseHandle(sei.hProcess);

################################################################################

def elevate(*args, direc=None, wait=False, show=SW_SHOW):
    ShellExecuteEx(args[0], "runas", " ".join(args[1:]), direc, wait, show)

################################################################################
