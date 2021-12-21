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
from types import SimpleNamespace as _namespace

from .wtypes import *
from . import (
    kernel,
    _raise_if,
    _fun_fact,
    WAIT_FAILED,
    GWL_STYLE,
    GWL_EXSTYLE,
    INPUT_KEYBOARD,
    KEYEVENTF_KEYUP,
    MONITOR_DEFAULTTOPRIMARY,
    SWP_NOSIZE,
    SWP_NOZORDER,
    )
from .ntdll import proc_path_from_pid

_u32 = _ct.windll.user32
_ref = _ct.byref

################################################################################

_GetWindowThreadProcessId = _fun_fact(
    _u32.GetWindowThreadProcessId, (DWORD, HANDLE, PDWORD)
    )

def GetWindowThreadProcessId(hwnd):
    pid = DWORD()
    tid = _GetWindowThreadProcessId(hwnd, _ref(pid))
    return tid, pid.value

################################################################################

_GetWindowTextLength = _fun_fact(
    _u32.GetWindowTextLengthW, (INT, HWND)
    )

def GetWindowTextLength(hwnd):
    return _GetWindowTextLength(hwnd)

################################################################################

_GetWindowText = _fun_fact(
    _u32.GetWindowTextW, (INT, HWND, PWSTR, INT)
    )

def GetWindowText(hwnd):
    slen = GetWindowTextLength(hwnd)
    buf = _ct.create_unicode_buffer(slen + 1)
    res = _GetWindowText(hwnd, buf, slen + 1)
    _raise_if(res != slen)
    return buf.value

################################################################################

_GetClassName = _fun_fact(
    _u32.GetClassNameW, (INT, HWND, PWSTR, INT)
    )

def GetClassName(hwnd):
    size = 32
    while True:
        size *= 2
        buf = _ct.create_unicode_buffer(size)
        res = _GetClassName(hwnd, buf, buf._length_)
        _raise_if(not res)
        if res != size - 1:
            return buf.value

################################################################################

_GetWindowLong = _fun_fact(_u32.GetWindowLongW, (LONG, HWND, INT))

def GetWindowLong(hwnd, idx):
    return _GetWindowLong(hwnd, idx)

################################################################################

_GetWindowLongPtr = _fun_fact(
    _u32.GetWindowLongPtrW, (LONG_PTR, HWND, INT)
    )

def GetWindowLongPtr(hwnd, idx):
    return _GetWindowLongPtr(hwnd, idx)

################################################################################

class _EnumWindowsContext(_ct.Structure):
    _fields_ = (
        ("callback", _ct.py_object),
        ("context", _ct.py_object)
        )
_EnumWindowsContextPtr = _ct.POINTER(_EnumWindowsContext)

_EnumWindowsCallback = _ct.WINFUNCTYPE(
    BOOL,
    HWND,
    _EnumWindowsContextPtr
    )

@_EnumWindowsCallback
def _EnumWndCb(hwnd, ctxt):
    ewc = ctxt.contents
    return ewc.callback(hwnd, ewc.context)

################################################################################

_EnumWindows = _fun_fact(
    _u32.EnumWindows, (BOOL, _EnumWindowsCallback, _EnumWindowsContextPtr)
    )

def EnumWindows(callback, context):
    ewc = _EnumWindowsContext(callback, context)
    _EnumWindows(_EnumWndCb, _ref(ewc))

################################################################################

_EnumChildWindows = _fun_fact(
    _u32.EnumChildWindows,
    (BOOL, HWND, _EnumWindowsCallback, _EnumWindowsContextPtr)
    )

def EnumChildWindows(hwnd, callback, context):
    ewc = _EnumWindowsContext(callback, context)
    _EnumChildWindows(hwnd, _EnumWndCb, _ref(ewc))

################################################################################

_EnumThreadWindows = _fun_fact(
    _u32.EnumThreadWindows,
    (BOOL, DWORD, _EnumWindowsCallback, _EnumWindowsContextPtr)
    )

def EnumThreadWindows(tid, callback, context):
    ewc = _EnumWindowsContext(callback, context)
    _EnumThreadWindows(tid, _EnumWndCb, _ref(ewc))

################################################################################

def _get_wnd_lst_cb(hwnd, wnd_lst):
    tid, pid = GetWindowThreadProcessId(hwnd)
    d = _namespace(
        hwnd=hwnd,
        text=GetWindowText(hwnd),
        pid=pid,
        pname=proc_path_from_pid(pid),
        cls=GetClassName(hwnd),
        style=GetWindowLong(hwnd, GWL_STYLE),
        exstyle=GetWindowLong(hwnd, GWL_EXSTYLE)
        )
    wnd_lst.append(d)
    return True

def get_window_list():
    wnd_lst = []
    EnumWindows(_get_wnd_lst_cb, wnd_lst)
    return wnd_lst

def get_child_window_list(hwnd):
    wnd_lst = []
    EnumChildWindows(hwnd, _get_wnd_lst_cb, wnd_lst)
    return wnd_lst

def get_thread_window_list(tid):
    wnd_lst = []
    EnumThreadWindows(tid, _get_wnd_lst_cb, wnd_lst)
    return wnd_lst

################################################################################

_WaitForInputIdle = _fun_fact(
    _u32.WaitForInputIdle, (DWORD, HANDLE, DWORD)
    )

def WaitForInputIdle(proc, timeout):
    res = _WaitForInputIdle(proc, timeout)
    _raise_if(res == WAIT_FAILED)
    return res

################################################################################

_PostMessage = _fun_fact(
    _u32.PostMessageW,
    (BOOL, HWND, UINT, UINT_PTR, LONG_PTR)
    )

def PostMessage(hwnd, msg, wp, lp):
    _raise_if(not _PostMessage(hwnd, msg, wp, lp))

################################################################################

_SendMessage = _fun_fact(
    _u32.SendMessageW,
    (LONG_PTR, HWND, UINT, UINT_PTR, LONG_PTR)
    )

def SendMessage(hwnd, msg, wp, lp):
    return _SendMessage(hwnd, msg, wp, lp)

################################################################################

_SendMessageTimeout = _fun_fact(
    _u32.SendMessageTimeoutW, (
        LONG_PTR,
        HWND,
        UINT,
        UINT_PTR,
        LONG_PTR,
        UINT,
        UINT,
        PDWORD
        )
    )

def SendMessageTimeout(hwnd, msg, wp, lp, flags, timeout):
    result = DWORD()
    _raise_if(
        0 == _SendMessageTimeout(
            hwnd,
            msg,
            wp,
            lp,
            flags,
            timeout,
            _ref(result)
            )
        )
    return result.value

################################################################################

_GetWindow = _fun_fact(_u32.GetWindow, (HWND, HWND, UINT))

def GetWindow(hwnd, cmd):
    return _GetWindow(hwnd, cmd)

################################################################################

_GetAsyncKeyState = _fun_fact(_u32.GetAsyncKeyState, (SHORT, INT))

def GetAsyncKeyState(vkey):
    return _GetAsyncKeyState(vkey)

################################################################################

class RECT(_ct.Structure):
    _fields_ = (
        ("left", LONG),
        ("top", LONG),
        ("right", LONG),
        ("bottom", LONG)
        )

    @property
    def width(self):
        return self.right - self.left

    @property
    def height(self):
        return self.bottom - self.top

    @property
    def center(self):
        return (self.left + self.right) // 2, (self.top + self.bottom) // 2

PRECT = _ct.POINTER(RECT)

################################################################################

_GetWindowRect = _fun_fact(_u32.GetWindowRect, (BOOL, HWND, PRECT))

def GetWindowRect(hwnd):
   rc = RECT()
   _raise_if(not _GetWindowRect(hwnd, _ref(rc)))
   return rc

################################################################################

class POINT(_ct.Structure):
    _fields_ = (
        ("x", LONG),
        ("y", LONG)
        )

class WINDOWPLACEMENT(_ct.Structure):
    _fields_ = (
        ("length", UINT),
        ("flags", UINT),
        ("showCmd", UINT),
        ("MinPosition", POINT),
        ("MaxPosition", POINT),
        ("NormalPosition", RECT),
        )

    def __init__(self, f=0, s=1, mi=(0, 0), ma=(0, 0), no=(0, 0, 0, 0)):
        self.length = _ct.sizeof(WINDOWPLACEMENT)
        self.flags = f
        self.showCmd = s
        self.MinPosition = mi
        self.MaxPosition = ma
        self.NormalPosition = no

    def __repr__(self):
        c = self.__class__.__name__
        l = self.length
        f = self.flags
        s = self.showCmd
        mi = f"({self.MinPosition.x}, {self.MinPosition.y})"
        ma = f"({self.MaxPosition.x}, {self.MaxPosition.y})"
        no = (
            f"({self.NormalPosition.left}, {self.NormalPosition.top}, " +
            f"{self.NormalPosition.right}, {self.NormalPosition.bottom})"
            )
        return f"{c}({l}, {f}, {s}, {mi}, {ma}, {no})"

PWINDOWPLACEMENT = _ct.POINTER(WINDOWPLACEMENT)

################################################################################

_GetWindowPlacement = _fun_fact(
    _u32.GetWindowPlacement, (BOOL, HWND, PWINDOWPLACEMENT)
    )

def GetWindowPlacement(hwnd):
    wpt = WINDOWPLACEMENT()
    _raise_if(not _GetWindowPlacement(hwnd, _ct.byref(wpt)))
    return wpt

################################################################################

_SetWindowPlacement = _fun_fact(
    _u32.SetWindowPlacement, (BOOL, HWND, PWINDOWPLACEMENT)
    )

def SetWindowPlacement(hwnd, wpt):
    _raise_if(not _SetWindowPlacement(hwnd, _ct.byref(wpt)))

################################################################################

_SetWindowPos = _fun_fact(
    _u32.SetWindowPos, (BOOL, HWND, HWND, INT, INT, INT, INT, UINT)
    )

def SetWindowPos(hwnd, ins_after, x, y, cx, cy, flags):
    _raise_if(not _SetWindowPos(hwnd, ins_after, x, y, cx, cy, flags))

################################################################################

_AttachThreadInput = _fun_fact(
    _u32.AttachThreadInput, (BOOL, DWORD, DWORD, BOOL)
    )

def AttachThreadInput(id_attach, id_attach_to, do_attach):
    _raise_if(not _AttachThreadInput(id_attach, id_attach_to, do_attach))

################################################################################

_BringWindowToTop = _fun_fact(_u32.BringWindowToTop, (BOOL, HWND))

def BringWindowToTop(hwnd):
    _raise_if(not _BringWindowToTop(hwnd))

def to_top_maybe_attach(hwnd):
    wnd_id, _ = GetWindowThreadProcessId(hwnd)
    self_id = kernel.GetCurrentThreadId()
    if wnd_id != self_id:
        AttachThreadInput(self_id, wnd_id, True)
    BringWindowToTop(hwnd)
    if wnd_id != self_id:
        AttachThreadInput(self_id, wnd_id, False)

################################################################################

_SetActiveWindow = _fun_fact(_u32.SetActiveWindow, (HWND, HWND))

def SetActiveWindow(hwnd):
    return _SetActiveWindow(hwnd)

################################################################################

_MessageBox = _fun_fact(
    _u32.MessageBoxW, (INT, HWND, PWSTR, PWSTR, UINT)
    )

def MessageBox(hwnd, text, caption, flags):
    res = _MessageBox(hwnd, text, caption, flags)
    _raise_if(res == 0)
    return res

################################################################################

class MOUSEINPUT(_ct.Structure):
    _fields_ = (
        ("dx", LONG),
        ("dy", LONG),
        ("mouseData", DWORD),
        ("dwFlags", DWORD),
        ("time", DWORD),
        ("dwExtraInfo", UINT_PTR),
        )

class KEYBDINPUT(_ct.Structure):
    _fields_ = (
        ("wVk", WORD),
        ("wScan", WORD),
        ("dwFlags", DWORD),
        ("time", DWORD),
        ("dwExtraInfo", UINT_PTR),
        )

class HARDWAREINPUT(_ct.Structure):
    _fields_ = (
        ("uMsg", DWORD),
        ("wParamL", WORD),
        ("wParamH", WORD),
        )

class _DUMMY_INPUT_UNION(_ct.Union):
    _fields_ = (
        ("mi", MOUSEINPUT),
        ("ki", KEYBDINPUT),
        ("hi", HARDWAREINPUT),
        )

class INPUT(_ct.Structure):
    _anonymous_ = ("anon",)
    _fields_ = (
        ("type", DWORD),
        ("anon", _DUMMY_INPUT_UNION),
        )

    def copy(self):
        other = INPUT()
        _ct.memmove(_ref(other), _ref(self), _ct.sizeof(INPUT))
        return other

    def as_keyup(self):
        if not self.type == INPUT_KEYBOARD:
            raise ValueError("not INPUT_KEYBOARD")
        up = self.copy()
        up.ki.dwFlags |= KEYEVENTF_KEYUP
        return up

PINPUT = _ct.POINTER(INPUT)

################################################################################

def kb_input(vk, scan, flags=0):
    kip = INPUT()
    kip.type = INPUT_KEYBOARD
    kip.ki.wVk = vk
    kip.ki.wScan = scan
    kip.ki.dwFlags = flags
    return kip

################################################################################

_SendInput = _fun_fact(_u32.SendInput, (UINT, UINT, PINPUT, _ct.c_int))

def SendInput(inputs):
    if isinstance(inputs, INPUT):
        num, ptr = 1, _ref(inputs)
    else:
        try:
            num = len(inputs)
            if not num:
                return
            inputs = (INPUT * num)(*inputs)
            ptr = _ct.cast(inputs, PINPUT)
        except Exception as e:
            raise TypeError(f"expected INPUT or list of INPUTs: {e}")
    _raise_if(0 == _SendInput(num, ptr, _ct.sizeof(INPUT)))

################################################################################

_ExitWindowsEx = _fun_fact(_u32.ExitWindowsEx, (BOOL, UINT, DWORD))

def ExitWindowsEx(flags, reason):
    _raise_if(0 == _ExitWindowsEx(flags, reason))

################################################################################

_LockWorkStation = _fun_fact(_u32.LockWorkStation, (BOOL,))

def LockWorkStation():
    _raise_if(0 == _LockWorkStation())

################################################################################

_GetShellWindow = _fun_fact(_u32.GetShellWindow, (HWND,))

def GetShellWindow():
    return _GetShellWindow()

################################################################################

_MonitorFromWindow = _fun_fact(_u32.MonitorFromWindow, (HANDLE, HWND, DWORD))

def MonitorFromWindow(hwnd, flags=MONITOR_DEFAULTTOPRIMARY):
    return _MonitorFromWindow(hwnd, flags)

################################################################################

class MONITORINFO(_ct.Structure):
    _fields_ = (
        ("cbSize", DWORD),
        ("rcMonitor", RECT),
        ("rcWork", RECT),
        ("dwFlags", DWORD),
        )
    def __init__(self):
        self.cbSize = _ct.sizeof(MONITORINFO)

PMONITORINFO = _ct.POINTER(MONITORINFO)

################################################################################

_GetMonitorInfo = _fun_fact(_u32.GetMonitorInfoW, (BOOL, HANDLE, PMONITORINFO))

def GetMonitorInfo(hmon):
    mi = MONITORINFO()
    _raise_if(not _GetMonitorInfo(hmon, _ref(mi)))
    return mi

################################################################################

def start_centered(arglist):
    def center_wnd_cb(hwnd, _):
        wa = GetMonitorInfo(MonitorFromWindow(hwnd)).rcWork
        rc = GetWindowRect(hwnd)
        SetWindowPos(
            hwnd,
            None,
            (wa.width - rc.width) // 2,
            (wa.height - rc.height) // 2,
            0,
            0,
            SWP_NOSIZE | SWP_NOZORDER
            )
        return True

    with kernel.create_process(arglist) as pi:
        WaitForInputIdle(pi.hProcess, 10000)
        EnumThreadWindows(pi.dwThreadId, center_wnd_cb, None)

################################################################################

