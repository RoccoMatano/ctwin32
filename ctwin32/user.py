################################################################################
#
# Copyright 2021-2022 Rocco Matano
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
    GMEM_MOVEABLE,
    CF_UNICODETEXT,
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

_GetWindowText = _fun_fact(_u32.GetWindowTextW, (INT, HWND, PWSTR, INT))

def GetWindowText(hwnd):
    slen = GetWindowTextLength(hwnd)
    buf = _ct.create_unicode_buffer(slen + 1)
    res = _GetWindowText(hwnd, buf, slen + 1)
    _raise_if(res != slen)
    return buf.value

################################################################################

_SetWindowText = _fun_fact(_u32.SetWindowTextW, (BOOL, HWND, PWSTR))

def SetWindowText(hwnd, txt):
    _raise_if(not _SetWindowText(hwnd, txt))

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

_SetWindowLong = _fun_fact(
    _u32.SetWindowLongW, (LONG, HWND, INT, LONG)
    )

def SetWindowLong(hwnd, idx, value):
    return _SetWindowLong(hwnd, idx, value)

################################################################################

_SetWindowLongPtr = _fun_fact(
    _u32.SetWindowLongPtrW, (LONG_PTR, HWND, INT, LONG_PTR)
    )

def SetWindowLongPtr(hwnd, idx, value):
    return _SetWindowLongPtr(hwnd, idx, value)

################################################################################

_EnumWindowsCallback = _ct.WINFUNCTYPE(
    BOOL,
    HWND,
    CallbackContextPtr
    )

@_EnumWindowsCallback
def _EnumWndCb(hwnd, ctxt):
    cbc = ctxt.contents
    res = cbc.callback(hwnd, cbc.context)
    # keep on enumerating if the callback fails to return a value
    return res if res is not None else True

################################################################################

_EnumWindows = _fun_fact(
    _u32.EnumWindows, (BOOL, _EnumWindowsCallback, CallbackContextPtr)
    )

def EnumWindows(callback, context):
    cbc = CallbackContext(callback, context)
    _EnumWindows(_EnumWndCb, _ref(cbc))

################################################################################

_EnumChildWindows = _fun_fact(
    _u32.EnumChildWindows,
    (BOOL, HWND, _EnumWindowsCallback, CallbackContextPtr)
    )

def EnumChildWindows(hwnd, callback, context):
    cbc = CallbackContext(callback, context)
    _EnumChildWindows(hwnd, _EnumWndCb, _ref(cbc))

################################################################################

_EnumThreadWindows = _fun_fact(
    _u32.EnumThreadWindows,
    (BOOL, DWORD, _EnumWindowsCallback, CallbackContextPtr)
    )

def EnumThreadWindows(tid, callback, context):
    cbc = CallbackContext(callback, context)
    _EnumThreadWindows(tid, _EnumWndCb, _ref(cbc))

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

PostQuitMessage = _fun_fact(_u32.PostQuitMessage, (None, INT))

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

_GetWindowRect = _fun_fact(_u32.GetWindowRect, (BOOL, HWND, PRECT))

def GetWindowRect(hwnd):
    rc = RECT()
    _raise_if(not _GetWindowRect(hwnd, _ref(rc)))
    return rc

################################################################################

_GetClientRect = _fun_fact(_u32.GetClientRect, (BOOL, HWND, PRECT))

def GetClientRect(hwnd):
    rc = RECT()
    _raise_if(not _GetClientRect(hwnd, _ref(rc)))
    return rc

################################################################################

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

_LoadCursor = _fun_fact(_u32.LoadCursorW, (HANDLE, HANDLE, PWSTR))

def LoadCursor(hinst, cname):
    if isinstance(cname, int) and cname < 2**16:
        cname = _ct.cast(cname, PWSTR)
    res = _LoadCursor(hinst, cname)
    _raise_if(not res)
    return res

################################################################################

_LoadIcon = _fun_fact(_u32.LoadIconW, (HANDLE, HANDLE, PWSTR))

def LoadIcon(hinst, cname):
    if isinstance(cname, int) and cname < 2**16:
        cname = _ct.cast(cname, PWSTR)
    res = _LoadIcon(hinst, cname)
    _raise_if(not res)
    return res

################################################################################

_DefWindowProc = _fun_fact(
    _u32.DefWindowProcW, (LRESULT, HWND, UINT, WPARAM, LPARAM)
    )

def DefWindowProc(hwnd, msg, wp, lp):
    return _DefWindowProc(hwnd, msg, wp, lp)

################################################################################

class CREATESTRUCT(_ct.Structure):
    _fields_ = (
        ("lpCreateParams", PVOID),
        ("hInstance", HANDLE),
        ("hMenu", HANDLE),
        ("hwndParent", HWND),
        ("cx", INT),
        ("cy", INT),
        ("x", INT),
        ("y", INT),
        ("style", LONG),
        ("lpszName", PWSTR),
        ("lpszClass", PWSTR),
        ("dwExStyle", DWORD),
        )

################################################################################

WNDPROC = _ct.WINFUNCTYPE(
    LRESULT,
    HWND,
    UINT,
    WPARAM,
    LPARAM
    )

class WNDCLASS(_ct.Structure):
    _fields_ = (
        ("style", UINT),
        ("lpfnWndProc", WNDPROC),
        ("cbClsExtra", INT),
        ("cbWndExtra", INT),
        ("hInstance", HANDLE),
        ("hIcon", HANDLE),
        ("hCursor", HANDLE),
        ("hbrBackground", HANDLE),
        ("lpszMenuName", PWSTR),
        ("lpszClassName", PWSTR),
        )

PWNDCLASS = _ct.POINTER(WNDCLASS)

################################################################################

class MSG(_ct.Structure):
    _fields_ = (
        ("hWnd", HWND),
        ("message", UINT),
        ("wParam", WPARAM),
        ("lParam", LPARAM),
        ("time", DWORD),
        ("pt", POINT)
        )

PMSG = _ct.POINTER(MSG)

################################################################################

class PAINTSTRUCT(_ct.Structure):
    _fields_ = (
        ("hdc", HANDLE),
        ("fErase", BOOL),
        ("rcPaint", RECT),
        ("fRestore", BOOL),
        ("fIncUpdate", BOOL),
        ("rgbReserved", BYTE * 32),
        )

PPAINTSTRUCT = _ct.POINTER(PAINTSTRUCT)

################################################################################

_GetClassInfo = _fun_fact(_u32.GetClassInfoW, (BOOL, HANDLE, PWSTR, PWNDCLASS))

def GetClassInfo(hinst, cname):
    wclass = WNDCLASS()
    _raise_if(not _GetClassInfo(hinst, cname, _ref(wclass)))
    return wclass

################################################################################

_RegisterClass = _fun_fact(_u32.RegisterClassW, (WORD, PWNDCLASS))

def RegisterClass(wclass):
    res = _RegisterClass(_ref(wclass))
    _raise_if(not res)
    return res

################################################################################

_CreateWindowEx = _fun_fact(
    _u32.CreateWindowExW, (
        HWND,
        DWORD,
        PWSTR,
        PWSTR,
        DWORD,
        INT,
        INT,
        INT,
        INT,
        HWND,
        HANDLE,
        HINSTANCE,
        PVOID
        )
    )

def CreateWindowEx(
    ex_style,
    class_name,
    wnd_name,
    style,
    x,
    y,
    width,
    height,
    parent,
    menu,
    hinst,
    create_param
    ):
    hwnd = _CreateWindowEx(
        ex_style,
        class_name,
        wnd_name,
        style,
        x,
        y,
        width,
        height,
        parent,
        menu,
        hinst,
        create_param
        )
    _raise_if(not hwnd)
    return hwnd

################################################################################

_GetMessage = _fun_fact(_u32.GetMessageW, (BOOL, PMSG, HWND, UINT, UINT))

def GetMessage(hwnd=None, msg_min=0, msg_max=0):
    msg = MSG()
    res = _GetMessage(_ref(msg), hwnd, msg_min, msg_max)
    _raise_if(res == -1)
    return msg

################################################################################

_TranslateMessage = _fun_fact(_u32.TranslateMessage, (BOOL, PMSG))

def TranslateMessage(msg):
    return _TranslateMessage(_ref(msg))

################################################################################

_DispatchMessage = _fun_fact(_u32.DispatchMessageW, (LRESULT, PMSG))

def DispatchMessage(msg):
    return _DispatchMessage(_ref(msg))

################################################################################

_ShowWindow = _fun_fact(_u32.ShowWindow, (BOOL, HWND, INT))

def ShowWindow(hwnd, cmd):
    return bool(_ShowWindow(hwnd, cmd))

################################################################################

_UpdateWindow = _fun_fact(_u32.UpdateWindow, (BOOL, HWND))

def UpdateWindow(hwnd):
    _raise_if(not _UpdateWindow(hwnd))

################################################################################

_DestroyWindow = _fun_fact(_u32.DestroyWindow, (BOOL, HWND))

def DestroyWindow(hwnd):
    _raise_if(not _DestroyWindow(hwnd))

################################################################################

IsWindow = _fun_fact(_u32.IsWindow, (BOOL, HWND))

################################################################################

_GetDlgItem = _fun_fact(_u32.GetDlgItem, (HWND, HWND, INT))

def GetDlgItem(hwnd, id):
    res = _GetDlgItem(hwnd, id)
    _raise_if(not res)
    return res

################################################################################

SendDlgItemMessage = _fun_fact(
    _u32.SendDlgItemMessageW, (LRESULT, HWND, INT, UINT, WPARAM, LPARAM)
    )

################################################################################

_SetDlgItemText = _fun_fact(
    _u32.SetDlgItemTextW, (BOOL, HWND, INT, PWSTR)
    )

def SetDlgItemText(dlg, id, txt):
    _raise_if(not _SetDlgItemText(dlg, id, txt))

################################################################################

EnableWindow = _fun_fact(_u32.EnableWindow, (BOOL, HWND, BOOL))

################################################################################

SetForegroundWindow = _fun_fact(_u32.SetForegroundWindow, (BOOL, HWND))

################################################################################

GetParent = _fun_fact(_u32.GetParent, (HWND, HWND))

################################################################################

_InvalidateRect = _fun_fact(_u32.InvalidateRect, (BOOL, HWND, PRECT, BOOL))

def InvalidateRect(hwnd, rc, erase):
    prc = _ref(rc) if rc is not None else None
    _raise_if(not _InvalidateRect(hwnd, prc, erase))

################################################################################

WindowFromPoint = _fun_fact(_u32.WindowFromPoint, (HWND, POINT))

################################################################################

_MoveWindow = _fun_fact(
    _u32.MoveWindow, (
        BOOL,
        HWND,
        INT,
        INT,
        INT,
        INT,
        BOOL
        )
    )

def MoveWindow(hwnd, x, y, width, height, repaint):
    _raise_if(not _MoveWindow(hwnd, x, y, width, height, repaint))

################################################################################

MapWindowPoints = _fun_fact(
    _u32.MapWindowPoints, (
        INT,
        HWND,
        HWND,
        PPOINT,
        UINT,
        )
    )

################################################################################

_GetCursorPos = _fun_fact(_u32.GetCursorPos, (BOOL, PPOINT))

def GetCursorPos():
    pt = POINT()
    _raise_if(not GetCursorPos(_ref(pt)))
    return pt

################################################################################

_GetDC = _fun_fact(_u32.GetDC, (HANDLE, HWND))

def GetDC(hwnd):
    res = _GetDC(hwnd)
    _raise_if(not res)
    return res

################################################################################

_GetWindowDC = _fun_fact(_u32.GetWindowDC, (HANDLE, HWND))

def GetWindowDC(hwnd):
    res = _GetWindowDC(hwnd)
    _raise_if(not res)
    return res

################################################################################

_ReleaseDC = _fun_fact(_u32.ReleaseDC, (INT, HWND, HANDLE))

def ReleaseDC(hwnd, hdc):
    _raise_if(not _ReleaseDC(hwnd, hdc))

################################################################################

_SetTimer = _fun_fact(_u32.SetTimer, (UINT_PTR, HWND, UINT_PTR, UINT, PVOID))

def SetTimer(hwnd, timer_id, period_ms):
    _raise_if(not _SetTimer(hwnd, timer_id, period_ms, None))

################################################################################

_KillTimer = _fun_fact(_u32.KillTimer, (BOOL, HWND, UINT_PTR))

def KillTimer(hwnd, timer_id):
    _raise_if(not _KillTimer(hwnd, timer_id))

################################################################################

_CheckDlgButton = _fun_fact(_u32.CheckDlgButton, (BOOL, HWND, INT, UINT))

def CheckDlgButton(dlg, id, check):
    _raise_if(not _CheckDlgButton(dlg, id, check))

################################################################################

IsDlgButtonChecked = _fun_fact(_u32.IsDlgButtonChecked, (UINT, HWND, INT))

################################################################################

_BeginPaint = _fun_fact(_u32.BeginPaint, (HANDLE, HWND, PPAINTSTRUCT))

def BeginPaint(hwnd):
    ps = PAINTSTRUCT()
    hdc = _BeginPaint(hwnd, _ref(ps))
    _raise_if(not hdc)
    return hdc, ps

################################################################################

_EndPaint = _fun_fact(_u32.EndPaint, (BOOL, HWND, PPAINTSTRUCT))

def EndPaint(hwnd, ps):
    _raise_if(not _EndPaint(hwnd, _ref(ps)))

################################################################################

_DrawText = _fun_fact(_u32.DrawTextW, (INT, HANDLE, PWSTR, INT, PRECT, UINT))

def DrawText(hdc, txt, rc, fmt):
    _raise_if(0 == _DrawText(hdc, txt, len(txt), _ref(rc), fmt))

################################################################################

_SetProp = _fun_fact(_u32.SetPropW, (BOOL, HWND, PWSTR, HANDLE))

def SetProp(hwnd, name, data):
    _raise_if(not _SetProp(hwnd, name, data))

################################################################################

_GetProp = _fun_fact(_u32.GetPropW, (HANDLE, HWND, PWSTR))

def GetProp(hwnd, name):
    data = _GetProp(hwnd, name)
    _raise_if(not data)
    return data

def get_prop_def(hwnd, name, default=None):
    data = _GetProp(hwnd, name)
    return data or default

################################################################################

_RemoveProp = _fun_fact(_u32.RemovePropW, (HANDLE, HWND, PWSTR))

def RemoveProp(hwnd, name):
    data = _RemoveProp(hwnd, name)
    _raise_if(not data)
    return data

################################################################################

_EnumPropsCallback = _ct.WINFUNCTYPE(
    BOOL,
    HWND,
    PWSTR,
    HANDLE,
    CallbackContextPtr
    )

@_EnumPropsCallback
def _EnumPropsCb(hwnd, name, data, ctxt):
    cbc = ctxt.contents
    res = cbc.callback(hwnd, name, data, cbc.context)
    # keep on enumerating if the callback fails to return a value
    return res if res is not None else True

################################################################################

_EnumPropsEx = _fun_fact(
    _u32.EnumPropsExW, (INT, HWND, _EnumPropsCallback, CallbackContextPtr)
    )

def EnumPropsEx(hwnd, callback, context):
    cbc = CallbackContext(callback, context)
    _EnumPropsEx(hwnd, _EnumPropsCb, _ref(cbc))

################################################################################

_OpenClipboard = _fun_fact(_u32.OpenClipboard, (BOOL, HWND))

def OpenClipboard(hwnd):
    _raise_if(not _OpenClipboard(hwnd))

################################################################################

_EmptyClipboard = _fun_fact(_u32.EmptyClipboard, (BOOL,))

def EmptyClipboard():
    _raise_if(not _EmptyClipboard())

################################################################################

_SetClipboardData = _fun_fact(_u32.SetClipboardData, (HANDLE, UINT, HANDLE))

def SetClipboardData(fmt, hmem):
    res = _SetClipboardData(fmt, hmem)
    _raise_if(not res)
    return res

################################################################################

_GetClipboardData = _fun_fact(_u32.GetClipboardData, (HANDLE, UINT))

def GetClipboardData(fmt):
    res = _GetClipboardData(fmt)
    _raise_if(not res)
    return res

################################################################################

IsClipboardFormatAvailable = _fun_fact(
    _u32.IsClipboardFormatAvailable, (BOOL, UINT)
    )

################################################################################

_CloseClipboard = _fun_fact(_u32.CloseClipboard, (BOOL,))

def CloseClipboard():
    _raise_if(not _CloseClipboard())

################################################################################

def txt_to_clip(txt, wnd=None):
    buf = _ct.create_unicode_buffer(txt)
    size = _ct.sizeof(buf)
    copied = False
    hcopy = kernel.GlobalAlloc(GMEM_MOVEABLE, size)
    try:
        _ct.memmove(kernel.GlobalLock(hcopy), buf, size)
        kernel.GlobalUnlock(hcopy)
        OpenClipboard(wnd)
        EmptyClipboard()
        SetClipboardData(CF_UNICODETEXT, hcopy)
        copied = True
        CloseClipboard()
    finally:
        if not copied:
            kernel.GlobalFree(hcopy)

################################################################################

def txt_from_clip(wnd=None):
    if not IsClipboardFormatAvailable(CF_UNICODETEXT):
        raise EnvironmentError("no clipboard text available")
    OpenClipboard(wnd)
    hmem = GetClipboardData(CF_UNICODETEXT)
    txt = _ct.wstring_at(kernel.GlobalLock(hmem))
    kernel.GlobalUnlock(hmem)
    CloseClipboard();
    return txt

################################################################################
