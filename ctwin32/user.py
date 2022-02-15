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

from types import SimpleNamespace as _namespace

from .wtypes import *
from . import (
    ctypes,
    ref,
    kernel,
    raise_if,
    fun_fact,
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

_usr = ctypes.windll.user32

################################################################################

_GetWindowThreadProcessId = fun_fact(
    _usr.GetWindowThreadProcessId, (DWORD, HANDLE, PDWORD)
    )

def GetWindowThreadProcessId(hwnd):
    pid = DWORD()
    tid = _GetWindowThreadProcessId(hwnd, ref(pid))
    return tid, pid.value

################################################################################

_GetWindowTextLength = fun_fact(
    _usr.GetWindowTextLengthW, (INT, HWND)
    )

def GetWindowTextLength(hwnd):
    return _GetWindowTextLength(hwnd)

################################################################################

_GetWindowText = fun_fact(_usr.GetWindowTextW, (INT, HWND, PWSTR, INT))

def GetWindowText(hwnd):
    slen = GetWindowTextLength(hwnd)
    buf = ctypes.create_unicode_buffer(slen + 1)
    res = _GetWindowText(hwnd, buf, slen + 1)
    raise_if(res != slen)
    return buf.value

################################################################################

_SetWindowText = fun_fact(_usr.SetWindowTextW, (BOOL, HWND, PWSTR))

def SetWindowText(hwnd, txt):
    raise_if(not _SetWindowText(hwnd, txt))

################################################################################

_GetClassName = fun_fact(
    _usr.GetClassNameW, (INT, HWND, PWSTR, INT)
    )

def GetClassName(hwnd):
    size = 32
    while True:
        size *= 2
        buf = ctypes.create_unicode_buffer(size)
        res = _GetClassName(hwnd, buf, buf._length_)
        raise_if(not res)
        if res != size - 1:
            return buf.value

################################################################################

_GetWindowLong = fun_fact(_usr.GetWindowLongW, (LONG, HWND, INT))

def GetWindowLong(hwnd, idx):
    return _GetWindowLong(hwnd, idx)

################################################################################

_GetWindowLongPtr = fun_fact(
    _usr.GetWindowLongPtrW, (LONG_PTR, HWND, INT)
    )

def GetWindowLongPtr(hwnd, idx):
    return _GetWindowLongPtr(hwnd, idx)

################################################################################

_SetWindowLong = fun_fact(
    _usr.SetWindowLongW, (LONG, HWND, INT, LONG)
    )

def SetWindowLong(hwnd, idx, value):
    return _SetWindowLong(hwnd, idx, value)

################################################################################

_SetWindowLongPtr = fun_fact(
    _usr.SetWindowLongPtrW, (LONG_PTR, HWND, INT, LONG_PTR)
    )

def SetWindowLongPtr(hwnd, idx, value):
    return _SetWindowLongPtr(hwnd, idx, value)

################################################################################

_EnumWindowsCallback = ctypes.WINFUNCTYPE(
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

_EnumWindows = fun_fact(
    _usr.EnumWindows, (BOOL, _EnumWindowsCallback, CallbackContextPtr)
    )

def EnumWindows(callback, context):
    cbc = CallbackContext(callback, context)
    _EnumWindows(_EnumWndCb, ref(cbc))

################################################################################

_EnumChildWindows = fun_fact(
    _usr.EnumChildWindows,
    (BOOL, HWND, _EnumWindowsCallback, CallbackContextPtr)
    )

def EnumChildWindows(hwnd, callback, context):
    cbc = CallbackContext(callback, context)
    _EnumChildWindows(hwnd, _EnumWndCb, ref(cbc))

################################################################################

_EnumThreadWindows = fun_fact(
    _usr.EnumThreadWindows,
    (BOOL, DWORD, _EnumWindowsCallback, CallbackContextPtr)
    )

def EnumThreadWindows(tid, callback, context):
    cbc = CallbackContext(callback, context)
    _EnumThreadWindows(tid, _EnumWndCb, ref(cbc))

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

_WaitForInputIdle = fun_fact(
    _usr.WaitForInputIdle, (DWORD, HANDLE, DWORD)
    )

def WaitForInputIdle(proc, timeout):
    res = _WaitForInputIdle(proc, timeout)
    raise_if(res == WAIT_FAILED)
    return res

################################################################################

_PostMessage = fun_fact(
    _usr.PostMessageW,
    (BOOL, HWND, UINT, UINT_PTR, LONG_PTR)
    )

def PostMessage(hwnd, msg, wp, lp):
    raise_if(not _PostMessage(hwnd, msg, wp, lp))

################################################################################

PostQuitMessage = fun_fact(_usr.PostQuitMessage, (None, INT))

################################################################################

_SendMessage = fun_fact(
    _usr.SendMessageW,
    (LONG_PTR, HWND, UINT, UINT_PTR, LONG_PTR)
    )

def SendMessage(hwnd, msg, wp, lp):
    return _SendMessage(hwnd, msg, wp, lp)

################################################################################

_SendMessageTimeout = fun_fact(
    _usr.SendMessageTimeoutW, (
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
    raise_if(
        0 == _SendMessageTimeout(
            hwnd,
            msg,
            wp,
            lp,
            flags,
            timeout,
            ref(result)
            )
        )
    return result.value

################################################################################

_GetWindow = fun_fact(_usr.GetWindow, (HWND, HWND, UINT))

def GetWindow(hwnd, cmd):
    return _GetWindow(hwnd, cmd)

################################################################################

_GetAsyncKeyState = fun_fact(_usr.GetAsyncKeyState, (SHORT, INT))

def GetAsyncKeyState(vkey):
    return _GetAsyncKeyState(vkey)

################################################################################

_GetWindowRect = fun_fact(_usr.GetWindowRect, (BOOL, HWND, PRECT))

def GetWindowRect(hwnd):
    rc = RECT()
    raise_if(not _GetWindowRect(hwnd, ref(rc)))
    return rc

################################################################################

_GetClientRect = fun_fact(_usr.GetClientRect, (BOOL, HWND, PRECT))

def GetClientRect(hwnd):
    rc = RECT()
    raise_if(not _GetClientRect(hwnd, ref(rc)))
    return rc

################################################################################

_AdjustWindowRectEx = fun_fact(
    _usr.AdjustWindowRectEx, (BOOL, PRECT, DWORD, BOOL, DWORD)
    )

def AdjustWindowRectEx(rc, style, has_menu, exstyle):
    new_rect = rc.copy()
    raise_if(not _AdjustWindowRectEx(ref(new_rect), style, has_menu, exstyle))
    return new_rect

################################################################################

class WINDOWPLACEMENT(ctypes.Structure):
    _fields_ = (
        ("length", UINT),
        ("flags", UINT),
        ("showCmd", UINT),
        ("MinPosition", POINT),
        ("MaxPosition", POINT),
        ("NormalPosition", RECT),
        )

    def __init__(self, f=0, s=1, mi=(0, 0), ma=(0, 0), no=(0, 0, 0, 0)):
        self.length = ctypes.sizeof(WINDOWPLACEMENT)
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

PWINDOWPLACEMENT = ctypes.POINTER(WINDOWPLACEMENT)

################################################################################

_GetWindowPlacement = fun_fact(
    _usr.GetWindowPlacement, (BOOL, HWND, PWINDOWPLACEMENT)
    )

def GetWindowPlacement(hwnd):
    wpt = WINDOWPLACEMENT()
    raise_if(not _GetWindowPlacement(hwnd, ref(wpt)))
    return wpt

################################################################################

_SetWindowPlacement = fun_fact(
    _usr.SetWindowPlacement, (BOOL, HWND, PWINDOWPLACEMENT)
    )

def SetWindowPlacement(hwnd, wpt):
    raise_if(not _SetWindowPlacement(hwnd, ref(wpt)))

################################################################################

_SetWindowPos = fun_fact(
    _usr.SetWindowPos, (BOOL, HWND, HWND, INT, INT, INT, INT, UINT)
    )

def SetWindowPos(hwnd, ins_after, x, y, cx, cy, flags):
    raise_if(not _SetWindowPos(hwnd, ins_after, x, y, cx, cy, flags))

################################################################################

_AttachThreadInput = fun_fact(
    _usr.AttachThreadInput, (BOOL, DWORD, DWORD, BOOL)
    )

def AttachThreadInput(id_attach, id_attach_to, do_attach):
    raise_if(not _AttachThreadInput(id_attach, id_attach_to, do_attach))

################################################################################

_BringWindowToTop = fun_fact(_usr.BringWindowToTop, (BOOL, HWND))

def BringWindowToTop(hwnd):
    raise_if(not _BringWindowToTop(hwnd))

def to_top_maybe_attach(hwnd):
    wnd_id, _ = GetWindowThreadProcessId(hwnd)
    self_id = kernel.GetCurrentThreadId()
    if wnd_id != self_id:
        AttachThreadInput(self_id, wnd_id, True)
    BringWindowToTop(hwnd)
    if wnd_id != self_id:
        AttachThreadInput(self_id, wnd_id, False)

################################################################################

_SetActiveWindow = fun_fact(_usr.SetActiveWindow, (HWND, HWND))

def SetActiveWindow(hwnd):
    return _SetActiveWindow(hwnd)

################################################################################

_MessageBox = fun_fact(
    _usr.MessageBoxW, (INT, HWND, PWSTR, PWSTR, UINT)
    )

def MessageBox(hwnd, text, caption, flags):
    res = _MessageBox(hwnd, text, caption, flags)
    raise_if(res == 0)
    return res

################################################################################

class MOUSEINPUT(ctypes.Structure):
    _fields_ = (
        ("dx", LONG),
        ("dy", LONG),
        ("mouseData", DWORD),
        ("dwFlags", DWORD),
        ("time", DWORD),
        ("dwExtraInfo", UINT_PTR),
        )

class KEYBDINPUT(ctypes.Structure):
    _fields_ = (
        ("wVk", WORD),
        ("wScan", WORD),
        ("dwFlags", DWORD),
        ("time", DWORD),
        ("dwExtraInfo", UINT_PTR),
        )

class HARDWAREINPUT(ctypes.Structure):
    _fields_ = (
        ("uMsg", DWORD),
        ("wParamL", WORD),
        ("wParamH", WORD),
        )

class _DUMMY_INPUT_UNION(ctypes.Union):
    _fields_ = (
        ("mi", MOUSEINPUT),
        ("ki", KEYBDINPUT),
        ("hi", HARDWAREINPUT),
        )

class INPUT(ctypes.Structure):
    _anonymous_ = ("anon",)
    _fields_ = (
        ("type", DWORD),
        ("anon", _DUMMY_INPUT_UNION),
        )

    def copy(self):
        other = INPUT()
        ctypes.memmove(ref(other), ref(self), ctypes.sizeof(INPUT))
        return other

    def as_keyup(self):
        if not self.type == INPUT_KEYBOARD:
            raise ValueError("not INPUT_KEYBOARD")
        up = self.copy()
        up.ki.dwFlags |= KEYEVENTF_KEYUP
        return up

PINPUT = ctypes.POINTER(INPUT)

################################################################################

def kb_input(vk, scan, flags=0):
    kip = INPUT()
    kip.type = INPUT_KEYBOARD
    kip.ki.wVk = vk
    kip.ki.wScan = scan
    kip.ki.dwFlags = flags
    return kip

################################################################################

_SendInput = fun_fact(_usr.SendInput, (UINT, UINT, PINPUT, INT))

def SendInput(inputs):
    if isinstance(inputs, INPUT):
        num, ptr = 1, ref(inputs)
    else:
        try:
            num = len(inputs)
            if not num:
                return
            inputs = (INPUT * num)(*inputs)
            ptr = ctypes.cast(inputs, PINPUT)
        except Exception as e:
            raise TypeError(f"expected INPUT or list of INPUTs: {e}")
    raise_if(0 == _SendInput(num, ptr, ctypes.sizeof(INPUT)))

################################################################################

_ExitWindowsEx = fun_fact(_usr.ExitWindowsEx, (BOOL, UINT, DWORD))

def ExitWindowsEx(flags, reason):
    raise_if(0 == _ExitWindowsEx(flags, reason))

################################################################################

_LockWorkStation = fun_fact(_usr.LockWorkStation, (BOOL,))

def LockWorkStation():
    raise_if(0 == _LockWorkStation())

################################################################################

_GetShellWindow = fun_fact(_usr.GetShellWindow, (HWND,))

def GetShellWindow():
    return _GetShellWindow()

################################################################################

_MonitorFromWindow = fun_fact(_usr.MonitorFromWindow, (HANDLE, HWND, DWORD))

def MonitorFromWindow(hwnd, flags=MONITOR_DEFAULTTOPRIMARY):
    return _MonitorFromWindow(hwnd, flags)

################################################################################

class MONITORINFO(ctypes.Structure):
    _fields_ = (
        ("cbSize", DWORD),
        ("rcMonitor", RECT),
        ("rcWork", RECT),
        ("dwFlags", DWORD),
        )
    def __init__(self):
        self.cbSize = ctypes.sizeof(MONITORINFO)

PMONITORINFO = ctypes.POINTER(MONITORINFO)

################################################################################

_GetMonitorInfo = fun_fact(_usr.GetMonitorInfoW, (BOOL, HANDLE, PMONITORINFO))

def GetMonitorInfo(hmon):
    mi = MONITORINFO()
    raise_if(not _GetMonitorInfo(hmon, ref(mi)))
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

_LoadCursor = fun_fact(_usr.LoadCursorW, (HANDLE, HANDLE, PWSTR))

def LoadCursor(hinst, cname):
    if isinstance(cname, int) and cname < 2**16:
        cname = ctypes.cast(cname, PWSTR)
    res = _LoadCursor(hinst, cname)
    raise_if(not res)
    return res

################################################################################

_LoadIcon = fun_fact(_usr.LoadIconW, (HANDLE, HANDLE, PWSTR))

def LoadIcon(hinst, cname):
    if isinstance(cname, int) and cname < 2**16:
        cname = ctypes.cast(cname, PWSTR)
    res = _LoadIcon(hinst, cname)
    raise_if(not res)
    return res

################################################################################

_DefWindowProc = fun_fact(
    _usr.DefWindowProcW, (LRESULT, HWND, UINT, WPARAM, LPARAM)
    )

def DefWindowProc(hwnd, msg, wp, lp):
    return _DefWindowProc(hwnd, msg, wp, lp)

################################################################################

class CREATESTRUCT(ctypes.Structure):
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

WNDPROC = ctypes.WINFUNCTYPE(
    LRESULT,
    HWND,
    UINT,
    WPARAM,
    LPARAM
    )

class WNDCLASS(ctypes.Structure):
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

PWNDCLASS = ctypes.POINTER(WNDCLASS)

################################################################################

class MSG(ctypes.Structure):
    _fields_ = (
        ("hWnd", HWND),
        ("message", UINT),
        ("wParam", WPARAM),
        ("lParam", LPARAM),
        ("time", DWORD),
        ("pt", POINT)
        )

PMSG = ctypes.POINTER(MSG)

################################################################################

class PAINTSTRUCT(ctypes.Structure):
    _fields_ = (
        ("hdc", HANDLE),
        ("fErase", BOOL),
        ("rcPaint", RECT),
        ("fRestore", BOOL),
        ("fIncUpdate", BOOL),
        ("rgbReserved", BYTE * 32),
        )

PPAINTSTRUCT = ctypes.POINTER(PAINTSTRUCT)

################################################################################

_GetClassInfo = fun_fact(_usr.GetClassInfoW, (BOOL, HANDLE, PWSTR, PWNDCLASS))

def GetClassInfo(hinst, cname):
    wclass = WNDCLASS()
    raise_if(not _GetClassInfo(hinst, cname, ref(wclass)))
    return wclass

################################################################################

_RegisterClass = fun_fact(_usr.RegisterClassW, (WORD, PWNDCLASS))

def RegisterClass(wclass):
    res = _RegisterClass(ref(wclass))
    raise_if(not res)
    return res

################################################################################

_CreateWindowEx = fun_fact(
    _usr.CreateWindowExW, (
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
    raise_if(not hwnd)
    return hwnd

################################################################################

_GetMessage = fun_fact(_usr.GetMessageW, (BOOL, PMSG, HWND, UINT, UINT))

def GetMessage(hwnd=None, msg_min=0, msg_max=0):
    msg = MSG()
    res = _GetMessage(ref(msg), hwnd, msg_min, msg_max)
    raise_if(res == -1)
    return msg

################################################################################

_TranslateMessage = fun_fact(_usr.TranslateMessage, (BOOL, PMSG))

def TranslateMessage(msg):
    return _TranslateMessage(ref(msg))

################################################################################

_DispatchMessage = fun_fact(_usr.DispatchMessageW, (LRESULT, PMSG))

def DispatchMessage(msg):
    return _DispatchMessage(ref(msg))

################################################################################

_ShowWindow = fun_fact(_usr.ShowWindow, (BOOL, HWND, INT))

def ShowWindow(hwnd, cmd):
    return bool(_ShowWindow(hwnd, cmd))

################################################################################

_UpdateWindow = fun_fact(_usr.UpdateWindow, (BOOL, HWND))

def UpdateWindow(hwnd):
    raise_if(not _UpdateWindow(hwnd))

################################################################################

_DestroyWindow = fun_fact(_usr.DestroyWindow, (BOOL, HWND))

def DestroyWindow(hwnd):
    raise_if(not _DestroyWindow(hwnd))

################################################################################

IsWindow = fun_fact(_usr.IsWindow, (BOOL, HWND))

################################################################################

_GetDlgItem = fun_fact(_usr.GetDlgItem, (HWND, HWND, INT))

def GetDlgItem(hwnd, id):
    res = _GetDlgItem(hwnd, id)
    raise_if(not res)
    return res

################################################################################

SendDlgItemMessage = fun_fact(
    _usr.SendDlgItemMessageW, (LRESULT, HWND, INT, UINT, WPARAM, LPARAM)
    )

################################################################################

_SetDlgItemText = fun_fact(
    _usr.SetDlgItemTextW, (BOOL, HWND, INT, PWSTR)
    )

def SetDlgItemText(dlg, id, txt):
    raise_if(not _SetDlgItemText(dlg, id, txt))

################################################################################

EnableWindow = fun_fact(_usr.EnableWindow, (BOOL, HWND, BOOL))

################################################################################

SetForegroundWindow = fun_fact(_usr.SetForegroundWindow, (BOOL, HWND))

################################################################################

GetParent = fun_fact(_usr.GetParent, (HWND, HWND))

################################################################################

_InvalidateRect = fun_fact(_usr.InvalidateRect, (BOOL, HWND, PRECT, BOOL))

def InvalidateRect(hwnd, rc, erase):
    prc = ref(rc) if rc is not None else None
    raise_if(not _InvalidateRect(hwnd, prc, erase))

################################################################################

WindowFromPoint = fun_fact(_usr.WindowFromPoint, (HWND, POINT))

################################################################################

_MoveWindow = fun_fact(
    _usr.MoveWindow, (
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
    raise_if(not _MoveWindow(hwnd, x, y, width, height, repaint))

################################################################################

MapWindowPoints = fun_fact(
    _usr.MapWindowPoints, (
        INT,
        HWND,
        HWND,
        PPOINT,
        UINT,
        )
    )

################################################################################

_GetCursorPos = fun_fact(_usr.GetCursorPos, (BOOL, PPOINT))

def GetCursorPos():
    pt = POINT()
    raise_if(not GetCursorPos(ref(pt)))
    return pt

################################################################################

_GetDC = fun_fact(_usr.GetDC, (HANDLE, HWND))

def GetDC(hwnd):
    res = _GetDC(hwnd)
    raise_if(not res)
    return res

################################################################################

_GetWindowDC = fun_fact(_usr.GetWindowDC, (HANDLE, HWND))

def GetWindowDC(hwnd):
    res = _GetWindowDC(hwnd)
    raise_if(not res)
    return res

################################################################################

_ReleaseDC = fun_fact(_usr.ReleaseDC, (INT, HWND, HANDLE))

def ReleaseDC(hwnd, hdc):
    raise_if(not _ReleaseDC(hwnd, hdc))

################################################################################

_SetTimer = fun_fact(_usr.SetTimer, (UINT_PTR, HWND, UINT_PTR, UINT, PVOID))

def SetTimer(hwnd, timer_id, period_ms):
    raise_if(not _SetTimer(hwnd, timer_id, period_ms, None))

################################################################################

_KillTimer = fun_fact(_usr.KillTimer, (BOOL, HWND, UINT_PTR))

def KillTimer(hwnd, timer_id):
    raise_if(not _KillTimer(hwnd, timer_id))

################################################################################

_CheckDlgButton = fun_fact(_usr.CheckDlgButton, (BOOL, HWND, INT, UINT))

def CheckDlgButton(dlg, id, check):
    raise_if(not _CheckDlgButton(dlg, id, check))

################################################################################

IsDlgButtonChecked = fun_fact(_usr.IsDlgButtonChecked, (UINT, HWND, INT))

################################################################################

_BeginPaint = fun_fact(_usr.BeginPaint, (HANDLE, HWND, PPAINTSTRUCT))

def BeginPaint(hwnd):
    ps = PAINTSTRUCT()
    hdc = _BeginPaint(hwnd, ref(ps))
    raise_if(not hdc)
    return hdc, ps

################################################################################

_EndPaint = fun_fact(_usr.EndPaint, (BOOL, HWND, PPAINTSTRUCT))

def EndPaint(hwnd, ps):
    raise_if(not _EndPaint(hwnd, ref(ps)))

################################################################################

_DrawText = fun_fact(_usr.DrawTextW, (INT, HANDLE, PWSTR, INT, PRECT, UINT))

def DrawText(hdc, txt, rc, fmt):
    raise_if(0 == _DrawText(hdc, txt, len(txt), ref(rc), fmt))

################################################################################

_SetProp = fun_fact(_usr.SetPropW, (BOOL, HWND, PWSTR, HANDLE))

def SetProp(hwnd, name, data):
    raise_if(not _SetProp(hwnd, name, data))

################################################################################

_GetProp = fun_fact(_usr.GetPropW, (HANDLE, HWND, PWSTR))

def GetProp(hwnd, name):
    data = _GetProp(hwnd, name)
    raise_if(not data)
    return data

def get_prop_def(hwnd, name, default=None):
    data = _GetProp(hwnd, name)
    return data or default

################################################################################

_RemoveProp = fun_fact(_usr.RemovePropW, (HANDLE, HWND, PWSTR))

def RemoveProp(hwnd, name):
    data = _RemoveProp(hwnd, name)
    raise_if(not data)
    return data

################################################################################

_EnumPropsCallback = ctypes.WINFUNCTYPE(
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

_EnumPropsEx = fun_fact(
    _usr.EnumPropsExW, (INT, HWND, _EnumPropsCallback, CallbackContextPtr)
    )

def EnumPropsEx(hwnd, callback, context):
    cbc = CallbackContext(callback, context)
    _EnumPropsEx(hwnd, _EnumPropsCb, ref(cbc))

################################################################################

_OpenClipboard = fun_fact(_usr.OpenClipboard, (BOOL, HWND))

def OpenClipboard(hwnd):
    raise_if(not _OpenClipboard(hwnd))

################################################################################

_EmptyClipboard = fun_fact(_usr.EmptyClipboard, (BOOL,))

def EmptyClipboard():
    raise_if(not _EmptyClipboard())

################################################################################

_SetClipboardData = fun_fact(_usr.SetClipboardData, (HANDLE, UINT, HANDLE))

def SetClipboardData(fmt, hmem):
    res = _SetClipboardData(fmt, hmem)
    raise_if(not res)
    return res

################################################################################

_GetClipboardData = fun_fact(_usr.GetClipboardData, (HANDLE, UINT))

def GetClipboardData(fmt):
    res = _GetClipboardData(fmt)
    raise_if(not res)
    return res

################################################################################

IsClipboardFormatAvailable = fun_fact(
    _usr.IsClipboardFormatAvailable, (BOOL, UINT)
    )

################################################################################

_CloseClipboard = fun_fact(_usr.CloseClipboard, (BOOL,))

def CloseClipboard():
    raise_if(not _CloseClipboard())

################################################################################

def txt_to_clip(txt, wnd=None):
    buf = ctypes.create_unicode_buffer(txt)
    size = ctypes.sizeof(buf)
    copied = False
    hcopy = kernel.GlobalAlloc(GMEM_MOVEABLE, size)
    try:
        ctypes.memmove(kernel.GlobalLock(hcopy), buf, size)
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
    txt = ctypes.wstring_at(kernel.GlobalLock(hmem))
    kernel.GlobalUnlock(hmem)
    CloseClipboard();
    return txt

################################################################################

GetSystemMetrics = fun_fact(_usr.GetSystemMetrics, (INT, INT))

################################################################################

_ScrollWindow = fun_fact(
    _usr.ScrollWindow, (BOOL, HWND, INT, INT, PRECT, PRECT)
    )

def ScrollWindow(hwnd, x, y, scroll_rect=None, clip_rect=None):
    scroll_rect = ref(scroll_rect) if scroll_rect is not None else None
    clip_rect = ref(clip_rect) if clip_rect is not None else None
    raise_if(not _ScrollWindow(hwnd, x, y, scroll_rect, clip_rect))

################################################################################

_GetKeyNameText = fun_fact(_usr.GetKeyNameTextW, (INT, LONG, PWSTR, INT))

def GetKeyNameText(lparam):
    size = ret = 32
    while ret >= size - 1:
        size *= 2
        key_name = ctypes.create_unicode_buffer(size)
        ret = _GetKeyNameText(lparam, key_name, size)
        raise_if(not ret)
    return key_name.value

################################################################################
