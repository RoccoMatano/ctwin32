################################################################################
#
# Copyright 2021-2024 Rocco Matano
# SPDX-License-Identifier: MIT
#
################################################################################

from types import SimpleNamespace as _namespace

import ctypes
from .wtypes import (
    byte_buffer,
    string_buffer,
    BOOL,
    BYTE,
    CallbackContext,
    CallbackContextPtr,
    DWORD,
    HANDLE,
    HINSTANCE,
    HWND,
    INT,
    INT_PTR,
    LOGFONT,
    LONG,
    LONG_PTR,
    LPARAM,
    LRESULT,
    NTSTATUS,
    PDWORD,
    POINT,
    POINTER,
    PPOINT,
    PPVOID,
    PPWSTR,
    PRECT,
    PVOID,
    PWSTR,
    SHORT,
    RECT,
    UINT,
    UINT_PTR,
    WCHAR,
    WinError,
    WPARAM,
    WORD,
    )
from . import (
    ref,
    ntdll,
    kernel,
    raise_if,
    raise_on_zero,
    raise_on_err,
    fun_fact,
    CF_UNICODETEXT,
    GMEM_MOVEABLE,
    GWL_STYLE,
    GWL_EXSTYLE,
    INPUT_KEYBOARD,
    KEYEVENTF_KEYUP,
    LR_DEFAULTSIZE,
    MONITOR_DEFAULTTOPRIMARY,
    SPI_GETNONCLIENTMETRICS,
    SPI_SETNONCLIENTMETRICS,
    SPI_GETWHEELSCROLLLINES,
    SPI_SETWHEELSCROLLLINES,
    SPI_GETWORKAREA,
    SPIF_UPDATEINIFILE,
    SPIF_SENDCHANGE,
    SWP_NOSIZE,
    SWP_NOZORDER,
    UOI_FLAGS,
    WAIT_FAILED,
    WM_QUIT,
    WSF_VISIBLE,
    )

_usr = ctypes.WinDLL("user32.dll", use_last_error=True)

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
    buf = string_buffer(slen + 1)
    res = _GetWindowText(hwnd, buf, slen + 1)
    raise_if(res != slen)
    return buf.value

################################################################################

_SetWindowText = fun_fact(_usr.SetWindowTextW, (BOOL, HWND, PWSTR))

def SetWindowText(hwnd, txt):
    raise_on_zero(_SetWindowText(hwnd, txt))

################################################################################

_GetClassName = fun_fact(
    _usr.GetClassNameW, (INT, HWND, PWSTR, INT)
    )

def GetClassName(hwnd):
    size = 32
    while True:
        size *= 2
        buf = string_buffer(size)
        res = _GetClassName(hwnd, buf, buf._length_)
        raise_on_zero(res)
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
    # cannot propagate exceptions from callback
    with kernel.terminate_on_exception():
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
        pname=ntdll.proc_path_from_pid(pid),
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
    raise_on_zero(_PostMessage(hwnd, msg, wp, lp))

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
    raise_on_zero(
        _SendMessageTimeout(
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
    raise_on_zero(_GetWindowRect(hwnd, ref(rc)))
    return rc

################################################################################

_GetClientRect = fun_fact(_usr.GetClientRect, (BOOL, HWND, PRECT))

def GetClientRect(hwnd):
    rc = RECT()
    raise_on_zero(_GetClientRect(hwnd, ref(rc)))
    return rc

################################################################################

_AdjustWindowRectEx = fun_fact(
    _usr.AdjustWindowRectEx, (BOOL, PRECT, DWORD, BOOL, DWORD)
    )

def AdjustWindowRectEx(rc, style, has_menu, exstyle):
    new_rect = rc.copy()
    raise_on_zero(_AdjustWindowRectEx(ref(new_rect), style, has_menu, exstyle))
    return new_rect

################################################################################

class WINDOWPLACEMENT(ctypes.Structure):
    _fields_ = (
        ("length", UINT),
        ("flags", UINT),
        ("showCmd", UINT),
        ("ptMinPosition", POINT),
        ("ptMaxPosition", POINT),
        ("rcNormalPosition", RECT),
        )

    def __init__(self, f=0, s=1, mi=(0, 0), ma=(0, 0), no=(0, 0, 0, 0)):
        self.length = ctypes.sizeof(WINDOWPLACEMENT)
        self.flags = f
        self.showCmd = s
        self.ptMinPosition = mi
        self.ptMaxPosition = ma
        self.rcNormalPosition = no

    def __repr__(self):
        cl = self.__class__.__name__
        ln = self.length
        fl = self.flags
        sc = self.showCmd
        mi = f"({self.ptMinPosition.x}, {self.ptMinPosition.y})"
        ma = f"({self.ptMaxPosition.x}, {self.ptMaxPosition.y})"
        no = (
            f"({self.rcNormalPosition.left}, {self.rcNormalPosition.top}, ",
            f"{self.rcNormalPosition.right}, {self.rcNormalPosition.bottom})"
            )
        return f"{cl}({ln}, {fl}, {sc}, {mi}, {ma}, {no})"

PWINDOWPLACEMENT = POINTER(WINDOWPLACEMENT)

################################################################################

_GetWindowPlacement = fun_fact(
    _usr.GetWindowPlacement, (BOOL, HWND, PWINDOWPLACEMENT)
    )

def GetWindowPlacement(hwnd):
    wpt = WINDOWPLACEMENT()
    raise_on_zero(_GetWindowPlacement(hwnd, ref(wpt)))
    return wpt

################################################################################

_SetWindowPlacement = fun_fact(
    _usr.SetWindowPlacement, (BOOL, HWND, PWINDOWPLACEMENT)
    )

def SetWindowPlacement(hwnd, wpt):
    raise_on_zero(_SetWindowPlacement(hwnd, ref(wpt)))

################################################################################

_SetWindowPos = fun_fact(
    _usr.SetWindowPos, (BOOL, HWND, HWND, INT, INT, INT, INT, UINT)
    )

def SetWindowPos(hwnd, ins_after, x, y, cx, cy, flags):
    raise_on_zero(_SetWindowPos(hwnd, ins_after, x, y, cx, cy, flags))

################################################################################

_AttachThreadInput = fun_fact(
    _usr.AttachThreadInput, (BOOL, DWORD, DWORD, BOOL)
    )

def AttachThreadInput(id_attach, id_attach_to, do_attach):
    raise_on_zero(_AttachThreadInput(id_attach, id_attach_to, do_attach))

################################################################################

_BringWindowToTop = fun_fact(_usr.BringWindowToTop, (BOOL, HWND))

def BringWindowToTop(hwnd):
    raise_on_zero(_BringWindowToTop(hwnd))

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
    raise_on_zero(res)
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

PINPUT = POINTER(INPUT)

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
            raise TypeError(f"expected INPUT or list of INPUTs: {e}") from e
    raise_on_zero(_SendInput(num, ptr, ctypes.sizeof(INPUT)))

################################################################################

_ExitWindowsEx = fun_fact(_usr.ExitWindowsEx, (BOOL, UINT, DWORD))

def ExitWindowsEx(flags, reason):
    raise_on_zero(_ExitWindowsEx(flags, reason))

################################################################################

_LockWorkStation = fun_fact(_usr.LockWorkStation, (BOOL,))

def LockWorkStation():
    raise_on_zero(_LockWorkStation())

################################################################################

GetDesktopWindow = fun_fact(_usr.GetDesktopWindow, (HWND,))

################################################################################

GetShellWindow = fun_fact(_usr.GetShellWindow, (HWND,))

################################################################################

_MonitorFromWindow = fun_fact(_usr.MonitorFromWindow, (HANDLE, HWND, DWORD))

def MonitorFromWindow(hwnd, flags=MONITOR_DEFAULTTOPRIMARY):
    return _MonitorFromWindow(hwnd, flags)

################################################################################

class MONITORINFOEX(ctypes.Structure):
    _fields_ = (
        ("cbSize", DWORD),
        ("rcMonitor", RECT),
        ("rcWork", RECT),
        ("dwFlags", DWORD),
        ("szDevice", WCHAR * 32),
        )

    def __init__(self):
        self.cbSize = ctypes.sizeof(self)

PMONITORINFOEX = POINTER(MONITORINFOEX)

################################################################################

_GetMonitorInfo = fun_fact(_usr.GetMonitorInfoW, (BOOL, HANDLE, PMONITORINFOEX))

def GetMonitorInfo(hmon):
    mi = MONITORINFOEX()
    raise_on_zero(_GetMonitorInfo(hmon, ref(mi)))
    return mi

################################################################################

def get_wnd_center(hwnd=None):
    if hwnd is None:
        return GetMonitorInfo(MonitorFromWindow(None)).rcMonitor.center
    return GetWindowRect(hwnd).center

################################################################################

def center_wnd(to_be_centered, center_on=None):
    center_x, center_y = get_wnd_center(center_on)
    rc = GetWindowRect(to_be_centered)
    SetWindowPos(
        to_be_centered,
        None,
        rc.left + center_x - (rc.left + rc.right) // 2,
        rc.top + center_y - (rc.top + rc.bottom) // 2,
        0,
        0,
        SWP_NOSIZE | SWP_NOZORDER
        )

################################################################################

def start_centered(arglist):
    def center_wnd_cb(hwnd, _):
        center_wnd(hwnd)
        return True

    with kernel.create_process(arglist) as pi:
        WaitForInputIdle(pi.hProcess, 10000)
        EnumThreadWindows(pi.dwThreadId, center_wnd_cb, None)

################################################################################

_LoadString = fun_fact(_usr.LoadStringW, (INT, HANDLE, UINT, PPWSTR, INT))

def LoadString(hinst, strid):
    ptr = PWSTR()
    raise_on_zero(res := _LoadString(hinst, strid, ref(ptr), 0))
    return ctypes.wstring_at(ptr, res)

################################################################################

_LoadCursor = fun_fact(_usr.LoadCursorW, (HANDLE, HANDLE, PWSTR))

def LoadCursor(hinst, cname):
    if isinstance(cname, int) and cname < 2**16:
        cname = ctypes.cast(cname, PWSTR)
    raise_on_zero(res := _LoadCursor(hinst, cname))
    return res

################################################################################

_LoadIcon = fun_fact(_usr.LoadIconW, (HANDLE, HANDLE, PWSTR))

def LoadIcon(hinst, cname):
    if isinstance(cname, int) and cname < 2**16:
        cname = ctypes.cast(cname, PWSTR)
    raise_on_zero(res := _LoadIcon(hinst, cname))
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

PWNDCLASS = POINTER(WNDCLASS)

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

    def __bool__(self):
        return self.message != WM_QUIT

PMSG = POINTER(MSG)

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

PPAINTSTRUCT = POINTER(PAINTSTRUCT)

################################################################################

_GetClassInfo = fun_fact(_usr.GetClassInfoW, (BOOL, HANDLE, PWSTR, PWNDCLASS))

def GetClassInfo(hinst, cname):
    wclass = WNDCLASS()
    raise_on_zero(_GetClassInfo(hinst, cname, ref(wclass)))
    return wclass

################################################################################

_RegisterClass = fun_fact(_usr.RegisterClassW, (WORD, PWNDCLASS))

def RegisterClass(wclass):
    res = _RegisterClass(ref(wclass))
    raise_on_zero(res)
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
    raise_on_zero(hwnd)
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
    raise_on_zero(_UpdateWindow(hwnd))

################################################################################

_DestroyWindow = fun_fact(_usr.DestroyWindow, (BOOL, HWND))

def DestroyWindow(hwnd):
    raise_on_zero(_DestroyWindow(hwnd))

################################################################################

IsWindow = fun_fact(_usr.IsWindow, (BOOL, HWND))

################################################################################

_GetDlgItem = fun_fact(_usr.GetDlgItem, (HWND, HWND, INT))

def GetDlgItem(hwnd, id):
    res = _GetDlgItem(hwnd, id)
    raise_on_zero(res)
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
    raise_on_zero(_SetDlgItemText(dlg, id, txt))

################################################################################

_GetDlgItemText = fun_fact(
    _usr.GetDlgItemTextW, (UINT, HWND, INT, PWSTR, INT)
    )

def GetDlgItemText(dlg, id):
    length = 128
    res = length
    while res >= length:
        length *= 2
        buf = string_buffer(length)
        kernel.SetLastError(0)
        res = _GetDlgItemText(dlg, id, buf, length)
        raise_on_err(kernel.GetLastError())
    return buf.value

################################################################################

_CheckRadioButton = fun_fact(
    _usr.CheckRadioButton, (BOOL, HWND, INT, INT, INT)
    )

def CheckRadioButton(dlg, first, last, check):
    raise_on_zero(_CheckRadioButton(dlg, first, last, check))

################################################################################

_GetDlgCtrlID = fun_fact(_usr.GetDlgCtrlID, (INT, HWND))

def GetDlgCtrlID(hwnd):
    res = _GetDlgCtrlID(hwnd)
    raise_on_zero(res)
    return res

################################################################################

EnableWindow = fun_fact(_usr.EnableWindow, (BOOL, HWND, BOOL))

################################################################################

SetForegroundWindow = fun_fact(_usr.SetForegroundWindow, (BOOL, HWND))

################################################################################

SetFocus = fun_fact(_usr.SetFocus, (HWND, HWND))

################################################################################

GetParent = fun_fact(_usr.GetParent, (HWND, HWND))

################################################################################

GetMenu = fun_fact(_usr.GetMenu, (HANDLE, HWND))

################################################################################

_InvalidateRect = fun_fact(_usr.InvalidateRect, (BOOL, HWND, PRECT, BOOL))

def InvalidateRect(hwnd, rc, erase):
    prc = ref(rc) if rc is not None else None
    raise_on_zero(_InvalidateRect(hwnd, prc, erase))

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
    raise_on_zero(_MoveWindow(hwnd, x, y, width, height, repaint))

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
    raise_on_zero(GetCursorPos(ref(pt)))
    return pt

################################################################################

_GetDC = fun_fact(_usr.GetDC, (HANDLE, HWND))

def GetDC(hwnd):
    res = _GetDC(hwnd)
    raise_on_zero(res)
    return res

################################################################################

_GetWindowDC = fun_fact(_usr.GetWindowDC, (HANDLE, HWND))

def GetWindowDC(hwnd):
    res = _GetWindowDC(hwnd)
    raise_on_zero(res)
    return res

################################################################################

_ReleaseDC = fun_fact(_usr.ReleaseDC, (INT, HWND, HANDLE))

def ReleaseDC(hwnd, hdc):
    raise_on_zero(_ReleaseDC(hwnd, hdc))

################################################################################

_SetTimer = fun_fact(_usr.SetTimer, (UINT_PTR, HWND, UINT_PTR, UINT, PVOID))

def SetTimer(hwnd, timer_id, period_ms):
    raise_on_zero(_SetTimer(hwnd, timer_id, period_ms, None))

################################################################################

_KillTimer = fun_fact(_usr.KillTimer, (BOOL, HWND, UINT_PTR))

def KillTimer(hwnd, timer_id):
    raise_on_zero(_KillTimer(hwnd, timer_id))

################################################################################

_CheckDlgButton = fun_fact(_usr.CheckDlgButton, (BOOL, HWND, INT, UINT))

def CheckDlgButton(dlg, id, check):
    raise_on_zero(_CheckDlgButton(dlg, id, check))

################################################################################

IsDlgButtonChecked = fun_fact(_usr.IsDlgButtonChecked, (UINT, HWND, INT))

################################################################################

_BeginPaint = fun_fact(_usr.BeginPaint, (HANDLE, HWND, PPAINTSTRUCT))

def BeginPaint(hwnd):
    ps = PAINTSTRUCT()
    hdc = _BeginPaint(hwnd, ref(ps))
    raise_on_zero(hdc)
    return hdc, ps

################################################################################

_EndPaint = fun_fact(_usr.EndPaint, (BOOL, HWND, PPAINTSTRUCT))

def EndPaint(hwnd, ps):
    raise_on_zero(_EndPaint(hwnd, ref(ps)))

################################################################################

_DrawText = fun_fact(_usr.DrawTextW, (INT, HANDLE, PWSTR, INT, PRECT, UINT))

def DrawText(hdc, txt, rc, fmt):
    raise_on_zero(_DrawText(hdc, txt, len(txt), ref(rc), fmt))

################################################################################

_SetProp = fun_fact(_usr.SetPropW, (BOOL, HWND, PWSTR, HANDLE))

def SetProp(hwnd, name, data):
    raise_on_zero(_SetProp(hwnd, name, data))

################################################################################

_GetProp = fun_fact(_usr.GetPropW, (HANDLE, HWND, PWSTR))

def GetProp(hwnd, name):
    data = _GetProp(hwnd, name)
    raise_on_zero(data)
    return data

def get_prop_def(hwnd, name, default=None):
    data = _GetProp(hwnd, name)
    return data or default

################################################################################

_RemoveProp = fun_fact(_usr.RemovePropW, (HANDLE, HWND, PWSTR))

def RemoveProp(hwnd, name):
    data = _RemoveProp(hwnd, name)
    raise_on_zero(data)
    return data

################################################################################

_EnumPropsCallback = ctypes.WINFUNCTYPE(
    BOOL,
    HWND,
    PVOID,  # cannot use PWSTR, since it can be string or atom
    HANDLE,
    CallbackContextPtr
    )

@_EnumPropsCallback
def _EnumPropsCb(hwnd, name, data, ctxt):
    # cannot propagate exceptions from callback
    with kernel.terminate_on_exception():
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

def get_prop_dict(hwnd):
    props = {}

    @_EnumPropsCallback
    def collect(hwnd, name, data, not_used):
        #      string            or                      atom
        name = PWSTR(name).value if name >= 0x10000 else f"#{name}"
        props[name] = data
        return True

    _EnumPropsEx(hwnd, collect, None)
    return props

################################################################################

_OpenClipboard = fun_fact(_usr.OpenClipboard, (BOOL, HWND))

def OpenClipboard(hwnd):
    raise_on_zero(_OpenClipboard(hwnd))

################################################################################

_EmptyClipboard = fun_fact(_usr.EmptyClipboard, (BOOL,))

def EmptyClipboard():
    raise_on_zero(_EmptyClipboard())

################################################################################

_SetClipboardData = fun_fact(_usr.SetClipboardData, (HANDLE, UINT, HANDLE))

def SetClipboardData(fmt, hmem):
    res = _SetClipboardData(fmt, hmem)
    raise_on_zero(res)
    return res

################################################################################

_GetClipboardData = fun_fact(_usr.GetClipboardData, (HANDLE, UINT))

def GetClipboardData(fmt):
    res = _GetClipboardData(fmt)
    raise_on_zero(res)
    return res

################################################################################

IsClipboardFormatAvailable = fun_fact(
    _usr.IsClipboardFormatAvailable, (BOOL, UINT)
    )

################################################################################

_CloseClipboard = fun_fact(_usr.CloseClipboard, (BOOL,))

def CloseClipboard():
    raise_on_zero(_CloseClipboard())

################################################################################

_GetClipboardFormatName = fun_fact(
    _usr.GetClipboardFormatNameW, (DWORD, DWORD, PWSTR, DWORD)
    )

def GetClipboardFormatName(fmt_atom):
    bufsize = 1024
    buf = string_buffer(bufsize)
    if _GetClipboardFormatName(fmt_atom, buf, bufsize) == 0:
        raise WinError()
    return buf.value

################################################################################

EnumClipboardFormats = fun_fact(_usr.EnumClipboardFormats, (DWORD, DWORD))

################################################################################

def txt_to_clip(txt, hwnd=None):
    buf = string_buffer(txt)
    size = ctypes.sizeof(buf)
    copied = False
    hcopy = kernel.GlobalAlloc(GMEM_MOVEABLE, size)
    try:
        ctypes.memmove(kernel.GlobalLock(hcopy), buf, size)
        kernel.GlobalUnlock(hcopy)
        OpenClipboard(hwnd)
        try:
            EmptyClipboard()
            SetClipboardData(CF_UNICODETEXT, hcopy)
            copied = True
        finally:
            CloseClipboard()
    finally:
        if not copied:
            kernel.GlobalFree(hcopy)

################################################################################

def txt_from_clip(hwnd=None):
    if not IsClipboardFormatAvailable(CF_UNICODETEXT):
        raise OSError("no clipboard text available")
    OpenClipboard(hwnd)
    try:
        hmem = GetClipboardData(CF_UNICODETEXT)
        txt = ctypes.wstring_at(kernel.GlobalLock(hmem))
        kernel.GlobalUnlock(hmem)
    finally:
        CloseClipboard()
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
    raise_on_zero(_ScrollWindow(hwnd, x, y, scroll_rect, clip_rect))

################################################################################

_GetKeyNameText = fun_fact(_usr.GetKeyNameTextW, (INT, LONG, PWSTR, INT))

def GetKeyNameText(lparam, expect_empty=False):
    size = ret = 32
    while ret >= size - 1:
        size *= 2
        key_name = string_buffer(size)
        ret = _GetKeyNameText(lparam, key_name, size)
        raise_if(not ret and not expect_empty)
    return key_name.value

################################################################################

_CreateIconFromResourceEx = fun_fact(
    _usr.CreateIconFromResourceEx, (
        HANDLE, PVOID, DWORD, BOOL, DWORD, INT, INT, UINT
        )
    )

def CreateIconFromResourceEx(
        data,
        cx=0,
        cy=0,
        is_icon=True,
        default_size=False
        ):
    res = _CreateIconFromResourceEx(
        data,
        len(data),
        is_icon,
        0x00030000,
        cx,
        cy,
        LR_DEFAULTSIZE if default_size else 0
        )
    raise_on_zero(res)
    return res

################################################################################

class GUITHREADINFO(ctypes.Structure):
    _fields_ = (
        ("cbSize",        DWORD),
        ("flags",         DWORD),
        ("hwndActive",    HWND),
        ("hwndFocus",     HWND),
        ("hwndCapture",   HWND),
        ("hwndMenuOwner", HWND),
        ("hwndMoveSize",  HWND),
        ("hwndCaret",     HWND),
        ("rcCaret",       RECT),
        )

    def __init__(self):
        self.cbSize = ctypes.sizeof(self)

PGUITHREADINFO = POINTER(GUITHREADINFO)

_GetGUIThreadInfo = fun_fact(
    _usr.GetGUIThreadInfo, (BOOL, DWORD, PGUITHREADINFO)
    )

def GetGUIThreadInfo(tid=0):
    gti = GUITHREADINFO()
    raise_on_zero(_GetGUIThreadInfo(tid, ref(gti)))
    return gti

################################################################################

_SystemParametersInfo = fun_fact(
    _usr.SystemParametersInfoW, (BOOL, UINT, UINT, PVOID, UINT)
    )

################################################################################

class NONCLIENTMETRICS(ctypes.Structure):
    _fields_ = (
        ("cbSize",             UINT),
        ("iBorderWidth",       INT),
        ("iScrollWidth",       INT),
        ("iScrollHeight",      INT),
        ("iCaptionWidth",      INT),
        ("iCaptionHeight",     INT),
        ("lfCaptionFont",      LOGFONT),
        ("iSmCaptionWidth",    INT),
        ("iSmCaptionHeight",   INT),
        ("lfSmCaptionFont",    LOGFONT),
        ("iMenuWidth",         INT),
        ("iMenuHeight",        INT),
        ("lfMenuFont",         LOGFONT),
        ("lfStatusFont",       LOGFONT),
        ("lfMessageFont",      LOGFONT),
        ("iPaddedBorderWidth", INT),
        )

    def __init__(self):
        self.cbSize = ctypes.sizeof(self)

def get_non_client_metrics():
    ncm = NONCLIENTMETRICS()
    raise_on_zero(
        _SystemParametersInfo(
            SPI_GETNONCLIENTMETRICS,
            ncm.cbSize,
            ref(ncm),
            0
            )
        )
    return ncm

def set_non_client_metrics(ncm, winini=SPIF_UPDATEINIFILE | SPIF_SENDCHANGE):
    ncm.cbSize = ctypes.sizeof(ncm)
    raise_on_zero(
        _SystemParametersInfo(
            SPI_SETNONCLIENTMETRICS,
            ncm.cbSize,
            ref(ncm),
            winini
            )
        )

################################################################################

def get_wheel_scroll_lines():
    lines = UINT()
    raise_on_zero(
        _SystemParametersInfo(
            SPI_GETWHEELSCROLLLINES,
            0,
            ref(lines),
            0
            )
        )
    return lines.value

def set_wheel_scroll_lines(lines, winini=SPIF_UPDATEINIFILE | SPIF_SENDCHANGE):
    raise_on_zero(
        _SystemParametersInfo(
            SPI_SETWHEELSCROLLLINES,
            lines,
            None,
            winini
            )
        )

################################################################################

def get_work_area():
    wa = RECT()
    raise_on_zero(_SystemParametersInfo(SPI_GETWORKAREA, 0, ref(wa), 0))
    return wa

################################################################################

class DLGTEMPLATE(ctypes.Structure):
    _pack_ = 2  # for correct length
    _fields_ = (
        ("style", DWORD),
        ("dwExtendedStyle", DWORD),
        ("cdit", WORD),
        ("x", SHORT),
        ("y", SHORT),
        ("cx", SHORT),
        ("cy", SHORT),
        )

################################################################################

class DLGTEMPLATEEX(ctypes.Structure):
    _pack_ = 2  # for correct length
    _fields_ = (
        ("dlgVer", WORD),
        ("signature", WORD),
        ("helpID", DWORD),
        ("exStyle", DWORD),
        ("style", DWORD),
        ("cDlgItems", WORD),
        ("x", WORD),
        ("y", WORD),
        ("cx", WORD),
        ("cy", WORD),
        )

################################################################################

class DLGITEMTEMPLATE(ctypes.Structure):
    _pack_ = 2  # for correct length
    _fields_ = (
        ("style", DWORD),
        ("exstyle", DWORD),
        ("x", SHORT),
        ("y", SHORT),
        ("cx", SHORT),
        ("cy", SHORT),
        ("id", WORD),
        )

################################################################################

class NMHDR(ctypes.Structure):
    _fields_ = (
        ("hwndFrom", HWND),
        ("idFrom", UINT_PTR),
        ("code", UINT),
        )
PNMHDR = POINTER(NMHDR)

MSDN_FIRST = 0xf060       # ModelesS Dialog
MSDN_LAST = MSDN_FIRST + 50

MSDN_ACTIVATE = MSDN_FIRST + 1

class NM_MSD_ACTIVATE(ctypes.Structure):
    _fields_ = (
        ("hdr", NMHDR),
        ("is_active", BOOL),
        )

MSDN_DESTROY = MSDN_FIRST + 2
NM_MSD_DESTROY = NMHDR

################################################################################

DLGPROC = ctypes.WINFUNCTYPE(
    INT_PTR,
    HWND,
    UINT,
    WPARAM,
    LPARAM
    )

################################################################################

_DialogBoxIndirectParam = fun_fact(
    _usr.DialogBoxIndirectParamW, (INT_PTR, HANDLE, PVOID, HWND, DLGPROC, PVOID)
    )

def DialogBoxIndirectParam(templ, parent, dlg_func, init_param, hinst=None):
    kernel.SetLastError(0)
    res = _DialogBoxIndirectParam(hinst, templ, parent, dlg_func, init_param)
    raise_on_err(kernel.GetLastError())
    return res

################################################################################

_CreateDialogIndirectParam = fun_fact(
    _usr.CreateDialogIndirectParamW, (
        HWND, HANDLE, PVOID, HWND, DLGPROC, PVOID
        )
    )

def CreateDialogIndirectParam(templ, parent, dlg_func, init_param, hinst=None):
    res = _CreateDialogIndirectParam(hinst, templ, parent, dlg_func, init_param)
    raise_on_zero(res)
    return res

################################################################################

_EndDialog = fun_fact(_usr.EndDialog, (BOOL, HWND, INT_PTR))

def EndDialog(hdlg, result):
    raise_on_zero(_EndDialog(hdlg, result))

################################################################################

try:
    _w32 = ctypes.WinDLL("win32u.dll", use_last_error=True)
    _NtUserBuildHwndList = fun_fact(
        _w32.NtUserBuildHwndList, (
            NTSTATUS,
            HANDLE,
            HWND,
            BOOL,
            BOOL,
            DWORD,
            DWORD,
            PPVOID,
            PDWORD
            )
        )

    # build_wnd_list(0, 0) -> EnumWindows(...)
    # build_wnd_list(parent, 0) -> EnumChildWindows(parent, ...)
    # build_wnd_list(0, tid) -> EnumThreadWindows(tid, ...)

    def build_wnd_list(parent_wnd, thread_id, hdesk=0, hide_immersive=True):
        enum_children = bool(parent_wnd)
        allocated = 512
        while True:
            array = (allocated * PVOID)()
            received = DWORD()
            status = _NtUserBuildHwndList(
                hdesk,
                parent_wnd,
                enum_children,
                hide_immersive,
                thread_id,
                allocated,
                array,
                ref(received)
                )
            received = received.value
            if status == 0:
                break

            if status == ntdll.STATUS_BUFFER_TOO_SMALL:
                # avoid under-allocating due to newly added windows -> + 32
                allocated = received + 32
            else:
                raise WinError(ntdll.RtlNtStatusToDosError(status))

        return array[:received - 1]

except (FileNotFoundError, AttributeError):
    def build_wnd_list(parent_wnd, thread_id, hdesk=0, hide_immersive=True):
        raise NotImplementedError

################################################################################

_GetProcessWindowStation = fun_fact(_usr.GetProcessWindowStation, (HANDLE,))

def GetProcessWindowStation():
    res = _GetProcessWindowStation()
    raise_on_zero(res)
    return res

################################################################################

_GetThreadDesktop = fun_fact(_usr.GetThreadDesktop, (HANDLE, DWORD))

def GetThreadDesktop(tid):
    res = _GetThreadDesktop(tid)
    raise_on_zero(res)
    return res

################################################################################

_GetUserObjectInformation = fun_fact(
    _usr.GetUserObjectInformationW,
    (BOOL, HANDLE, INT, PVOID, DWORD, PDWORD)
    )

def GetUserObjectInformation(hdl, idx):
    size = DWORD()
    _GetUserObjectInformation(hdl, idx, None, 0, ref(size))
    buf = byte_buffer(size.value)
    raise_on_zero(_GetUserObjectInformation(hdl, idx, buf, size, ref(size)))
    return buf

################################################################################

class USEROBJECTFLAGS(ctypes.Structure):
    _fields_ = (
        ("fInherit", BOOL),
        ("fReserved", BOOL),
        ("dwFlags", DWORD),
        )

def is_interactive_process():
    uof = USEROBJECTFLAGS.from_buffer(
        GetUserObjectInformation(GetProcessWindowStation(), UOI_FLAGS)
        )
    return bool(uof.dwFlags & WSF_VISIBLE)

################################################################################
