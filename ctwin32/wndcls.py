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

import sys
import traceback
import ctypes as _ct

from ctwin32.wtypes import *
from ctwin32 import (
    _raise_if,
    _fun_fact,
    kernel,
    user,
    gdi,
    WM_NOTIFY,
    SW_SHOW,
    HWND_TOP,
    HWND_TOPMOST,
    SWP_NOSIZE,
    SWP_NOMOVE,
    SWP_NOACTIVATE,
    HORZRES,
    HORZSIZE,
    GWL_STYLE,
    GWL_EXSTYLE,
    GWLP_HINSTANCE,
    BST_CHECKED,
    BST_UNCHECKED,
    COLOR_WINDOW,
    IDC_ARROW,
    CW_USEDEFAULT,
    WS_OVERLAPPEDWINDOW,
    CS_HREDRAW,
    CS_VREDRAW,
    CS_DBLCLKS,
    WM_NCCREATE,
    GWLP_USERDATA,
    WM_NCDESTROY,
    SW_SHOW,
    MB_OK,
    MB_ICONERROR,
    )

_ref = _ct.byref

################################################################################

class NMHDR(_ct.Structure):
    _fields_ = (
        ("hwndFrom", HWND),
        ("idFrom", UINT_PTR),
        ("code", UINT),
        )

PNMHDR = _ct.POINTER(NMHDR)

################################################################################

class BaseWnd:

    def __init__(hwnd=None):
        self.hwnd = hwnd

    def def_win_proc(self, msg, wp, lp):
        return user.DefWindowProc(self.hwnd, msg, wp, lp)

    def is_window(self):
        return bool(user.IsWindow(self.hwnd))

    def get_dlg_item(self, id):
        return self.__class__(user.GetDlgItem(self.hwnd, id))

    def send_msg(self, msg, wp, lp):
        return user.SendMessage(self.hwnd, msg, wp, lp)

    def post_msg(self, msg, wp, lp):
        user.PostMessage(self.hwnd, msg, wp, lp)

    def send_dlg_item_msg(self, id , msg, wp, lp):
        return user.SendDlgItemMessage(self.hwnd, id, msg, wp, lp)

    def set_dlg_item_text(self, id , txt):
        user.SetDlgItemText(self.hwnd, id, txt)

    def send_notify(self, nmhdr):
        return user.SendMessage(
            self.hwnd,
            WM_NOTIFY,
            nmhdr.idFrom,
            LPARAM(_ct.cast(_ref(nmhdr), PVOID).value)
            )

    def destroy(self):
        user.DestroyWindow(self.hwnd)
        self.hwnd = None

    def show(self, how=SW_SHOW):
        user.ShowWindow(self.hwnd, how)

    def hide(self):
        user.ShowWindow(self.hwnd, SW_HIDE)

    def enable(self, enabled=True):
        user.EnableWindow(self.hwnd, enabled)

    def disable(self):
        user.EnableWindow(self.hwnd, False)

    def activate(self):
        user.SetActiveWindow(self.hwnd)

    def set_foreground(self):
        user.SetForegroundWindow(self.hwnd)

    def invalidate_rect(self, rc=None, erase=False):
        user.InvalidateRect(self.hwnd, rc, Erase)

    def update(self):
        user.UpdateWindow(self.hwnd)

    def get_parent(self):
        return self.__class__(user.GetParent(self.hwnd))

    def move(self, rc, repaint=True):
        user.MoveWindow(
            self.hwnd,
            rc.left,
            rc.top,
            rc.width(),
            rc.height(),
            repaint
            )

    def set_pos(self, wnd_ins_after, x, y, cx, cy, flags):
        user.SetWindowPos(
            self.hwnd,
            wnd_ins_after.hwnd,
            X,
            Y,
            cx,
            cy,
            flags
            )

    def set_topmost(self):
        self.set_pos(
            self.__class__(HWND_TOPMOST),
            0,
            0,
            0,
            0,
            SWP_NOSIZE | SWP_NOMOVE | SWP_NOACTIVATE
            )

    def set_non_topmost(self):
        self.set_pos(
            self.__class__(HWND_TOP),
            0,
            0,
            0,
            0,
            SWP_NOSIZE | SWP_NOMOVE | SWP_NOACTIVATE
            )

    def bring_to_top(self):
        user.BringWindowToTop(self.hwnd)

    def map_window_point(self, to_bwnd, pt):
        user.MapWindowPoints(self.hwnd, to_bwnd.hwnd, _ref(pt), 1)
        return pt

    def map_window_rect(self, to_bwnd, rc):
        ppt = _ct.cast(_ref(rc), PPOINT)
        user.MapWindowPoints(self.hwnd, to_bwnd.hwnd, ppt, 2)
        return rc

    def lp_pt_to_parent(self, lp):
        pt = POINT.from_lparam(lp)
        user.MapWindowPoints(self.hwnd, user.GetParent(self.hwnd), _ref(pt), 1)
        return pt.as_lparam()

    def client_to_screen(self, pt_or_rc):
        meth = (
            self.map_window_point if isinstance(pt_or_rc, POINT)
            else self.map_window_rect
            )
        return meth(self.__class__(), pt_or_rc)

    def window_rect(self):
        return user.GetWindowRect(self.hwnd)

    def client_rect(self):
        return user.GetClientRect(self.hwnd)

    def window_rect_as_client(self):
        rc = self.window_rect()
        ppt = _ct.cast(_ref(rc), PPOINT)
        user.MapWindowPoints(None, self.hwnd, ppt, 2)
        return rc

    def window_rect_as_other_client(self, other):
        rc = self.window_rect()
        ppt = _ct.cast(_ref(rc), PPOINT)
        user.MapWindowPoints(None, other.hwnd, ppt, 2)
        return rc

    def get_cursor_pos(self):
        pt = user.GetCursorPos()
        user.MapWindowPoints(None, self.hwnd, _ref(pt), 1)
        return pt;

    def get_nc_cursor_pos(self):
        pt = user.GetCursorPos()
        rc = self.window_rect()
        pt.x -= rc.left
        pt.y -= rc.top
        return pt

    def cursor_over_thread_wnd(self):
        pt = user.GetCursorPos()
        tid, _ = user.GetWindowThreadProcessId(user.WindowFromPoint(pt))
        return (tid == kernel.GetCurrentThreadId())

    def get_dc(self):
        return user.GetDC(self.hwnd)

    def release_dc(self):
        user.ReleaseDC(self.hwnd)

    def get_dpi_scale_100(self):
        hdc = self.get_dc()
        try:
            hres = gdi.GetDeviceCaps(hdc, HORZRES)
            hsize = gdi.GetDeviceCaps(hdc, HORZSIZE)
            dpi_100 = (hres * 2540 + hsize // 2) // hsize
            return (dpi_100 + 48) // 96
        finally:
            self.release_dc(hdc)

    def get_style(self):
        return user.GetWindowLong(self.hwnd, GWL_STYLE)

    def get_exstyle(self):
        return user.GetWindowLong(self.hwnd, GWL_EXSTYLE)

    def modify_style(self, remove, add, flags=0, idx=GWL_STYLE):
        style = user.GetWindowLong(self.hwnd, idx)
        new_style = (style & ~remove) | add
        if new_style != style:
            user.SetWindowLong(self.hwnd, idx, new_style)
            if flags:
                flags |= SWP_NOSIZE | SWP_NOMOVE | SWP_NOZORDER;
                self.SetPos(None, 0, 0, 0, 0, flags);

    def modify_exstyle(self, remove, add, flags=0):
        self.modify_style(remove, add, flags, GWL_EXSTYLE)

    def hinstance(self):
        return HANDLE(user.GetWindowLongPtr(self.hwnd, GWLP_HINSTANCE))

    def set_timer(self, id, period):
        user.SetTimer(self.hwnd, id, period)

    def kill_timer(self, id):
        user.KillTimer(self.hwnd, id)

    def set_text(self, txt):
        user.SetWindowText(self.hwnd, txt)

    def get_text(self):
        return user.GetWindowText(self.hwnd)

    def get_font(self):
        return HANDLE(self.send_msg(WM_GETFONT, 0, 0))

    def check_dlg_button(id, checked):
        user.CheckDlgButton(
            self.hwnd,
            id,
            BST_CHECKED if checked else BST_UNCHECKED
            )

    def is_dlg_button_checked(self, id):
        return (user.IsDlgButtonChecked(self.hwnd, id) == BST_CHECKED)

    def begin_paint(self):
        return user.BeginPaint(self.hwnd)

    def end_paint(self, ps):
        user.EndPaint(self.hwnd, ps)

    def set_prop(self, name, data):
        user.SetProp(self.hwnd, name, data)

    def get_prop(self, name, data):
        return user.GetProp(self.hwnd, name)

    def get_prop_def(self, name, data, default=None):
        return user.get_prop_def(self.hwnd, name, default)

    def del_prop(self, name):
        return user.RemoveProp(self.hwnd, name)

################################################################################
################################################################################
################################################################################

class WndCreateParams:
    def __init__(self):
        self.cls = user.WNDCLASS()
        self.cls.hbrBackground = COLOR_WINDOW + 1
        self.cls.hInstance = kernel.GetModuleHandle(None)
        self.cls.hCursor = user.LoadCursor(None, IDC_ARROW)
        self.cls.style = CS_HREDRAW | CS_VREDRAW | CS_DBLCLKS
        self.wnd_style = WS_OVERLAPPEDWINDOW
        self.ex_style = 0
        self.left = self.top = self.width = self.height = CW_USEDEFAULT
        self.menu = self.parent = None
        self.name = ""

################################################################################

_PROP_SELF = f"ctwin32:SimpleWnd:self"

class SimpleWnd(BaseWnd):

    def __init__(self, wc_params: WndCreateParams = None):
        self.hwnd = None
        self.parent = None
        if wc_params is not None:
            self.create(wc_params)

    ############################################################################

    @user.WNDPROC
    @staticmethod
    def _wnd_proc_(hwnd, msg, wp, lp):
        # Since this is a python callback that ctypes calls when requested
        # by foreign C code, ctypes has no way of propagating any exception
        # that might get raised back to the python interpreter - that exception
        # would simply be ignored. Therefore we have to catch all unhandled
        # exceptions here. In such a case we try to inform the user and
        # terminate the program.
        try:
            if msg != WM_NCCREATE:
                self_prop = user.get_prop_def(hwnd, _PROP_SELF)
                if self_prop:
                    self = _ct.cast(self_prop, _ct.py_object).value
                    res = self.on_message(msg, wp, lp)
                    if msg == WM_NCDESTROY:
                        self.hwnd = None
                    return res

                # Some kind of messages may arrive before WM_NCCREATE
                # (e.g. WM_GETMINMAXINFO), i.e. still self_prop == None.
                return user.DefWindowProc(hwnd, msg, wp, lp)

            cparam = user.CREATESTRUCT.from_address(lp).lpCreateParams
            self = _ct.cast(cparam, _ct.py_object).value
            if isinstance(self, SimpleWnd):
                self.hwnd = hwnd
                self.set_prop(_PROP_SELF, cparam)
                return self.on_message(msg, wp, lp)
            else:
                raise TypeError("not derived from SimpleWnd")
        except BaseException:
            err_info = traceback.format_exc()
            if sys.stderr is None or not hasattr(sys.stderr, 'mode'):
                user.txt_to_clip(err_info)
                err_info += '\nThe above text has been copied to the clipboard.'
                user.MessageBox(
                    None,
                    err_info,
                    "Terminating program",
                    MB_OK | MB_ICONERROR
                    )
            else:
                sys.stderr.write(err_info)

            # Calling sys.exit() here won't help, since it depends on exception
            # propagation. We could hope that this thread is pumping messages
            # while watching for WM_QUIT messages and post such a message.
            # Since this possibility seems too vague, we play it safe
            # and call:
            kernel.ExitProcess(1)

    ############################################################################

    def create(self, wcp):
        if self.is_window():
            raise RecursionError("can only be created once")
        self.parent = wcp.parent
        wcp.cls.lpfnWndProc = self._wnd_proc_

        if wcp.cls.lpszClassName is None:
            # calc hash over wcp.cls and in case it is negative convert it
            # to its two's complement.
            h = hash(bytes(wcp.cls))
            h = h & (2 ** (h.bit_length() + 1) - 1)
            wcp.cls.lpszClassName = f"ctwin32:{h:x}"

        try:
            user.GetClassInfo(wcp.cls.hInstance, wcp.cls.lpszClassName)
        except OSError:
            user.RegisterClass(wcp.cls)

        user.CreateWindowEx(
            wcp.ex_style,
            wcp.cls.lpszClassName,
            wcp.name,
            wcp.wnd_style,
            wcp.left,
            wcp.top,
            wcp.width,
            wcp.height,
            wcp.parent,
            wcp.menu,
            wcp.cls.hInstance,
            # PVOID (or more precisely ctypes.c_void_p) has a flaw: neither can
            # PVOID.from_param() process a py_object, nor does ctypes.cast()
            # allow to convert a py_object to a PVOID (
            # _ct.cast(_ct.py_object(self), PVOID) fails).
            # Therefore we need this odd way of converting a python object
            # pointer to PVOID.
            PVOID.from_buffer(_ct.py_object(self))
            )

    ############################################################################

    def on_message(self, msg, wp, lp):
        raise NotImplementedError("must be implemented in derived class")

    ############################################################################

    def __del__(self):
        if self.is_window():
            self.destroy()

################################################################################
