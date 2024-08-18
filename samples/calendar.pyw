################################################################################
#
# Copyright 2021-2024 Rocco Matano
# SPDX-License-Identifier: MIT
#
################################################################################

from ctwin32 import (
    ctypes,
    comctl,     # for initialization of common controls
    user,
    wndcls,
    WM_CREATE,
    WM_SETFOCUS,
    WM_DESTROY,
    WM_QUIT,
    WS_BORDER,
    WS_CHILD,
    WS_VISIBLE,
    WS_OVERLAPPED,
    WS_CAPTION,
    WS_SYSMENU,
    WS_MINIMIZEBOX,
    SWP_NOMOVE,
    SWP_NOZORDER,
    )
from ctwin32.wtypes import RECT

MONTHCAL_CLASS = "SysMonthCal32"
MCS_WEEKNUMBERS = 4
MCM_FIRST = 0x1000
MCM_GETMINREQRECT = MCM_FIRST + 9

################################################################################

class CalendarWnd(wndcls.SimpleWnd):

    def on_message(self, msg, wp, lp):

        if msg == WM_CREATE:
            self.cal = wndcls.BaseWnd(
                user.CreateWindowEx(
                    0,
                    MONTHCAL_CLASS,
                    None,
                    WS_BORDER | WS_CHILD | WS_VISIBLE | MCS_WEEKNUMBERS,
                    0, 0, 0, 0, # resize it later
                    self.hwnd,
                    None,
                    self.hinstance(),
                    None
                    )
                )

            # get the size required to show an entire month
            control = RECT()
            self.cal.send_msg(MCM_GETMINREQRECT, 0, ctypes.addressof(control))

            # resize the control and parent
            self.cal.set_pos(None, 0, 0, control.width, control.height, 0)
            self.adjust_window_rect(control)
            return 0

        elif msg == WM_SETFOCUS:
            self.cal.set_focus()
            return 0

        elif msg == WM_DESTROY:
            user.PostQuitMessage(0)
            return 0

        else:
            return self.def_win_proc(msg, wp, lp)

################################################################################

if __name__ == "__main__":

    icon = wndcls.load_ctwin32_ico()
    style = WS_SYSMENU | WS_MINIMIZEBOX
    wnd = CalendarWnd(wndcls.WndCreateParams("Calendar", icon, style))
    wnd.show()

    while msg := user.GetMessage():
        user.TranslateMessage(msg)
        user.DispatchMessage(msg)

################################################################################
