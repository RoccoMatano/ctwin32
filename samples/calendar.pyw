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
