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

from ctwin32 import (
    ctypes,
    comctl,     # for initialization of common controls
    user,
    wndcls,
    RECT,
    WM_CREATE,
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

MONTHCAL_CLASS = "SysMonthCal32"
MCS_WEEKNUMBERS = 4
MCM_FIRST = 0x1000
MCM_GETMINREQRECT = MCM_FIRST + 9

################################################################################

class CalendarWnd(wndcls.SimpleWnd):

    def on_message(self, msg, wp, lp):

        if msg == WM_CREATE:
            hcal = wndcls.BaseWnd(
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
            hcal.send_msg(MCM_GETMINREQRECT, 0, ctypes.addressof(control))

            # resize the control and parent
            hcal.set_pos(
                None,
                0,
                0,
                control.width,
                control.height,
                SWP_NOZORDER | SWP_NOMOVE
                )
            frame = user.AdjustWindowRectEx(
                control,
                self.get_style(),
                False,
                self.get_exstyle()
                )
            wrc = self.window_rect()
            self.set_pos(
                None,
                wrc.left,
                wrc.top,
                frame.width,
                frame.height,
                SWP_NOZORDER
                )
            return 0

        elif msg == WM_DESTROY:
            user.PostQuitMessage(0)
            return 0

        else:
            return self.def_win_proc(msg, wp, lp)

################################################################################

if __name__ == "__main__":

    wcp = wndcls.WndCreateParams()
    wcp.name = "Calendar"
    wcp.wnd_style = WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU | WS_MINIMIZEBOX
    for idx in range(1, 1024):
        try:
            wcp.cls.hIcon = user.LoadIcon(wcp.cls.hInstance, idx)
            break
        except OSError:
            pass
    wnd = CalendarWnd(wcp)
    wnd.show()

    msg = user.GetMessage()
    while msg.message != WM_QUIT:
        user.TranslateMessage(msg)
        user.DispatchMessage(msg)
        msg = user.GetMessage()

################################################################################
