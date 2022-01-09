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
    user,
    gdi,
    wndcls,
    WM_CREATE,
    WM_PAINT,
    WM_DESTROY,
    WM_SETICON,
    WM_QUIT,
    SW_SHOW,
    DT_CENTER,
    DT_SINGLELINE,
    DT_VCENTER,
    )

################################################################################

class HelloWnd(wndcls.SimpleWnd):

    def on_message(self, msg, wp, lp):

        if msg == WM_CREATE:
            lf = gdi.LOGFONT()
            lf.lfFaceName = "MS Shell Dlg"
            lf.lfHeight = -72
            self.font = gdi.CreateFontIndirect(lf)

            for idx in range(1, 1024):
                try:
                    ico = user.LoadIcon(self.hinstance(), idx)
                    self.send_msg(WM_SETICON, 0, ico)
                    self.send_msg(WM_SETICON, 1, ico)
                    break
                except OSError:
                    pass

            return 0

        elif msg == WM_PAINT:
            hdc, ps = self.begin_paint()
            oldfont = gdi.SelectObject(hdc, self.font)
            user.DrawText(
                hdc,
                "Hello from ctwin32!",
                self.client_rect(),
                DT_CENTER | DT_SINGLELINE | DT_VCENTER
                )
            gdi.SelectObject(hdc, oldfont)
            self.end_paint(ps)
            return 0

        elif msg == WM_DESTROY:
            gdi.DeleteObject(self.font)
            user.PostQuitMessage(0)
            return 0

        else:
            return self.def_win_proc(msg, wp, lp)

################################################################################

if __name__ == "__main__":

    wcp = wndcls.WndCreateParams()
    wcp.name = "Hello Window"
    wnd = HelloWnd(wcp)
    wnd.show()

    msg = user.GetMessage()
    while msg.message != WM_QUIT:
        user.TranslateMessage(msg)
        user.DispatchMessage(msg)
        msg = user.GetMessage()

################################################################################
