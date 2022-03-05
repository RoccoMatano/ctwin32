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

# This sample was inspired by Charles Petzold's 'keyview' sample from his
# 'Programming Windows' book (https://www.charlespetzold.com/pw5/index.html)

import dataclasses
from ctwin32 import (
    user,
    gdi,
    wndcls,
    RECT,
    WM_CREATE,
    WM_PAINT,
    WM_DESTROY,
    WM_QUIT,
    WM_SIZE,
    WM_KEYFIRST,
    WM_KEYLAST,
    WM_CHAR,
    WM_SYSCHAR,
    WM_DEADCHAR,
    WM_SYSDEADCHAR,
    WM_SETICON,
    SW_SHOW,
    DEFAULT_CHARSET,
    SYSTEM_FONT,
    SWP_NOMOVE,
    SM_CYMAXIMIZED,
    TRANSPARENT,
    )

################################################################################

@dataclasses.dataclass
class HistoryEntry:
    msg: int = 0
    wp: int = 0
    lp: int = 0

################################################################################

class KeyViewWnd(wndcls.SimpleWnd):

    def __init__(self, wc_params):
        self.heading = (
            " message        key     char              rep.  "
            "scan   ext. alt   prev  now"
            )
        self.underline = "".join(
                (" " if c == " " else "_") for c in self.heading
                )
        self.msg_fmt = [
            " %-13s %3d %-18s%c%6u  %4d     %3s %4s %6s %5s",
            " %-13s          0x%04X     %1s%c %6u  %4d     %3s %4s %6s %5s"
            ]
        self.msg_name = [
            "WM_KEYDOWN",
            "WM_KEYUP",
            "WM_CHAR",
            "WM_DEADCHAR",
            "WM_SYSKEYDOWN",
            "WM_SYSKEYUP",
            "WM_SYSCHAR",
            "WM_SYSDEADCHAR"
            ]
        self.font = None
        self.char_height = 0
        self.num_lines = 0
        self.scroll_rect = RECT()
        self.max_lines = 0

        # have to call __init__ of base class AFTER preparing members that
        # might get accessed by on_message
        super().__init__(wc_params)

    ############################################################################

    def on_create(self):
        hdc = self.get_dc()
        lf = gdi.LOGFONT()
        lf.lfCharSet = DEFAULT_CHARSET
        lf.lfFaceName = "consolas"
        lf.lfHeight = 16
        self.font = gdi.CreateFontIndirect(lf)
        gdi.SelectObject(hdc, self.font)
        tm = gdi.GetTextMetrics(hdc)
        gdi.SelectObject(hdc, gdi.GetStockObject(SYSTEM_FONT))
        self.release_dc(hdc)

        self.char_height = tm.tmHeight;
        size = (len(self.underline) + 4) * tm.tmAveCharWidth
        self.set_pos(None, 0, 0, size, size, SWP_NOMOVE);

        self.max_lines = (
            user.GetSystemMetrics(SM_CYMAXIMIZED) // self.char_height
            )
        self.history = [None] * self.max_lines

        return 0

    ############################################################################

    def on_paint(self):
        hdc, ps = self.begin_paint()
        gdi.SelectObject(hdc, self.font)

        gdi.SetBkMode(hdc, TRANSPARENT)
        gdi.TextOut(hdc, 0, 0, self.heading)
        gdi.TextOut(hdc, 0, 0, self.underline)

        char_msg = (WM_CHAR, WM_SYSCHAR, WM_DEADCHAR, WM_SYSDEADCHAR)
        for i in range(min(self.num_lines, self.y_lines)):
            then = self.history[i]
            is_char = then.msg in char_msg
            line = self.msg_fmt[is_char] % (
                self.msg_name[then.msg - WM_KEYFIRST],
                then.wp,
                " " if is_char else user.GetKeyNameText(then.lp, True),
                then.wp if is_char else ' ',
                then.lp & 0xffff,
                (then.lp >> 16) & 0xff,
                "yes" if 0x01000000 & then.lp else "no",
                "yes" if 0x20000000 & then.lp else "no",
                "down" if 0x40000000 & then.lp else "up",
                "down" if 0x80000000 & then.lp else "up",
                )
            gdi.TextOut(hdc, 0, (self.y_lines - i) * self.char_height, line)

        gdi.SelectObject(hdc, gdi.GetStockObject(SYSTEM_FONT))
        self.end_paint(ps)
        return 0

    ############################################################################

    def on_message(self, msg, wp, lp):

        if msg == WM_CREATE:
            return self.on_create()

        elif msg == WM_SIZE:
            self.y_lines = ((lp >> 16) & 0xffff) // self.char_height - 1
            self.scroll_rect.right  = lp & 0xffff
            self.scroll_rect.top    = self.char_height;
            self.scroll_rect.bottom = self.char_height * (self.y_lines + 1)
            self.invalidate_rect(erase=True)
            return 0

        elif WM_KEYFIRST <= msg < WM_KEYLAST:
            self.history.pop()
            self.history.insert(0, HistoryEntry(msg, wp, lp))

            self.num_lines = min(self.num_lines + 1, self.max_lines);
            rc = self.scroll_rect
            user.ScrollWindow(self.hwnd, 0, -self.char_height, rc, rc)
            return self.def_win_proc(msg, wp, lp)

        elif msg == WM_PAINT:
            return self.on_paint()

        elif msg == WM_DESTROY:
            gdi.DeleteObject(self.font)
            user.PostQuitMessage(0)
            return 0

        else:
            return self.def_win_proc(msg, wp, lp)

################################################################################

if __name__ == "__main__":

    wcp = wndcls.WndCreateParams()
    wcp.name = "keyview"
    wcp.cls.hIcon = wndcls.load_py_ico()
    wnd = KeyViewWnd(wcp)
    wnd.show()

    msg = user.GetMessage()
    while msg.message != WM_QUIT:
        user.TranslateMessage(msg)
        user.DispatchMessage(msg)
        msg = user.GetMessage()

################################################################################
