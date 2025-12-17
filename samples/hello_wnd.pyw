################################################################################
#
# Copyright 2021-2025 Rocco Matano
# SPDX-License-Identifier: MIT
#
################################################################################

from ctwin32 import (
    ctypes,
    user,
    gdi,
    wndcls,
    comctl,
    shell,
    WM_CONTEXTMENU,
    WM_CREATE,
    WM_PAINT,
    WM_DESTROY,
    WS_CHILD,
    DT_CENTER,
    DT_SINGLELINE,
    DT_VCENTER,
    TDN_HYPERLINK_CLICKED,
    TDF_ALLOW_DIALOG_CANCELLATION,
    TDF_ENABLE_HYPERLINKS,
    TDF_POSITION_RELATIVE_TO_WINDOW,
    TDCBF_CLOSE_BUTTON,
    TD_INFORMATION_ICON,
    )
from ctwin32.wtypes import LOGFONT

################################################################################

def td_follow_link(hwnd, msg, wp, lp, ctxt):
    if msg == TDN_HYPERLINK_CLICKED:
        shell.ShellExecuteEx(ctypes.wstring_at(lp))

################################################################################

class DummyWnd(wndcls.SimpleWnd):
    def on_message(self, msg, wp, lp):
        return self.def_win_proc(msg, wp, lp)

################################################################################

class HelloWnd(wndcls.SimpleWnd):

    def on_message(self, msg, wp, lp):

        if msg == WM_CREATE:
            lf = LOGFONT()
            lf.lfFaceName = "MS Shell Dlg"
            lf.lfHeight = -72
            self.font = gdi.CreateFontIndirect(lf)
            return 0

        if msg == WM_PAINT:
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

        if msg == WM_DESTROY:
            gdi.DeleteObject(self.font)
            user.PostQuitMessage(0)
            return 0

        if msg == WM_CONTEXTMENU:
            # child window placed at mouse cursor that is used as the parent
            # for TaskDialog in order to be able to place that dialog
            cp = wndcls.WndCreateParams(style=WS_CHILD, parent=self.hwnd)
            pos = self.get_cursor_pos()
            cp.left = pos.x
            cp.top = pos.y
            placed = DummyWnd(cp)
            try:
                tdi = "TaskDialogIndirect"
                url = f"https://www.google.com/search?q={tdi}"
                tdc = comctl.TASKDIALOGCONFIG()
                tdc.hwndParent = placed.hwnd
                tdc.dwFlags = (
                    TDF_ALLOW_DIALOG_CANCELLATION |
                    TDF_ENABLE_HYPERLINKS |
                    TDF_POSITION_RELATIVE_TO_WINDOW
                    )
                tdc.dwCommonButtons = TDCBF_CLOSE_BUTTON
                tdc.pszWindowTitle = "TaskDialog Sample"
                tdc.pszMainIcon = TD_INFORMATION_ICON
                tdc.pszMainInstruction = f"Showing off {tdi}!"
                tdc.pszContent = f'Search Google for <a href="{url}">{tdi}</a>.'
                comctl.tsk_dlg_callback(tdc, td_follow_link)
            finally:
                placed.destroy()
            return 0

        return self.def_win_proc(msg, wp, lp)

################################################################################

if __name__ == "__main__":

    icon = wndcls.load_ctwin32_ico()
    wnd = HelloWnd(wndcls.WndCreateParams("Hello Window", icon))
    wnd.show()

    while msg := user.GetMessage():
        user.TranslateMessage(msg)
        user.DispatchMessage(msg)

################################################################################
