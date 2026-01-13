################################################################################
#
# Copyright 2021-2026 Rocco Matano
# SPDX-License-Identifier: MIT
#
################################################################################
#
# This sample contains a simple dialog for calculating and displaying
# TOTP-based passwords.
#
################################################################################

import base64
import binascii
import hmac
import struct
import time

from ctwin32 import (
    EM_SETPASSWORDCHAR,
    ES_LEFT,
    DS_MODALFRAME,
    IDCANCEL,
    IDOK,
    SS_CENTER,
    WM_TIMER,
    WS_BORDER,
    WS_CAPTION,
    WS_GROUP,
    WS_POPUP,
    WS_SYSMENU,
    WS_TABSTOP,
    user,
    wndcls,
    )

################################################################################

class TotpDlg(wndcls.BaseDlg):

    TOTP_ID  = 100
    KEY_ID   = 101
    ED_STYLE = ES_LEFT | WS_BORDER | WS_TABSTOP
    DLG_ITEMS = (
        (SS_CENTER | WS_GROUP, 7, 7, 201, 9, TOTP_ID, "static", ""),
        (ED_STYLE, 7, 19, 201, 13, KEY_ID, "edit", ""),
        (WS_TABSTOP, 158, 39, 50, 14, IDCANCEL, "button", "Cancel"),
        )

    ############################################################################

    def __init__(self, time_step=30, digits=6, fontsize=10, parent=None):
        self.time_step = time_step
        self.digits = digits
        self.fontsize = fontsize
        self.init_msg = "TOTP key:"
        super().__init__(parent)

    ############################################################################

    def on_init_dialog(self):
        # black circle -> U+25cf
        self.get_item(self.KEY_ID).send_msg(EM_SETPASSWORDCHAR, 0x25cf, 0)
        self.set_item_text(self.TOTP_ID, self.init_msg)
        self.set_timer(1, 1000)
        self.center(self.parent)
        return True

    ############################################################################

    def on_command(self, cmd_id, notification, ctrl):
        if cmd_id in (IDOK, IDCANCEL):
            user.EndDialog(self.hwnd, cmd_id)
        return True

    ############################################################################

    def hotp(self, key, counter, digest="sha1"):
        try:
            key = base64.b32decode(key.upper() + "=" * ((8 - len(key)) % 8))
        except binascii.Error:
            return None
        cnt = struct.pack(">Q", counter)
        mac = hmac.new(key, cnt, digest).digest()
        pos = mac[-1] & 0x0f
        num = struct.unpack(">L", mac[pos:pos+4])[0] & 0x7fffffff
        return str(num)[-self.digits:].zfill(self.digits)

    ############################################################################

    def on_message(self, msg, wp, lp):
        if msg == WM_TIMER:
            txt = self.init_msg
            if key := self.get_item_text(self.KEY_ID):
                tme = int(time.time())
                rem = self.time_step - tme % self.time_step
                if otp := self.hotp(key, tme // self.time_step):
                    txt = f"TOTP = {otp} ({rem}s remain)"
            self.set_item_text(self.TOTP_ID, txt)
            return True

        return False

    ############################################################################

    def do_modal(self):
        template = wndcls.dlg_template(
            self.DLG_ITEMS,
            DS_MODALFRAME | WS_POPUP | WS_CAPTION | WS_SYSMENU,
            0,
            0,
            215,
            60,
            "TOTP Calculator",
            "MS Shell Dlg",
            (self.fontsize * self.get_dpi_scale_100() + 50) // 100
            )
        super().do_modal(template)

################################################################################

if __name__ == "__main__":
    TotpDlg().do_modal()

################################################################################
