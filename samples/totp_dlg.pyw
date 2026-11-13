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
    EN_CHANGE,
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
    COPY_ID  = 102
    ED_STYLE = ES_LEFT | WS_BORDER | WS_TABSTOP
    DLG_ITEMS = (
        (SS_CENTER | WS_GROUP, 7, 7, 201, 9, TOTP_ID, "static", ""),
        (ED_STYLE, 7, 19, 201, 13, KEY_ID, "edit", ""),
        (WS_TABSTOP, 94, 39, 50, 14, COPY_ID, "button", "Copy"),
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
        self.update_ui()
        return True

    ############################################################################

    def hotp(self, key, counter, digest="sha1"):
        if not key:
            return None
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

    def get_otp_rem(self, key):
        tme = int(time.time())
        rem = self.time_step - tme % self.time_step
        otp = self.hotp(key, tme // self.time_step)
        return (otp, rem) if otp else ()

    ############################################################################

    def update_ui(self):
        txt = self.init_msg
        enable_cpy = False
        if otp_rem := self.get_otp_rem(self.get_item_text(self.KEY_ID)):
            txt = f"TOTP = {otp_rem[0]} ({otp_rem[1]}s remain)"
            enable_cpy = True
        self.get_item(self.COPY_ID).enable(enable_cpy)
        self.set_item_text(self.TOTP_ID, txt)

    ############################################################################

    def on_command(self, cmd_id, notification, ctrl):
        if cmd_id in (IDOK, IDCANCEL):
            user.EndDialog(self.hwnd, cmd_id)
        elif cmd_id == self.COPY_ID:
            if key := self.get_item_text(self.KEY_ID):
                if otp_rem := self.get_otp_rem(key):
                    user.txt_to_clip(otp_rem[0], self.hwnd)
        elif cmd_id == self.KEY_ID and notification == EN_CHANGE:
            self.update_ui()
        return True

    ############################################################################

    def on_message(self, msg, wp, lp):
        if msg == WM_TIMER:
            self.update_ui()
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
    with wndcls.display_fatal_exception():
        TotpDlg().do_modal()

################################################################################
