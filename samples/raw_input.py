################################################################################
#
# Copyright 2021-2026 Rocco Matano
# SPDX-License-Identifier: MIT
#
################################################################################

# This example shows how to receive raw input even if the application is not
# in the foreground.

from ctwin32 import (
    FILE_TYPE_CHAR,
    HID_USAGE_PAGE_GENERIC,
    HID_USAGE_GENERIC_MOUSE,
    HID_USAGE_GENERIC_KEYBOARD,
    HWND_MESSAGE,
    kernel,
    MOD_ALT,
    MOD_CONTROL,
    MOD_SHIFT,
    MOD_WIN,
    RI_KEY_BREAK,
    RI_KEY_E0,
    RI_KEY_E1,
    RI_KEY_TERMSRV_SET_LED,
    RI_KEY_TERMSRV_SHADOW,
    RI_MOUSE_BUTTON_1_DOWN,
    RI_MOUSE_BUTTON_1_UP,
    RI_MOUSE_BUTTON_2_DOWN,
    RI_MOUSE_BUTTON_2_UP,
    RI_MOUSE_BUTTON_3_DOWN,
    RI_MOUSE_BUTTON_3_UP,
    RI_MOUSE_BUTTON_4_DOWN,
    RI_MOUSE_BUTTON_4_UP,
    RI_MOUSE_BUTTON_5_DOWN,
    RI_MOUSE_BUTTON_5_UP,
    RI_MOUSE_WHEEL,
    RIDEV_INPUTSINK,
    RIM_TYPEMOUSE,
    RIM_TYPEHID,
    RIM_TYPEKEYBOARD,
    STD_INPUT_HANDLE,
    user,
    VK_CONTROL,
    VK_LCONTROL,
    VK_RCONTROL,
    VK_END,
    VK_MENU,
    VK_LMENU,
    VK_RMENU,
    VK_SHIFT,
    VK_LSHIFT,
    VK_RSHIFT,
    VK_LWIN,
    VK_RWIN,
    WM_INPUT,
    wndcls,
    )

# press CTRL+SHIFT+ALT+WIN+end to terminate this program
EXIT_MODIFIERS = MOD_CONTROL | MOD_ALT | MOD_SHIFT | MOD_WIN
EXIT_KEY = VK_END

################################################################################

def dump_raw_mouse(d):
    s = d.usButtonFlags
    state = []
    if s & RI_MOUSE_BUTTON_1_DOWN:
        state.append("b1 down")
    if s & RI_MOUSE_BUTTON_1_UP:
        state.append("b1 up")
    if s & RI_MOUSE_BUTTON_2_DOWN:
        state.append("b2 down")
    if s & RI_MOUSE_BUTTON_2_UP:
        state.append("b2 up")
    if s & RI_MOUSE_BUTTON_3_DOWN:
        state.append("b3 down")
    if s & RI_MOUSE_BUTTON_3_UP:
        state.append("b3 up")
    if s & RI_MOUSE_BUTTON_4_DOWN:
        state.append("b4 down")
    if s & RI_MOUSE_BUTTON_4_UP:
        state.append("b4 up")
    if s & RI_MOUSE_BUTTON_5_DOWN:
        state.append("b5 down")
    if s & RI_MOUSE_BUTTON_5_UP:
        state.append("b5 up")
    if s & RI_MOUSE_WHEEL:
        state.append("wheel")
    msg = [
        "MOUSE:",
        f"flags = {d.usFlags:04x},",
        f"state = {','.join(state)},",
        f"data = {d.usButtonData},",
        f"x / y = {d.lLastX} / {d.lLastY}",
        ]
    print(" ".join(msg))

################################################################################

def dump_raw_keyboard(d):
    s = d.Flags
    state = []
    state.append("up" if s & RI_KEY_BREAK else "down")
    if s & RI_KEY_E0:
        state.append("E0")
    if s & RI_KEY_E1:
        state.append("E1")
    if s & RI_KEY_TERMSRV_SET_LED:
        state.append("termserv led")
    if s & RI_KEY_TERMSRV_SHADOW:
        state.append("termserv shadow")
    msg = [
        "KEYBOARD:",
        f"scan = {d.MakeCode:02x},",
        f"state = {','.join(state)},",
        f"vkey = {d.VKey:02x}",
        ]
    print(" ".join(msg))

################################################################################

def dump_raw_hid(d):
    msg = [
        "HID:",
        f"size = {d.dwSizeHid},",
        f"count = {d.dwCount},",
        f"data = {bytes(d.bRawData)}",
        ]
    print(" ".join(msg))

################################################################################

def dump_raw_input(ri):
    if ri.header.dwType == RIM_TYPEMOUSE:
        dump_raw_mouse(ri.data.mouse)
    elif ri.header.dwType == RIM_TYPEKEYBOARD:
        dump_raw_keyboard(ri.data.keyboard)
    elif ri.header.dwType == RIM_TYPEHID:
        dump_raw_hid(ri.data.hid)
    else:
        raise ValueError(f"unknown raw input: {ri.header.dwType}")

################################################################################

class RawInputDest(wndcls.SimpleWnd):
    def __init__(self, wc_params):
        self.modifiers = 0
        self.conin = kernel.GetStdHandle(STD_INPUT_HANDLE)
        if self.conin is not None:
            if kernel.GetFileType(self.conin) != FILE_TYPE_CHAR:
                self.conin = None
        super().__init__(wc_params)

    ############################################################################

    def handle_modifiers(self, key, make):
        if key in (VK_CONTROL, VK_LCONTROL, VK_RCONTROL):
            mod = MOD_CONTROL
        elif key in (VK_MENU, VK_LMENU, VK_RMENU):
            mod = MOD_ALT
        elif key in (VK_SHIFT, VK_LSHIFT, VK_RSHIFT):
            mod = MOD_SHIFT
        elif key in (VK_LWIN, VK_RWIN):
            mod = MOD_WIN
        else:
            return False

        if make:
            self.modifiers |= mod
        else:
            self.modifiers &= ~ mod
        return True

    ############################################################################

    def on_message(self, msg, wp, lp):
        if msg != WM_INPUT:
            return self.def_win_proc(msg, wp, lp)

        # get raw input and dump it
        ri = user.GetRawInputData(lp)
        dump_raw_input(ri)

        if self.conin is not None:
            # remove input from console input buffer
            while num := kernel.GetNumberOfConsoleInputEvents(self.conin):
                kernel.ReadConsoleInput(self.conin, num)

        # exit program if the corresponding input is detected
        if ri.header.dwType == RIM_TYPEKEYBOARD:
            key = ri.data.keyboard.VKey
            make = not (ri.data.keyboard.Flags & RI_KEY_BREAK)
            self.handle_modifiers(key, make)
            if key == EXIT_KEY and self.modifiers == EXIT_MODIFIERS:
                user.PostQuitMessage(0)

        return 0

################################################################################

if __name__ == "__main__":

    wnd = RawInputDest(wndcls.WndCreateParams(parent=HWND_MESSAGE))

    gen = HID_USAGE_PAGE_GENERIC
    mouse = HID_USAGE_GENERIC_MOUSE
    keybo = HID_USAGE_GENERIC_KEYBOARD
    raw_devs = [
        user.RAWINPUTDEVICE(gen, mouse, RIDEV_INPUTSINK, wnd.hwnd),
        user.RAWINPUTDEVICE(gen, keybo, RIDEV_INPUTSINK, wnd.hwnd),
        ]
    user.RegisterRawInputDevices(raw_devs)

    while msg := user.GetMessage():
        user.TranslateMessage(msg)
        user.DispatchMessage(msg)

################################################################################
