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

import ctypes as _ct

from .wtypes import *
from . import (
    _raise_on_hr,
    _fun_fact,
    S_OK,
    )

_ctl = _ct.windll.comctl32
_ref = _ct.byref

################################################################################

_TaskDialog = _fun_fact(
    _ctl.TaskDialog, (
        HRESULT,
        HWND,
        HINSTANCE,
        PWSTR,
        PWSTR,
        PWSTR,
        DWORD,
        PWSTR,
        PINT
        )
    )

def TaskDialog(owner, title, main_instr, content, buttons, icon, inst=None):
    res = INT()
    _raise_on_hr(
        _TaskDialog(
            owner,
            inst,
            title,
            main_instr,
            content,
            buttons,
            icon,
            _ref(res)
            )
        )
    return res.value

################################################################################

_TaskDialogCallback = _ct.WINFUNCTYPE(
    LONG,
    HWND,
    UINT,
    WPARAM,
    LPARAM,
    CallbackContextPtr
    )

@_TaskDialogCallback
def _TskDlgCb(hwnd, msg, wp, lp, ctxt):
    cbc = ctxt.contents
    res = cbc.callback(hwnd, msg, wp, lp, cbc.context)
    # return S_OK if the callback fails to return a value
    return res if res is not None else S_OK

################################################################################

# ALL TASKDIALOG STRUCTURES NEED AN ALIGNMENT OF 1 (_pack_ = 1)!!!

class TASKDIALOG_BUTTON(_ct.Structure):
    _pack_ = 1
    _fields_ = (
        ("nButtonID", INT),
        ("pszButtonText", PWSTR),
        )

PTASKDIALOG_BUTTON = _ct.POINTER(TASKDIALOG_BUTTON)

class _TD_MAIN_ICON(_ct.Union):
    _pack_ = 1
    _fields_ = (("hMainIcon", HANDLE), ("pszMainIcon", PWSTR))

class _TD_FOOTER_ICON(_ct.Union):
    _pack_ = 1
    _fields_ = (("hFooterIcon", HANDLE), ("pszFooterIcon", PWSTR))


class TASKDIALOGCONFIG(_ct.Structure):
    _pack_ = 1
    _anonymous_ = ("_main_icon", "_footer_icon")
    _fields_ = (
        ("cbSize", UINT),
        ("hwndParent", HWND),
        ("hInstance", HINSTANCE),
        ("dwFlags", DWORD),
        ("dwCommonButtons", DWORD),
        ("pszWindowTitle", PWSTR),
        ("_main_icon", _TD_MAIN_ICON),
        ("pszMainInstruction", PWSTR),
        ("pszContent", PWSTR),
        ("cButtons", UINT),
        ("pButtons", PTASKDIALOG_BUTTON),
        ("nDefaultButton", INT),
        ("cRadioButtons", UINT),
        ("pRadioButtons", PTASKDIALOG_BUTTON),
        ("nDefaultRadioButton", INT),
        ("pszVerificationText", PWSTR),
        ("pszExpandedInformation", PWSTR),
        ("pszExpandedControlText", PWSTR),
        ("pszCollapsedControlText", PWSTR),
        ("_footer_icon", _TD_FOOTER_ICON),
        ("pszFooter", PWSTR),
        ("pfCallback", _TaskDialogCallback),
        ("lpCallbackData", CallbackContextPtr),
        ("cxWidth", UINT),
        )
    def __init__(self):
        self.cbSize = _ct.sizeof(self)

PTASKDIALOGCONFIG = _ct.POINTER(TASKDIALOGCONFIG)

################################################################################

_TaskDialogIndirect = _fun_fact(
    _ctl.TaskDialogIndirect, (
        HRESULT,
        PTASKDIALOGCONFIG,
        PINT,
        PINT,
        PBOOL
        )
    )

def TaskDialogIndirect(tsk_dlg_cfg):
    button_idx = INT()
    radio_idx = INT()
    verified = BOOL()
    _raise_on_hr(
        _TaskDialogIndirect(
            _ref(tsk_dlg_cfg),
            _ref(button_idx),
            _ref(radio_idx),
            _ref(verified)
            )
        )
    return button_idx.value, radio_idx.value, bool(verified.value)

################################################################################

def tsk_dlg_callback(tsk_dlg_cfg, callback, context=None):
    ctxt = CallbackContext(callback, context)
    tsk_dlg_cfg.pfCallback  = _TskDlgCb
    tsk_dlg_cfg.lpCallbackData = _ct.pointer(ctxt)
    return TaskDialogIndirect(tsk_dlg_cfg)

################################################################################
