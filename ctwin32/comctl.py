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

import tempfile
import pathlib
import ctypes as _ct

from .wtypes import *
from . import (
    kernel,
    _raise_if,
    _raise_on_hr,
    _fun_fact,
    S_OK,
    ACTCTX_FLAG_RESOURCE_NAME_VALID,
    ACTCTX_FLAG_ASSEMBLY_DIRECTORY_VALID,
    )

_ref = _ct.byref

################################################################################

def _load_comctl():

    # The version of comctl32 that is loaded by LoadLibrary is determined by
    # the activation context that is currently active. Since we need at least
    # version 6, we have to ensure that the current activation context is set
    # up for this version. Currenly the executables 'python.exe' and
    # 'pythonw.exe' contain a manifest resource that ensures that such a context
    # context is active (py 3.10). To be on the safe side, we are going to
    # activate a matching context anyway.

    # create a temporary manifest file
    manifest = (
        "<assembly xmlns='urn:schemas-microsoft-com:asm.v1' manifestVersion=",
        "'1.0'><dependency><dependentAssembly><assemblyIdentity type='win32'",
        " name='Microsoft.Windows.Common-Controls' version='6.0.0.0' ",
        "processorArchitecture='*' publicKeyToken='6595b64144ccf1df' ",
        "language='*'/></dependentAssembly></dependency></assembly>"
        )
    tmp_name = None
    try:
        with tempfile.NamedTemporaryFile(delete=False) as f:
            tmp_name = f.name
            f.write("".join(manifest).encode("ascii"))

        # create activation context from manifest file
        actx = kernel.ACTCTX()
        actx.lpSource = tmp_name
        ctx = kernel.CreateActCtx(actx)
    finally:
        # delete temporary file
        if tmp_name is not None:
            pathlib.Path(tmp_name).unlink()

    # activate context, load libray and and release the context
    cookie = kernel.ActivateActCtx(ctx)
    comctl = _ct.windll.comctl32            # <- this calls LoadLibrary
    kernel.DeactivateActCtx(0, cookie)
    kernel.ReleaseActCtx(ctx)

    # verify DLL version
    class DLLVERSIONINFO(_ct.Structure):
        _fields_ = (
            ("cbSize", DWORD),
            ("dwMajorVersion", DWORD),
            ("dwMinorVersion", DWORD),
            ("dwBuildNumber", DWORD),
            ("dwPlatformID", DWORD),
            )
    dvi = DLLVERSIONINFO()
    dvi.cbSize = _ct.sizeof(dvi)
    _raise_on_hr(comctl.DllGetVersion(_ref(dvi)))
    if dvi.dwMajorVersion < 6:
        raise OSError("need at least version 6 of comctl32")

    # register window classes
    class INITCOMMONCONTROLSEX(_ct.Structure):
        _fields_ = (
            ("dwSize", DWORD),
            ("dwICC", DWORD),
            )
    icc = INITCOMMONCONTROLSEX()
    icc.dwSize = _ct.sizeof(icc)
    icc.dwICC = 0xffff
    _raise_if(not comctl.InitCommonControlsEx(_ref(icc)))

    return comctl

_ctl = _load_comctl()
del _load_comctl

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
    return S_OK if res is None else res

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

def tsk_dlg_centered(owner, title, instr, content, buttons, icon, inst=None):
    tdc = TASKDIALOGCONFIG()
    tdc.hwndParent = owner
    tdc.pszWindowTitle = title
    tdc.pszMainInstruction = instr
    tdc.pszContent = content
    tdc.dwCommonButtons = buttons
    tdc.pszMainIcon = icon
    tdc.hInstance = inst
    tdc.dwFlags = TDF_POSITION_RELATIVE_TO_WINDOW
    button_idx = INT()
    _raise_on_hr(_TaskDialogIndirect(_ref(tdc), _ref(button_idx), None, None))
    return button_idx.value

################################################################################
