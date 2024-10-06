################################################################################
#
# Copyright 2021-2024 Rocco Matano
# SPDX-License-Identifier: MIT
#
################################################################################

import tempfile
import pathlib

import ctypes
from .wtypes import (
    BOOL,
    CallbackContext,
    CallbackContextPtr,
    DWORD,
    HINSTANCE,
    HRESULT,
    LONG,
    LPARAM,
    HANDLE,
    HWND,
    INT,
    PBOOL,
    PINT,
    POINTER,
    PWSTR,
    UINT,
    WPARAM,
    )
from . import (
    ref,
    kernel,
    raise_on_zero,
    raise_on_hr,
    fun_fact,
    S_OK,
    TDF_POSITION_RELATIVE_TO_WINDOW,
    )

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

    # simply doing the following would lead to a sharing violation :-(
    #
    # with tempfile.NamedTemporaryFile() as f:
    #     tmp_name = f.name
    #     f.write("".join(manifest).encode("ascii"))
    #     actx.lpSource = tmp_name
    #     ctx = kernel.CreateActCtx(actx) # <- sharing violation here
    #
    # so it gets a little more complicated...

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
    kernel.ActivateActCtx(ctx)

    # this calls LoadLibrary
    comctl = ctypes.WinDLL("comctl32.dll", use_last_error=True)

    # Do NOT deactivate the context! Just decrement its ref-count by
    # releasing it.
    kernel.ReleaseActCtx(ctx)

    # verify DLL version
    class DLLVERSIONINFO(ctypes.Structure):
        _fields_ = (
            ("cbSize", DWORD),
            ("dwMajorVersion", DWORD),
            ("dwMinorVersion", DWORD),
            ("dwBuildNumber", DWORD),
            ("dwPlatformID", DWORD),
            )
    dvi = DLLVERSIONINFO()
    dvi.cbSize = ctypes.sizeof(dvi)
    raise_on_hr(comctl.DllGetVersion(ref(dvi)))
    if dvi.dwMajorVersion < 6:
        raise OSError("need at least version 6 of comctl32")

    # register window classes
    class INITCOMMONCONTROLSEX(ctypes.Structure):
        _fields_ = (
            ("dwSize", DWORD),
            ("dwICC", DWORD),
            )
    icc = INITCOMMONCONTROLSEX()
    icc.dwSize = ctypes.sizeof(icc)
    icc.dwICC = 0xffff
    raise_on_zero(comctl.InitCommonControlsEx(ref(icc)))

    return comctl

_ctl = _load_comctl()
del _load_comctl

################################################################################

_TaskDialog = fun_fact(
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
    raise_on_hr(
        _TaskDialog(
            owner,
            inst,
            title,
            main_instr,
            content,
            buttons,
            icon,
            ref(res)
            )
        )
    return res.value

################################################################################

_TaskDialogCallback = ctypes.WINFUNCTYPE(
    LONG,
    HWND,
    UINT,
    WPARAM,
    LPARAM,
    CallbackContextPtr
    )

@_TaskDialogCallback
def _TskDlgCb(hwnd, msg, wp, lp, ctxt):
    # cannot propagate exceptions from callback
    with kernel.terminate_on_exception():
        cbc = ctxt.contents
        res = cbc.callback(hwnd, msg, wp, lp, cbc.context)
        # return S_OK if the callback fails to return a value
        return S_OK if res is None else res

################################################################################

# ALL TASKDIALOG STRUCTURES NEED AN ALIGNMENT OF 1 (_pack_ = 1)!!!

class TASKDIALOG_BUTTON(ctypes.Structure):
    _pack_ = 1
    _fields_ = (
        ("nButtonID", INT),
        ("pszButtonText", PWSTR),
        )

PTASKDIALOG_BUTTON = POINTER(TASKDIALOG_BUTTON)

class _TD_MAIN_ICON(ctypes.Union):
    _pack_ = 1
    _fields_ = (("hMainIcon", HANDLE), ("pszMainIcon", PWSTR))

class _TD_FOOTER_ICON(ctypes.Union):
    _pack_ = 1
    _fields_ = (("hFooterIcon", HANDLE), ("pszFooterIcon", PWSTR))

class TASKDIALOGCONFIG(ctypes.Structure):
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
        self.cbSize = ctypes.sizeof(self)

PTASKDIALOGCONFIG = POINTER(TASKDIALOGCONFIG)

################################################################################

_TaskDialogIndirect = fun_fact(
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
    raise_on_hr(
        _TaskDialogIndirect(
            ref(tsk_dlg_cfg),
            ref(button_idx),
            ref(radio_idx),
            ref(verified)
            )
        )
    return button_idx.value, radio_idx.value, bool(verified.value)

################################################################################

def tsk_dlg_callback(tsk_dlg_cfg, callback, context=None):
    ctxt = CallbackContext(callback, context)
    tsk_dlg_cfg.pfCallback = _TskDlgCb
    tsk_dlg_cfg.lpCallbackData = ctypes.pointer(ctxt)
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
    raise_on_hr(_TaskDialogIndirect(ref(tdc), ref(button_idx), None, None))
    return button_idx.value

################################################################################
