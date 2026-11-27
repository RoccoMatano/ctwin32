################################################################################
#
# Copyright 2021-2026 Rocco Matano
# SPDX-License-Identifier: MIT
#
################################################################################

import ctypes
from .wtypes import (
    BOOL,
    BYTE,
    byte_buffer,
    CallbackContext,
    CallbackContextPtr,
    DWORD,
    HANDLE,
    INT,
    LOGFONT,
    LONG,
    PINT,
    PLOGFONT,
    POINTER,
    PRECT,
    PVOID,
    PWSTR,
    Struct,
    UINT,
    WCHAR,
    )
from . import (
    ApiDll,
    DEFAULT_CHARSET,
    defer_exception,
    ETO_OPAQUE,
    HGDI_ERROR,
    ref,
    raise_if,
    raise_on_zero,
    user,
    )

_gdi = ApiDll("gdi32.dll")

################################################################################

GetDeviceCaps = _gdi.fun_fact("GetDeviceCaps", (INT, HANDLE, INT))

################################################################################

_CreateFontIndirect = _gdi.fun_fact("CreateFontIndirectW", (HANDLE, PLOGFONT))

def CreateFontIndirect(lf):
    res = _CreateFontIndirect(ref(lf))
    raise_on_zero(res)
    return res

################################################################################

_SelectObject = _gdi.fun_fact("SelectObject", (HANDLE, HANDLE, HANDLE))

def SelectObject(hdc, hobj):
    hprev = _SelectObject(hdc, hobj)
    raise_if(not hprev or hprev == HGDI_ERROR)
    return hprev

################################################################################

_DeleteObject = _gdi.fun_fact("DeleteObject", (BOOL, HANDLE))

def DeleteObject(hobj):
    raise_on_zero(_DeleteObject(hobj))

################################################################################

class TEXTMETRIC(Struct):
    _fields_ = (
        ("tmHeight", LONG),
        ("tmAscent", LONG),
        ("tmDescent", LONG),
        ("tmInternalLeading", LONG),
        ("tmExternalLeading", LONG),
        ("tmAveCharWidth", LONG),
        ("tmMaxCharWidth", LONG),
        ("tmWeight", LONG),
        ("tmOverhang", LONG),
        ("tmDigitizedAspectX", LONG),
        ("tmDigitizedAspectY", LONG),
        ("tmFirstChar", WCHAR),
        ("tmLastChar", WCHAR),
        ("tmDefaultChar", WCHAR),
        ("tmBreakChar", WCHAR),
        ("tmItalic", BYTE),
        ("tmUnderlined", BYTE),
        ("tmStruckOut", BYTE),
        ("tmPitchAndFamily", BYTE),
        ("tmCharSet", BYTE),
        )
PTEXTMETRIC = POINTER(TEXTMETRIC)

################################################################################

_GetTextMetrics = _gdi.fun_fact("GetTextMetricsW", (BOOL, HANDLE, PTEXTMETRIC))

def GetTextMetrics(hdc):
    tm = TEXTMETRIC()
    raise_on_zero(_GetTextMetrics(hdc, ref(tm)))
    return tm

################################################################################

_GetStockObject = _gdi.fun_fact("GetStockObject", (HANDLE, INT))

def GetStockObject(idx):
    obj = _GetStockObject(idx)
    raise_on_zero(obj)
    return obj

################################################################################

_SetBkMode = _gdi.fun_fact("SetBkMode", (INT, HANDLE, INT))

def SetBkMode(hdc, mode):
    previous = _SetBkMode(hdc, mode)
    raise_on_zero(previous)
    return previous

################################################################################

_SetBkColor = _gdi.fun_fact("SetBkColor", (DWORD, HANDLE, DWORD))

def SetBkColor(hdc, colorref):
    previous = _SetBkColor(hdc, colorref)
    raise_on_zero(previous)
    return previous

################################################################################

_TextOut = _gdi.fun_fact("TextOutW", (BOOL, HANDLE, INT, INT, PWSTR, INT))

def TextOut(hdc, x, y, text):
    raise_on_zero(_TextOut(hdc, x, y, text, len(text)))

################################################################################

_ExtTextOut = _gdi.fun_fact(
    "ExtTextOutW",
    (BOOL, HANDLE, INT, INT, UINT, PRECT, PWSTR, UINT, PINT)
    )

def ExtTextOut(hdc, x, y, opt, rect, text, pDX=None):
    span = len(text) if text else 0
    raise_on_zero(
        _ExtTextOut(hdc, x, y, opt, ref(rect), text, span, pDX)
        )

################################################################################

def fill_solid_rect(hdc, rect, colorref):
    oldclr = SetBkColor(hdc, colorref)
    ExtTextOut(hdc, 0, 0, ETO_OPAQUE, rect, None, None)
    SetBkColor(hdc, oldclr)

################################################################################

_GetObject = _gdi.fun_fact("GetObjectW", (INT, HANDLE, INT, PVOID))

def GetObject(hdl):
    raise_on_zero(size := _GetObject(hdl, 0, None))
    buf = byte_buffer(size)
    raise_on_zero(_GetObject(hdl, size, buf))
    return buf

################################################################################

_EnumFontFamExProc = ctypes.WINFUNCTYPE(
    INT,
    PLOGFONT,
    PTEXTMETRIC,
    DWORD,
    CallbackContextPtr,
    )

@_EnumFontFamExProc
def _EnumFontFamCb(lf, tm, ft, ctxt):
    # cannot propagate exceptions from callback
    try:
        lf = LOGFONT.from_buffer_copy(lf.contents)
        tm = TEXTMETRIC.from_buffer_copy(tm.contents)
        cbc = ctxt.contents
        res = cbc.callback(lf, tm, ft, cbc.context)
    except BaseException as e: # noqa: BLE001
        defer_exception(e)
        res = False
    # keep on enumerating if the callback fails to return a value
    return res if res is not None else True

################################################################################

_EnumFontFamiliesEx = _gdi.fun_fact(
    "EnumFontFamiliesExW",
    (INT, HANDLE, PLOGFONT, _EnumFontFamExProc, CallbackContextPtr, DWORD)
    )

def EnumFontFamiliesEx(hdc, lf, callback, context):
    cbc = CallbackContext(callback, context)
    relhdc = None
    if hdc is None:
        hdc = relhdc = user.GetDC(None)
    try:
        _EnumFontFamiliesEx(hdc, ref(lf), _EnumFontFamCb, ref(cbc), 0)
    finally:
        if relhdc:
            user.ReleaseDC(None, relhdc)

################################################################################

def get_font_family_names(hdc=None):
    fonts = set()
    def accu(lf, tm, ft, fonts):
        fonts.add(lf.lfFaceName)
        return True

    lf = LOGFONT(lfCharSet=DEFAULT_CHARSET)
    EnumFontFamiliesEx(hdc, lf, accu, fonts)
    return sorted(fonts)

################################################################################

def is_font_available(facename, hdc=None):
    is_available = []
    def search(lf, tm, ft, is_available):
        is_available.append(1)
        return False

    lf = LOGFONT(lfCharSet=DEFAULT_CHARSET, lfFaceName=facename)
    EnumFontFamiliesEx(hdc, lf, search, is_available)
    return bool(is_available)

################################################################################
