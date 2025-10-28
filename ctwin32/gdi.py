################################################################################
#
# Copyright 2021-2025 Rocco Matano
# SPDX-License-Identifier: MIT
#
################################################################################

import ctypes
from .wtypes import (
    BOOL,
    BYTE,
    byte_buffer,
    DWORD,
    HANDLE,
    INT,
    LONG,
    PINT,
    PLOGFONT,
    POINTER,
    PRECT,
    PVOID,
    PWSTR,
    UINT,
    WCHAR,
    )
from . import (
    ApiDll,
    ref,
    raise_if,
    raise_on_zero,
    ETO_OPAQUE,
    HGDI_ERROR,
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

class TEXTMETRIC(ctypes.Structure):
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
