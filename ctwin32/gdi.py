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

from .wtypes import *
from . import (
    ctypes,
    ref,
    raise_if,
    fun_fact,
    HGDI_ERROR,
    )

_gdi = ctypes.windll.gdi32

################################################################################

GetDeviceCaps = fun_fact(_gdi.GetDeviceCaps, (INT, HANDLE, INT))

################################################################################

class LOGFONT(ctypes.Structure):
    _fields_ = (
        ("lfHeight", LONG),
        ("lfWidth", LONG),
        ("lfEscapement", LONG),
        ("lfOrientation", LONG),
        ("lfWeight", LONG),
        ("lfItalic", BYTE),
        ("lfUnderline", BYTE),
        ("lfStrikeOut", BYTE),
        ("lfCharSet", BYTE),
        ("lfOutPrecision", BYTE),
        ("lfClipPrecision", BYTE),
        ("lfQuality", BYTE),
        ("lfPitchAndFamily", BYTE),
        ("lfFaceName", WCHAR * 32),
        )

PLOGFONT = ctypes.POINTER(LOGFONT)

################################################################################

_CreateFontIndirect = fun_fact(_gdi.CreateFontIndirectW, (HANDLE, PLOGFONT))

def CreateFontIndirect(lf):
    res = _CreateFontIndirect(ref(lf))
    raise_if(not res)
    return res

################################################################################

_SelectObject = fun_fact(_gdi.SelectObject, (HANDLE, HANDLE, HANDLE))

def SelectObject(hdc, hobj):
    hprev = _SelectObject(hdc, hobj)
    raise_if(not hprev or hprev == HGDI_ERROR)
    return hprev

################################################################################

_DeleteObject = fun_fact(_gdi.DeleteObject, (BOOL, HANDLE))

def DeleteObject(hobj):
    raise_if(not _DeleteObject(hobj))

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
PTEXTMETRIC = ctypes.POINTER(TEXTMETRIC)

################################################################################

_GetTextMetrics = fun_fact(_gdi.GetTextMetricsW, (BOOL, HANDLE, PTEXTMETRIC))

def GetTextMetrics(hdc):
    tm = TEXTMETRIC()
    raise_if(not _GetTextMetrics(hdc, ref(tm)))
    return tm

################################################################################

_GetStockObject = fun_fact(_gdi.GetStockObject, (HANDLE, INT))

def GetStockObject(idx):
    obj = _GetStockObject(idx)
    raise_if(obj == 0)
    return obj

################################################################################

_SetBkMode = fun_fact(_gdi.SetBkMode, (INT, HANDLE, INT))

def SetBkMode(hdc, mode):
    previous = _SetBkMode(hdc, mode)
    raise_if(not previous)
    return previous

################################################################################

_TextOut = fun_fact(_gdi.TextOutW, (BOOL, HANDLE, INT, INT, PWSTR, INT))

def TextOut(hdc, x, y, text):
    raise_if(not _TextOut(hdc, x, y, text, len(text)))

################################################################################
