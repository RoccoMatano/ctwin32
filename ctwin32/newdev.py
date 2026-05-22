################################################################################
#
# Copyright 2021-2026 Rocco Matano
# SPDX-License-Identifier: MIT
#
################################################################################

from .wtypes import BOOL, DWORD, HWND, PBOOL
from .setupapi import HDEVINFO, PSP_DEVINFO_DATA, PSP_DRVINFO_DATA
from . import ApiDll, ref, raise_on_zero

################################################################################

_ndv = ApiDll("newdev.dll")

_DiInstallDevice = _ndv.fun_fact(
    "DiInstallDevice",
    (BOOL, HWND, HDEVINFO, PSP_DEVINFO_DATA, PSP_DRVINFO_DATA, DWORD, PBOOL)
    )

def DiInstallDevice(hwnd, info_set, deinda, drinda, flags):
    need_boot = BOOL()
    raise_on_zero(
        _DiInstallDevice(hwnd, info_set, deinda, drinda, flags, ref(need_boot))
        )
    return need_boot.value

################################################################################
