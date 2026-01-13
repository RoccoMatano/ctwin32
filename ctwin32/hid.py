################################################################################
#
# Copyright 2021-2026 Rocco Matano
# SPDX-License-Identifier: MIT
#
################################################################################

import ctypes
from .wtypes import (
    BOOLEAN,
    Struct,
    DWORD,
    GUID,
    HANDLE,
    NTSTATUS,
    POINTER,
    PPVOID,
    PVOID,
    WinError,
    WORD,
    )
from . import (
    ApiDll,
    ERROR_INVALID_DATA,
    setupapi,
    ref,
    raise_on_zero,
    ns_from_struct,
    )

_hid = ApiDll("hid.dll")

################################################################################

HID_MAX_STR_LEN = 4093
HID_INTERFACE = GUID("4d1e55b2-f16f-11cf-88cb-001111000030")

class HIDD_ATTRIBUTES(Struct):
    _fields_ = [
        ("Size", DWORD),
        ("VendorID", WORD),
        ("ProductID", WORD),
        ("VersionNumber", WORD),
        ]
PHIDD_ATTRIBUTES = POINTER(HIDD_ATTRIBUTES)

class HIDP_CAPS(Struct):
    _fields_ = [
        ("Usage", WORD),
        ("UsagePage", WORD),
        ("InputReportByteLength", WORD),
        ("OutputReportByteLength", WORD),
        ("FeatureReportByteLength", WORD),
        ("Reserved", WORD * 17),
        ("NumberLinkCollectionNodes", WORD),
        ("NumberInputButtonCaps", WORD),
        ("NumberInputValueCaps", WORD),
        ("NumberInputDataIndices", WORD),
        ("NumberOutputButtonCaps", WORD),
        ("NumberOutputValueCaps", WORD),
        ("NumberOutputDataIndices", WORD),
        ("NumberFeatureButtonCaps", WORD),
        ("NumberFeatureValueCaps", WORD),
        ("NumberFeatureDataIndices", WORD),
        ]
PHIDP_CAPS = POINTER(HIDP_CAPS)

################################################################################

FACILITY_HID_ERROR_CODE = 0x11

def _hidp_error_code(severity, code):
    return NTSTATUS(
        (severity << 28) | (FACILITY_HID_ERROR_CODE << 16) | code
        ).value

HIDP_STATUS_SUCCESS                 = _hidp_error_code(0x0,0)
HIDP_STATUS_NULL                    = _hidp_error_code(0x8,1)
HIDP_STATUS_INVALID_PREPARSED_DATA  = _hidp_error_code(0xc,1)
HIDP_STATUS_INVALID_REPORT_TYPE     = _hidp_error_code(0xc,2)
HIDP_STATUS_INVALID_REPORT_LENGTH   = _hidp_error_code(0xc,3)
HIDP_STATUS_USAGE_NOT_FOUND         = _hidp_error_code(0xc,4)
HIDP_STATUS_VALUE_OUT_OF_RANGE      = _hidp_error_code(0xc,5)
HIDP_STATUS_BAD_LOG_PHY_VALUES      = _hidp_error_code(0xc,6)
HIDP_STATUS_BUFFER_TOO_SMALL        = _hidp_error_code(0xc,7)
HIDP_STATUS_INTERNAL_ERROR          = _hidp_error_code(0xc,8)
HIDP_STATUS_I8042_TRANS_UNKNOWN     = _hidp_error_code(0xc,9)
HIDP_STATUS_INCOMPATIBLE_REPORT_ID  = _hidp_error_code(0xc,0xa)
HIDP_STATUS_NOT_VALUE_ARRAY         = _hidp_error_code(0xc,0xb)
HIDP_STATUS_IS_VALUE_ARRAY          = _hidp_error_code(0xc,0xc)
HIDP_STATUS_DATA_INDEX_NOT_FOUND    = _hidp_error_code(0xc,0xd)
HIDP_STATUS_DATA_INDEX_OUT_OF_RANGE = _hidp_error_code(0xc,0xe)
HIDP_STATUS_BUTTON_NOT_PRESSED      = _hidp_error_code(0xc,0xf)
HIDP_STATUS_REPORT_DOES_NOT_EXIST   = _hidp_error_code(0xc,0x10)
HIDP_STATUS_NOT_IMPLEMENTED         = _hidp_error_code(0xc,0x20)

################################################################################

_HidD_GetAttributes = _hid.fun_fact(
    "HidD_GetAttributes",
    (BOOLEAN, HANDLE, PHIDD_ATTRIBUTES)
    )

def HidD_GetAttributes(hdl):
    attr = HIDD_ATTRIBUTES()
    raise_on_zero(_HidD_GetAttributes(hdl, ref(attr)))
    return ns_from_struct(attr)

################################################################################

_HidD_GetPreparsedData = _hid.fun_fact(
    "HidD_GetPreparsedData",
    (BOOLEAN, HANDLE, PPVOID)
    )

def HidD_GetPreparsedData(hdl):
    ptr = PVOID()
    raise_on_zero(_HidD_GetPreparsedData(hdl, ref(ptr)))
    return ptr.value

################################################################################

_HidD_FreePreparsedData = _hid.fun_fact(
    "HidD_FreePreparsedData",
    (BOOLEAN, PVOID)
    )

def HidD_FreePreparsedData(ptr):
    raise_on_zero(_HidD_FreePreparsedData(ptr))

################################################################################

_HidP_GetCaps = _hid.fun_fact("HidP_GetCaps", (NTSTATUS, PVOID, PHIDP_CAPS)
    )

def HidP_GetCaps(preparsed_data_ptr):
    caps = HIDP_CAPS()
    status = _HidP_GetCaps(preparsed_data_ptr, ref(caps))
    if status != HIDP_STATUS_SUCCESS:
        raise WinError(ERROR_INVALID_DATA)
    return ns_from_struct(caps)

################################################################################

def hid_get_caps(hdl):
    ppd = HidD_GetPreparsedData(hdl)
    try:
        return HidP_GetCaps(ppd)
    finally:
        HidD_FreePreparsedData(ppd)

################################################################################

_HidD_GetSerialNumberString = _hid.fun_fact(
    "HidD_GetSerialNumberString",
    (BOOLEAN, HANDLE, PVOID, DWORD)
    )
_HidD_GetManufacturerString = _hid.fun_fact(
    "HidD_GetManufacturerString",
    (BOOLEAN, HANDLE, PVOID, DWORD)
    )
_HidD_GetProductString = _hid.fun_fact(
    "HidD_GetProductString",
    (BOOLEAN, HANDLE, PVOID, DWORD)
    )

def _get_hid_str(hdl, func):
    buf = ctypes.create_unicode_buffer(HID_MAX_STR_LEN)
    raise_on_zero(func(hdl, buf, HID_MAX_STR_LEN))
    return buf.value

################################################################################

def HidD_GetSerialNumberString(hdl):
    return _get_hid_str(hdl, _HidD_GetSerialNumberString)

################################################################################

def HidD_GetManufacturerString(hdl):
    return _get_hid_str(hdl, _HidD_GetManufacturerString)

################################################################################

def HidD_GetProductString(hdl):
    return _get_hid_str(hdl, _HidD_GetProductString)

################################################################################

_HidD_SetNumInputBuffers = _hid.fun_fact(
    "HidD_SetNumInputBuffers",
    (BOOLEAN, HANDLE, DWORD)
    )

def HidD_SetNumInputBuffers(hdl, num):
    raise_on_zero(_HidD_SetNumInputBuffers(hdl, num))

################################################################################

def iface_no_from_path(path):
    # interface number can be parsed out of the path if a device has multiple
    # interfaces. if it's not in the path, it's set to -1.
    idx = path.find("&mi_")
    if idx >= 0:
        try:
            return int(path[idx + 4 : idx + 6], 16)
        except ValueError:
            return None
    return None

################################################################################

def enum_hid_devs():
    for iset, did in setupapi.enum_dev_interfaces(HID_INTERFACE):
        yield setupapi.SetupDiGetDeviceInterfaceDetail(iset, did)[0]

################################################################################
