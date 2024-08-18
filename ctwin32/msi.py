################################################################################
#
# Copyright 2021-2024 Rocco Matano
# SPDX-License-Identifier: MIT
#
################################################################################

import ctypes
from .wtypes import (
    byte_buffer,
    string_buffer,
    DWORD,
    PCHAR,
    PDWORD,
    POINTER,
    PWSTR,
    ScdToBeClosed,
    UINT,
    ULONG,
    )
from . import (
    ref,
    raise_on_err,
    suppress_winerr,
    fun_fact,
    ERROR_MORE_DATA,
    ERROR_NO_MORE_ITEMS
    )

_msi = ctypes.WinDLL("msi.dll", use_last_error=True)

MSIDBOPEN_READONLY     = PWSTR(0)
MSIDBOPEN_TRANSACT     = PWSTR(1)
MSIDBOPEN_DIRECT       = PWSTR(2)
MSIDBOPEN_CREATE       = PWSTR(3)
MSIDBOPEN_CREATEDIRECT = PWSTR(4)
MSIDBOPEN_PATCHFILE    = PWSTR(32 // 2)

BIN_NAME_IDX = 1  # field index of binary name
BIN_DATA_IDX = 2  # field index of binary data

################################################################################

_MsiCloseHandle = fun_fact(_msi.MsiCloseHandle, (UINT, ULONG))

def MsiCloseHandle(hdl):
    raise_on_err(_MsiCloseHandle(hdl))

################################################################################

class MSIHANDLE(ScdToBeClosed, ULONG, close_func=MsiCloseHandle, invalid=0):
    pass

PMSIHANDLE = POINTER(MSIHANDLE)

################################################################################

_MsiOpenDatabase = fun_fact(
    _msi.MsiOpenDatabaseW, (UINT, PWSTR, PWSTR, PMSIHANDLE)
    )

def MsiOpenDatabase(filename, persist):
    hdl = MSIHANDLE()
    raise_on_err(_MsiOpenDatabase(filename, persist, ref(hdl)))
    return hdl

################################################################################

_MsiDatabaseOpenView = fun_fact(
    _msi.MsiDatabaseOpenViewW, (UINT, MSIHANDLE, PWSTR, PMSIHANDLE)
    )

def MsiDatabaseOpenView(dbase, query):
    hdl = MSIHANDLE()
    raise_on_err(_MsiDatabaseOpenView(dbase, query, ref(hdl)))
    return hdl

################################################################################

_MsiViewExecute = fun_fact(
    _msi.MsiViewExecute, (UINT, MSIHANDLE, MSIHANDLE)
    )

def MsiViewExecute(view, record):
    raise_on_err(_MsiViewExecute(view, record))

################################################################################

_MsiViewFetch = fun_fact(
    _msi.MsiViewFetch, (UINT, MSIHANDLE, PMSIHANDLE)
    )

def MsiViewFetch(view):
    hdl = MSIHANDLE()
    raise_on_err(_MsiViewFetch(view, ref(hdl)))
    return hdl

################################################################################

def view_enum_records(view):
    with suppress_winerr(ERROR_NO_MORE_ITEMS):
        while True:
            with MsiViewFetch(view) as record:
                yield record

################################################################################

_MsiRecordGetFieldCount = fun_fact(
    _msi.MsiRecordGetFieldCount, (UINT, MSIHANDLE)
    )

def MsiRecordGetFieldCount(record):
    return _MsiRecordGetFieldCount(record)

################################################################################

_MsiRecordGetString = fun_fact(
    _msi.MsiRecordGetStringW, (
        UINT,
        MSIHANDLE,
        UINT,
        PWSTR,
        PDWORD
        )
    )

def MsiRecordGetString(record, field_idx):
    size = DWORD(512)
    err = ERROR_MORE_DATA
    while err == ERROR_MORE_DATA:
        buf = string_buffer(size.value)
        err = _MsiRecordGetString(record, field_idx, buf, ref(size))
    raise_on_err(err)
    return buf.value

################################################################################

_MsiRecordReadStream = fun_fact(
    _msi.MsiRecordReadStream, (
        UINT,
        MSIHANDLE,
        UINT,
        PCHAR,
        PDWORD
        )
    )

def MsiRecordReadStream(record, field_idx, size):
    res = byte_buffer(size)
    size = DWORD(size)
    raise_on_err(_MsiRecordReadStream(record, field_idx, res, ref(size)))
    return res.raw[:size.value]

################################################################################

def record_read_stream_all(record, field_idx):
    chunk_size = 64 * 1024
    chunks = []
    chunk = MsiRecordReadStream(record, field_idx, chunk_size)
    while chunk:
        chunks.append(chunk)
        chunk = MsiRecordReadStream(record, field_idx, chunk_size)
    return b"".join(chunks)

################################################################################
