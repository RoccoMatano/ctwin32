################################################################################
#
# Copyright 2021 Rocco Matano
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
import ctypes.wintypes as _wt

from . import _raise_on_err, _fun_fact, ERROR_MORE_DATA, ERROR_NO_MORE_ITEMS

_msi = _ct.windll.msi
_ref = _ct.byref

MSIDBOPEN_READONLY     = _ct.cast(_ct.c_void_p(0), _wt.LPWSTR)
MSIDBOPEN_TRANSACT     = _ct.cast(_ct.c_void_p(1), _wt.LPWSTR)
MSIDBOPEN_DIRECT       = _ct.cast(_ct.c_void_p(2), _wt.LPWSTR)
MSIDBOPEN_CREATE       = _ct.cast(_ct.c_void_p(3), _wt.LPWSTR)
MSIDBOPEN_CREATEDIRECT = _ct.cast(_ct.c_void_p(4), _wt.LPWSTR)
MSIDBOPEN_PATCHFILE    = _ct.cast(_ct.c_void_p(32 // 2), _wt.LPWSTR)

BIN_NAME_IDX = 1 # field index of binary name
BIN_DATA_IDX = 2 # field index of binary data

################################################################################

class MSIHANDLE(_wt.ULONG):

    ############################################################################

    def __init__(self, *args):
        if args:
            v = args[0]
            if (isinstance(v, _ct._SimpleCData)):
                self.value = v.value
            else:
                self.value = v
        else:
            self.value = 0

    ############################################################################

    # support for ctypes
    @classmethod
    def from_param(cls, obj):
        if isinstance(obj, cls):
            return obj
        elif obj is None:
            return _wt.ULONG(0)
        elif isinstance(obj, int):
            return _wt.ULONG(obj)
        else:
            msg = (
                "Don't know how to convert from " +
                f"{type(obj).__name__} to {cls.__name__}"
                )
            raise TypeError(msg)

    ############################################################################

    def close(self):
        if self.value:
            MsiCloseHandle(self.value)
            self.value = 0

    Close = close

    ############################################################################

    def __enter__(self):
        return self

    ############################################################################

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()

    ############################################################################

    def __int__(self):
        return self.value

PMSIHANDLE = _ct.POINTER(MSIHANDLE)

################################################################################

_MsiCloseHandle = _fun_fact(_msi.MsiCloseHandle, (_wt.UINT, MSIHANDLE))

def MsiCloseHandle(hdl):
    _raise_on_err(_MsiCloseHandle(hdl))

################################################################################

_MsiOpenDatabase = _fun_fact(
    _msi.MsiOpenDatabaseW, (_wt.UINT, _wt.LPWSTR, _wt.LPWSTR, PMSIHANDLE)
    )

def MsiOpenDatabase(filename, persist):
    hdl = MSIHANDLE()
    _raise_on_err(_MsiOpenDatabase(filename, persist, _ref(hdl)))
    return hdl

################################################################################

_MsiDatabaseOpenView = _fun_fact(
    _msi.MsiDatabaseOpenViewW, (_wt.UINT, MSIHANDLE, _wt.LPWSTR, PMSIHANDLE)
    )

def MsiDatabaseOpenView(dbase, query):
    hdl = MSIHANDLE()
    _raise_on_err(_MsiDatabaseOpenView(dbase, query, _ref(hdl)))
    return hdl

################################################################################

_MsiViewExecute = _fun_fact(
    _msi.MsiViewExecute, (_wt.UINT, MSIHANDLE, MSIHANDLE)
    )

def MsiViewExecute(view, record):
    _raise_on_err(_MsiViewExecute(view, record))

################################################################################

_MsiViewFetch = _fun_fact(
    _msi.MsiViewFetch, (_wt.UINT, MSIHANDLE, PMSIHANDLE)
    )

def MsiViewFetch(view):
    hdl = MSIHANDLE()
    _raise_on_err(_MsiViewFetch(view, _ref(hdl)))
    return hdl

################################################################################

def view_enum_records(view):
    while True:
        try:
            record = MsiViewFetch(view)
        except OSError as e:
            if e.winerror == ERROR_NO_MORE_ITEMS:
                break
            else:
                raise
        with record:
            yield record

################################################################################

_MsiRecordGetString = _fun_fact(
    _msi.MsiRecordGetStringW, (
        _wt.UINT,
        MSIHANDLE,
        _wt.UINT,
        _wt.LPWSTR,
        _wt.PDWORD
        )
    )

def MsiRecordGetString(record, field_idx):
    size = _wt.DWORD(512)
    err = ERROR_MORE_DATA
    while err == ERROR_MORE_DATA:
        buf = _ct.create_unicode_buffer(size.value)
        err = _MsiRecordGetString(record, field_idx, buf, _ref(size))
    _raise_on_err(err)
    return buf.value

################################################################################

_MsiRecordReadStream = _fun_fact(
    _msi.MsiRecordReadStream, (
        _wt.UINT,
        MSIHANDLE,
        _wt.UINT,
        _wt.PCHAR,
        _wt.PDWORD
        )
    )

def MsiRecordReadStream(record, field_idx, size):
    res = _ct.create_string_buffer(size)
    size = _wt.DWORD(size)
    _raise_on_err(_MsiRecordReadStream(record, field_idx, res, _ref(size)))
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
