################################################################################
#
# Copyright 2021-2026 Rocco Matano
# SPDX-License-Identifier: MIT
#
################################################################################

from types import SimpleNamespace as _namespace
import ctypes
from .wtypes import (
    BOOL,
    byte_buffer,
    DWORD,
    FILETIME,
    GUID,
    HANDLE,
    LONG,
    PBYTE,
    PDWORD,
    PGUID,
    POINTER,
    PSTR,
    PVOID,
    PWSTR,
    string_buffer,
    Struct,
    Union,
    )
from . import (
    ApiDll,
    CERT_NAME_SIMPLE_DISPLAY_TYPE,
    CERT_NAME_ISSUER_FLAG,
    CERT_SIGN_HASH_CNG_ALG_PROP_ID,
    CRYPT_E_SECURITY_SETTINGS,
    ERROR_SUCCESS,
    kernel,
    ref,
    raise_on_nullptr,
    raise_on_zero,
    TRUST_E_BAD_DIGEST,
    TRUST_E_EXPLICIT_DISTRUST,
    TRUST_E_NOSIGNATURE,
    TRUST_E_PROVIDER_UNKNOWN,
    TRUST_E_SUBJECT_FORM_UNKNOWN,
    TRUST_E_SUBJECT_NOT_TRUSTED,
    WSS_GET_SECONDARY_SIG_COUNT,
    WSS_VERIFY_SPECIFIC,
    WTD_CHOICE_FILE,
    WTD_STATEACTION_CLOSE,
    WTD_STATEACTION_VERIFY,
    WTD_UI_NONE,
    )

################################################################################

_wtr = ApiDll("wintrust.dll")
_cry = ApiDll("crypt32.dll")

class WINTRUST_FILE_INFO(Struct):
    _fields_ = (
        ("cbStruct", DWORD),
        ("pcwszFilePath", PWSTR),
        ("hFile", HANDLE),
        ("pgKnownSubject", PVOID),
        )
    def __init__(self):
        self.cbStruct = self._size_
PWINTRUST_FILE_INFO = POINTER(WINTRUST_FILE_INFO)

class WINTRUST_SIGNATURE_SETTINGS(Struct):
    _fields_ = (
        ("cbStruct", DWORD),
        ("dwIndex", DWORD),
        ("dwFlags", DWORD),
        ("cSecondarySigs", DWORD),
        ("dwVerifiedSigIndex", DWORD),
        ("pCryptoPolicy", PVOID),
        )
    def __init__(self):
        self.cbStruct = self._size_

PWINTRUST_SIGNATURE_SETTINGS = POINTER(WINTRUST_SIGNATURE_SETTINGS)

class WINTRUST_DATA_UNION(Union):
    _fields_ = (
        ("pFile", PVOID),
        ("pCatalog", PVOID),
        ("pBlob", PVOID),
        ("pSgnr", PVOID),
        ("pCert", PVOID),
        ("pDetachedSig", PVOID),
        )

class WINTRUST_DATA(Struct):
    _anonymous_ = ("anon",)
    _fields_ = (
        ("cbStruct", DWORD),
        ("pPolicyCallbackData", PVOID),
        ("pSIPClientData", PVOID),
        ("dwUIChoice", DWORD),
        ("fdwRevocationChecks", DWORD),
        ("dwUnionChoice", DWORD),
        ("anon", WINTRUST_DATA_UNION),
        ("dwStateAction", DWORD),
        ("hWVTStateData", HANDLE),
        ("pwszURLReference", PWSTR),
        ("dwProvFlags", DWORD),
        ("dwUIContext", DWORD),
        ("pSignatureSettings", PWINTRUST_SIGNATURE_SETTINGS),
        )
    def __init__(self):
        self.cbStruct = self._size_


WINTRUST_ACTION_GENERIC_VERIFY_V2 = GUID("00AAC56B-CD44-11d0-8CC2-00C04FC295EE")

################################################################################

_WinVerifyTrust = _wtr.fun_fact("WinVerifyTrust", (LONG, HANDLE, PGUID, PVOID))

def WinVerifyTrust(hwnd, action_id, wvt_data):
    return _WinVerifyTrust(hwnd, ref(action_id), ref(wvt_data))

################################################################################

class CRYPT_BLOB(Struct):
    _fields_ = (
        ("cbData", DWORD),
        ("pbData", PBYTE),
        )

class CRYPT_PROVIDER_SGNR(Struct):
    _fields_ = (
        ("cbStruct", DWORD),
        ("sftVerifyAsOf", FILETIME),
        ("csCertChain", DWORD),
        ("pasCertChain", PVOID),
        ("dwSignerType", DWORD),
        ("psSigner", PVOID),
        ("dwError", DWORD),
        ("csCounterSigners", DWORD),
        ("pasCounterSigners", PVOID),
        ("pChainContext", PVOID),
        )
PCRYPT_PROVIDER_SGNR = POINTER(CRYPT_PROVIDER_SGNR)

class CRYPT_ALGORITHM_IDENTIFIER(Struct):
    _fields_ = (
        ("pszObjId", PSTR),
        ("Parameters", CRYPT_BLOB),
        )

class CERT_PUBLIC_KEY_INFO(Struct):
    _fields_ = (
        ("Algorithm", CRYPT_ALGORITHM_IDENTIFIER),
        ("PublicKey", CRYPT_BLOB),
        )

class CERT_EXTENSION(Struct):
    _fields_ = (
        ("pszObjId", PSTR),
        ("fCritical", BOOL),
        ("Value", CRYPT_BLOB),
        )
PCERT_EXTENSION = POINTER(CERT_EXTENSION)

class CERT_INFO(Struct):
    _fields_ = (
        ("dwVersion", DWORD),
        ("SerialNumber", CRYPT_BLOB),
        ("SignatureAlgorithm", CRYPT_ALGORITHM_IDENTIFIER),
        ("Issuer", CRYPT_BLOB),
        ("NotBefore", FILETIME),
        ("NotAfter", FILETIME),
        ("Subject", CRYPT_BLOB),
        ("SubjectPublicKeyInfo", CERT_PUBLIC_KEY_INFO),
        ("IssuerUniqueId", CRYPT_BLOB),
        ("SubjectUniqueId", CRYPT_BLOB),
        ("cExtension", DWORD),
        ("rgExtension", PCERT_EXTENSION),
        )
PCERT_INFO = POINTER(CERT_INFO)

class CERT_CONTEXT(Struct):
    _fields_ = (
        ("dwCertEncodingType", DWORD),
        ("pbCertEncoded", PBYTE),
        ("cbCertEncoded", DWORD),
        ("pCertInfo", PCERT_INFO),
        ("hCertStore", PVOID),
        )
PCERT_CONTEXT = POINTER(CERT_CONTEXT)

class CRYPT_PROVIDER_CERT(Struct):
    _fields_ = (
        ("cbStruct", DWORD),
        ("pCert", PCERT_CONTEXT),
        ("fCommercial", BOOL),
        ("fTrustedRoot", BOOL),
        ("fSelfSigned", BOOL),
        ("fTestCert", BOOL),
        ("dwRevokedReason", DWORD),
        ("dwConfidence", DWORD),
        ("dwError", DWORD),
        ("pTrustListContext", PVOID),
        ("fTrustListSignerCert", BOOL),
        ("pCtlContext", PVOID),
        ("dwCtlError", DWORD),
        ("fIsCyclic", BOOL),
        ("pChainElement", PVOID),
        )
PCRYPT_PROVIDER_CERT = POINTER(CRYPT_PROVIDER_CERT)

################################################################################

_WTHelperGetProvCertFromChain = _wtr.fun_fact(
    "WTHelperGetProvCertFromChain",
    (PCRYPT_PROVIDER_CERT, PVOID, DWORD)
    )

def WTHelperGetProvCertFromChain(p_sgnr, idx=0):
    res = _WTHelperGetProvCertFromChain(p_sgnr, idx)
    raise_on_nullptr(res)
    return res

################################################################################

_WTHelperProvDataFromStateData = _wtr.fun_fact(
    "WTHelperProvDataFromStateData", (PVOID, HANDLE)
    )

def WTHelperProvDataFromStateData(hdl):
    res = _WTHelperProvDataFromStateData(hdl)
    raise_on_nullptr(res)
    return res

################################################################################

_WTHelperGetProvSignerFromChain = _wtr.fun_fact(
    "WTHelperGetProvSignerFromChain",
    (PCRYPT_PROVIDER_SGNR, PVOID, DWORD, BOOL, DWORD)
    )

def WTHelperGetProvSignerFromChain(p_pd, idx, fCounterSigner, cs_idx):
    res = _WTHelperGetProvSignerFromChain(p_pd, idx, fCounterSigner, cs_idx)
    raise_on_nullptr(res)
    return res

################################################################################

_CertGetNameString = _cry.fun_fact(
    "CertGetNameStringW",
    (DWORD, PVOID, DWORD, DWORD, PVOID, PWSTR, DWORD)
    )

def CertGetNameString(p_cert, typ, flags=0, p_typ_para=None):
    size = _CertGetNameString(p_cert, typ, flags, p_typ_para, None, 0)
    buf = string_buffer(size)
    size = _CertGetNameString(p_cert, typ, flags, p_typ_para, buf, size)
    raise_on_zero(size)
    return buf.value

################################################################################

_CertGetCertificateContextProperty = _cry.fun_fact(
    "CertGetCertificateContextProperty",
    (BOOL, PVOID, DWORD, PVOID, PDWORD)
    )

def CertGetCertificateContextProperty(p_cert, prop_id):
    size = DWORD(0)
    _CertGetCertificateContextProperty(p_cert, prop_id, None, ref(size))
    buf = byte_buffer(size.value)
    raise_on_zero(
        _CertGetCertificateContextProperty(p_cert, prop_id, buf, ref(size))
        )
    return buf[:size.value]

################################################################################

def get_cert_info(wvt_state_data):
    cpd = WTHelperProvDataFromStateData(wvt_state_data)
    p_sgnr = WTHelperGetProvSignerFromChain(cpd, 0, False, 0)
    p_ctxt = WTHelperGetProvCertFromChain(p_sgnr, 0).contents.pCert

    ft = kernel.FileTimeToLocalFileTime(p_sgnr.contents.sftVerifyAsOf)
    st = kernel.FileTimeToSystemTime(ft)
    dt = st.to_datetime(kernel.get_local_tzinfo())

    sdt = CERT_NAME_SIMPLE_DISPLAY_TYPE
    ifl = CERT_NAME_ISSUER_FLAG
    aid = CERT_SIGN_HASH_CNG_ALG_PROP_ID

    subject = CertGetNameString(p_ctxt, sdt)
    issuer = CertGetNameString(p_ctxt, sdt, ifl)
    alg_b = CertGetCertificateContextProperty(p_ctxt, aid)
    alg = ctypes.wstring_at(alg_b)

    sno = p_ctxt.contents.pCertInfo.contents.SerialNumber
    sn = bytes(reversed(sno.pbData[:sno.cbData]))

    return _namespace(
        subject_name=subject,
        issuer_name=issuer,
        algorithm=alg,
        timestamp=dt,
        serial_number=sn
        )

################################################################################

SIG_VERIFIED = "The file is signed and the signature was verified."
SIG_NOT_PRESENT = "No signature was present in the subject."
SIG_NOT_SUPPORTED = "The form is not supported or unknown."
SIG_UNKNOW_PROV = "Unknown trust provider."
SIG_UNKNOWN_ERR = "An unknown error occurred while verifying the signature"
SIG_EXPL_UNTRUST = "The certificate was explicitly marked as untrusted."
SIG_SUB_UNTRUST = "The subject is not trusted for the specified action."
SIG_SETTINGS = "The operation failed due to a local security setting."
SIG_BAD_DIGEST = "The digest did NOT match."

VERIFICATION_RESULT = {
    ERROR_SUCCESS: (SIG_VERIFIED, True),
    TRUST_E_BAD_DIGEST: (SIG_BAD_DIGEST, True),
    TRUST_E_EXPLICIT_DISTRUST: (SIG_EXPL_UNTRUST, True),
    TRUST_E_SUBJECT_NOT_TRUSTED: (SIG_SUB_UNTRUST, True),
    CRYPT_E_SECURITY_SETTINGS: (SIG_SETTINGS, False),
    TRUST_E_NOSIGNATURE: (SIG_NOT_PRESENT, False),
    TRUST_E_SUBJECT_FORM_UNKNOWN: (SIG_NOT_SUPPORTED, False),
    TRUST_E_PROVIDER_UNKNOWN: (SIG_UNKNOW_PROV, False),
    }

def verify_embedded_signature(file_path):
    wfi = WINTRUST_FILE_INFO()
    wfi.pcwszFilePath = file_path

    wss = WINTRUST_SIGNATURE_SETTINGS()
    wss.dwFlags = WSS_GET_SECONDARY_SIG_COUNT | WSS_VERIFY_SPECIFIC

    wtd = WINTRUST_DATA()
    wtd.dwUIChoice = WTD_UI_NONE
    wtd.dwUnionChoice = WTD_CHOICE_FILE
    wtd.dwStateAction = WTD_STATEACTION_VERIFY
    wtd.pFile = ctypes.addressof(wfi)
    wtd.pSignatureSettings = ctypes.pointer(wss)

    policy = WINTRUST_ACTION_GENERIC_VERIFY_V2
    status = WinVerifyTrust(None, policy, wtd)
    msg, get_certs = VERIFICATION_RESULT.get(status, (SIG_UNKNOWN_ERR, False))

    certs = []
    if get_certs and wtd.hWVTStateData:
        sig_cnt = wss.cSecondarySigs
        certs.append(get_cert_info(wtd.hWVTStateData))
        for idx in range(1, sig_cnt + 1):
            wtd.dwStateAction = WTD_STATEACTION_CLOSE
            WinVerifyTrust(None, policy, wtd)

            wtd.hWVTStateData = None
            wtd.dwStateAction = WTD_STATEACTION_VERIFY
            wtd.pSignatureSettings.contents.dwIndex = idx
            WinVerifyTrust(None, policy, wtd)
            if wtd.hWVTStateData:
                certs.append(get_cert_info(wtd.hWVTStateData))

    wtd.dwStateAction = WTD_STATEACTION_CLOSE
    WinVerifyTrust(None, policy, wtd)

    return status, msg, certs

################################################################################
