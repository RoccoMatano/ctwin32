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
    ENDIANNESS,
    HANDLE,
    NTSTATUS,
    PCHAR,
    PHANDLE,
    PULONG,
    PVOID,
    PWSTR,
    ScdToBeClosed,
    ULONG,
    )
from . import ref, fun_fact
from .ntdll import raise_failed_status, STATUS_INVALID_SIGNATURE

_bcr = ctypes.WinDLL("bcrypt.dll", use_last_error=True)

################################################################################

BCRYPT_OBJECT_LENGTH        = "ObjectLength"
BCRYPT_ALGORITHM_NAME       = "AlgorithmName"
BCRYPT_PROVIDER_HANDLE      = "ProviderHandle"
BCRYPT_CHAINING_MODE        = "ChainingMode"
BCRYPT_BLOCK_LENGTH         = "BlockLength"
BCRYPT_KEY_LENGTH           = "KeyLength"
BCRYPT_KEY_OBJECT_LENGTH    = "KeyObjectLength"
BCRYPT_KEY_STRENGTH         = "KeyStrength"
BCRYPT_KEY_LENGTHS          = "KeyLengths"
BCRYPT_BLOCK_SIZE_LIST      = "BlockSizeList"
BCRYPT_EFFECTIVE_KEY_LENGTH = "EffectiveKeyLength"
BCRYPT_HASH_LENGTH          = "HashDigestLength"
BCRYPT_HASH_OID_LIST        = "HashOIDList"
BCRYPT_PADDING_SCHEMES      = "PaddingSchemes"
BCRYPT_SIGNATURE_LENGTH     = "SignatureLength"
BCRYPT_HASH_BLOCK_LENGTH    = "HashBlockLength"
BCRYPT_AUTH_TAG_LENGTH      = "AuthTagLength"
BCRYPT_PRIMITIVE_TYPE       = "PrimitiveType"
BCRYPT_IS_KEYED_HASH        = "IsKeyedHash"
BCRYPT_IS_REUSABLE_HASH     = "IsReusableHash"
BCRYPT_MESSAGE_BLOCK_LENGTH = "MessageBlockLength"
BCRYPT_PUBLIC_KEY_LENGTH    = "PublicKeyLength"

BCRYPT_INITIALIZATION_VECTOR = "IV"

BCRYPT_CHAIN_MODE_NA  = "ChainingModeN/A"
BCRYPT_CHAIN_MODE_CBC = "ChainingModeCBC"
BCRYPT_CHAIN_MODE_ECB = "ChainingModeECB"
BCRYPT_CHAIN_MODE_CFB = "ChainingModeCFB"
BCRYPT_CHAIN_MODE_CCM = "ChainingModeCCM"
BCRYPT_CHAIN_MODE_GCM = "ChainingModeGCM"

BCRYPT_PUBLIC_KEY_BLOB     = "PUBLICBLOB"
BCRYPT_PRIVATE_KEY_BLOB    = "PRIVATEBLOB"
BCRYPT_ECCPUBLIC_BLOB      = "ECCPUBLICBLOB"
BCRYPT_ECCPRIVATE_BLOB     = "ECCPRIVATEBLOB"
BCRYPT_RSAPUBLIC_BLOB      = "RSAPUBLICBLOB"
BCRYPT_RSAPRIVATE_BLOB     = "RSAPRIVATEBLOB"
LEGACY_RSAPUBLIC_BLOB      = "CAPIPUBLICBLOB"
LEGACY_RSAPRIVATE_BLOB     = "CAPIPRIVATEBLOB"
BCRYPT_ECCFULLPUBLIC_BLOB  = "ECCFULLPUBLICBLOB"
BCRYPT_ECCFULLPRIVATE_BLOB = "ECCFULLPRIVATEBLOB"
SSL_ECCPUBLIC_BLOB         = "SSLECCPUBLICBLOB"
BCRYPT_OPAQUE_KEY_BLOB     = "OpaqueKeyBlob"
BCRYPT_KEY_DATA_BLOB       = "KeyDataBlob"
BCRYPT_AES_WRAP_KEY_BLOB   = "Rfc3565KeyWrapBlob"

BCRYPT_RSA_ALGORITHM               = "RSA"
BCRYPT_RSA_SIGN_ALGORITHM          = "RSA_SIGN"
BCRYPT_DH_ALGORITHM                = "DH"
BCRYPT_DSA_ALGORITHM               = "DSA"
BCRYPT_RC2_ALGORITHM               = "RC2"
BCRYPT_RC4_ALGORITHM               = "RC4"
BCRYPT_AES_ALGORITHM               = "AES"
BCRYPT_DES_ALGORITHM               = "DES"
BCRYPT_DESX_ALGORITHM              = "DESX"
BCRYPT_3DES_ALGORITHM              = "3DES"
BCRYPT_3DES_112_ALGORITHM          = "3DES_112"
BCRYPT_MD2_ALGORITHM               = "MD2"
BCRYPT_MD4_ALGORITHM               = "MD4"
BCRYPT_MD5_ALGORITHM               = "MD5"
BCRYPT_SHA1_ALGORITHM              = "SHA1"
BCRYPT_SHA256_ALGORITHM            = "SHA256"
BCRYPT_SHA384_ALGORITHM            = "SHA384"
BCRYPT_SHA512_ALGORITHM            = "SHA512"
BCRYPT_AES_GMAC_ALGORITHM          = "AES-GMAC"
BCRYPT_AES_CMAC_ALGORITHM          = "AES-CMAC"
BCRYPT_ECDSA_P256_ALGORITHM        = "ECDSA_P256"
BCRYPT_ECDSA_P384_ALGORITHM        = "ECDSA_P384"
BCRYPT_ECDSA_P521_ALGORITHM        = "ECDSA_P521"
BCRYPT_ECDH_P256_ALGORITHM         = "ECDH_P256"
BCRYPT_ECDH_P384_ALGORITHM         = "ECDH_P384"
BCRYPT_ECDH_P521_ALGORITHM         = "ECDH_P521"
BCRYPT_RNG_ALGORITHM               = "RNG"
BCRYPT_RNG_FIPS186_DSA_ALGORITHM   = "FIPS186DSARNG"
BCRYPT_RNG_DUAL_EC_ALGORITHM       = "DUALECRNG"
BCRYPT_SP800108_CTR_HMAC_ALGORITHM = "SP800_108_CTR_HMAC"
BCRYPT_SP80056A_CONCAT_ALGORITHM   = "SP800_56A_CONCAT"
BCRYPT_PBKDF2_ALGORITHM            = "PBKDF2"
BCRYPT_CAPI_KDF_ALGORITHM          = "CAPI_KDF"
BCRYPT_TLS1_1_KDF_ALGORITHM        = "TLS1_1_KDF"
BCRYPT_TLS1_2_KDF_ALGORITHM        = "TLS1_2_KDF"
BCRYPT_ECDSA_ALGORITHM             = "ECDSA"
BCRYPT_ECDH_ALGORITHM              = "ECDH"
BCRYPT_XTS_AES_ALGORITHM           = "XTS-AES"
BCRYPT_HKDF_ALGORITHM              = "HKDF"

################################################################################

_BCryptDestroyKey = fun_fact(
    _bcr.BCryptDestroyKey, (NTSTATUS, HANDLE)
    )

def BCryptDestroyKey(key):
    raise_failed_status(_BCryptDestroyKey(key))

class BCRYPT_KEY(ScdToBeClosed, HANDLE, close_func=BCryptDestroyKey, invalid=0):
    def __init__(self, init=None):
        super().__init__(init)
        # additional buffer for symmetric keys
        self.buf = None

    def close(self):
        super().close()
        self.buf = None

################################################################################

_BCryptDestroyHash = fun_fact(
    _bcr.BCryptDestroyHash, (NTSTATUS, HANDLE)
    )

def BCryptDestroyHash(hash):
    raise_failed_status(_BCryptDestroyHash(hash))

class BCRYPT_HASH(
        ScdToBeClosed,
        HANDLE,
        close_func=BCryptDestroyHash,
        invalid=0
        ):
    pass

################################################################################

_BCryptCloseAlgorithmProvider = fun_fact(
    _bcr.BCryptCloseAlgorithmProvider, (NTSTATUS, HANDLE, ULONG)
    )

def BCryptCloseAlgorithmProvider(balg):
    raise_failed_status(_BCryptCloseAlgorithmProvider(balg, 0))

class BCRYPT_ALG(
        ScdToBeClosed,
        HANDLE,
        close_func=BCryptCloseAlgorithmProvider,
        invalid=0
        ):
    pass

################################################################################

_BCryptOpenAlgorithmProvider = fun_fact(
    _bcr.BCryptOpenAlgorithmProvider, (NTSTATUS, PHANDLE, PWSTR, PWSTR, ULONG)
    )

def BCryptOpenAlgorithmProvider(alg, flags=0, impl=None):
    balg = BCRYPT_ALG()
    raise_failed_status(
        _BCryptOpenAlgorithmProvider(ref(balg), alg, impl, flags)
        )
    return balg

################################################################################

_BCryptGetProperty = fun_fact(
    _bcr.BCryptGetProperty, (
        NTSTATUS,
        HANDLE,
        PWSTR,
        PCHAR,
        ULONG,
        PULONG,
        ULONG
        )
    )

def BCryptGetProperty(obj, name):
    size = ULONG()
    raise_failed_status(_BCryptGetProperty(obj, name, None, 0, ref(size), 0))
    buf = byte_buffer(size.value)
    raise_failed_status(_BCryptGetProperty(obj, name, buf, size, ref(size), 0))
    return bytes(buf)

def get_property_ulong(obj, name):
    _bytes = BCryptGetProperty(obj, name)
    if len(_bytes) != ctypes.sizeof(ULONG):
        raise ValueError(f"property size mismatch ({len(_bytes)})")
    return int.from_bytes(_bytes, ENDIANNESS, signed=False)

################################################################################

_BCryptSetProperty = fun_fact(
    _bcr.BCryptSetProperty, (
        NTSTATUS,
        HANDLE,
        PWSTR,
        PCHAR,
        ULONG,
        ULONG
        )
    )

def BCryptSetProperty(obj, name, value):
    if isinstance(value, int):
        buf = value.to_bytes(((value.bit_length() + 31) // 32) * 4, ENDIANNESS)
    elif isinstance(value, str):
        buf = bytes(string_buffer(value))
    else:
        buf = bytes(value)
    raise_failed_status(_BCryptSetProperty(obj, name, buf, len(buf), 0))

################################################################################

_BCryptCreateHash = fun_fact(
    _bcr.BCryptCreateHash, (
        NTSTATUS,
        HANDLE,
        PHANDLE,
        PCHAR,
        ULONG,
        PULONG,
        ULONG,
        ULONG
        )
    )

def BCryptCreateHash(balg, obj_buf, secret=None):
    sec_size = ULONG(0 if secret is None else len(secret))
    bhash = BCRYPT_HASH()
    raise_failed_status(
        _BCryptCreateHash(
            balg,
            ref(bhash),
            obj_buf,
            len(obj_buf),
            secret,
            sec_size,
            0
            )
        )
    return bhash

################################################################################

_BCryptHashData = fun_fact(
    _bcr.BCryptHashData, (NTSTATUS, HANDLE, PCHAR, ULONG, ULONG)
    )

def BCryptHashData(bhash, data):
    raise_failed_status(_BCryptHashData(bhash, data, len(data), 0))

################################################################################

_BCryptFinishHash = fun_fact(
    _bcr.BCryptFinishHash, (NTSTATUS, HANDLE, PCHAR, ULONG, ULONG)
    )

def BCryptFinishHash(bhash, dig_size):
    buf = byte_buffer(dig_size)
    raise_failed_status(_BCryptFinishHash(bhash, buf, len(buf), 0))
    return bytes(buf)

################################################################################

class BCryptHash:
    "standard python hash wrapper for a BCrypt hash"

    def __init__(self, alg):
        self.alg = alg
        self.dig_size = 0
        self.hash = None
        self.obj_buf = None
        self.balg = None
        try:
            self.balg = BCryptOpenAlgorithmProvider(alg)
            self.dig_size = get_property_ulong(self.balg, BCRYPT_HASH_LENGTH)
            obj_size = get_property_ulong(self.balg, BCRYPT_OBJECT_LENGTH)
            self.obj_buf = byte_buffer(obj_size)
            self.hash = BCryptCreateHash(self.balg, self.obj_buf)
        except OSError:
            self.close()
            raise

    def close(self):
        if self.hash is not None:
            self.hash.close()
            self.hash = None
        if self.balg is not None:
            self.balg.close()
            self.balg = None
        self.obj_buf = None

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()

    def copy(self):
        raise NotImplementedError(
            f"cannot copy {self.__class__.__name__} objects"
            )

    def update(self, data):
        BCryptHashData(self.hash, data)

    def digest(self):
        dig = BCryptFinishHash(self.hash, self.dig_size)

        # can only ask for digest once
        self.close()

        return dig

    def hexdigest(self):
        return self.digest().hex()

    @property
    def digest_size(self):
        return self.dig_size

    @property
    def block_size(self):
        return 42

    @property
    def name(self):
        return self.alg

################################################################################

_BCryptExportKey = fun_fact(
    _bcr.BCryptExportKey, (
        NTSTATUS,
        HANDLE,
        HANDLE,
        PWSTR,
        PCHAR,
        ULONG,
        PULONG,
        ULONG
        )
    )

def BCryptExportKey(key, btype, exp_key=None):
    size = ULONG()
    raise_failed_status(
        _BCryptExportKey(key, exp_key, btype, None, 0, ref(size), 0)
        )
    blob = byte_buffer(size.value)
    raise_failed_status(
        _BCryptExportKey(key, exp_key, btype, blob, size, ref(size), 0)
        )
    return bytes(blob)

################################################################################

_BCryptGenerateKeyPair = fun_fact(
    _bcr.BCryptGenerateKeyPair, (NTSTATUS, HANDLE, PHANDLE, ULONG, ULONG)
    )

def BCryptGenerateKeyPair(balg, key_len):
    key = BCRYPT_KEY()
    raise_failed_status(_BCryptGenerateKeyPair(balg, ref(key), key_len, 0))
    return key

################################################################################

_BCryptFinalizeKeyPair = fun_fact(
    _bcr.BCryptFinalizeKeyPair, (NTSTATUS, HANDLE, ULONG)
    )

def BCryptFinalizeKeyPair(key):
    raise_failed_status(_BCryptFinalizeKeyPair(key, 0))

################################################################################

_BCryptGenerateSymmetricKey = fun_fact(
    _bcr.BCryptGenerateSymmetricKey, (
        NTSTATUS,
        HANDLE,
        PHANDLE,
        PCHAR,
        ULONG,
        PCHAR,
        ULONG,
        ULONG
        )
    )

def BCryptGenerateSymmetricKey(balg, secret):
    ksize = get_property_ulong(balg, BCRYPT_OBJECT_LENGTH)
    key = BCRYPT_KEY()
    key.buf = byte_buffer(ksize)
    raise_failed_status(
        _BCryptGenerateSymmetricKey(
            balg,
            ref(key),
            key.buf,
            len(key.buf),
            secret,
            len(secret),
            0
            )
        )
    return key

################################################################################

_BCryptImportKeyPair = fun_fact(
    _bcr.BCryptImportKeyPair, (
        NTSTATUS,
        HANDLE,
        HANDLE,
        PWSTR,
        PHANDLE,
        PCHAR,
        ULONG,
        ULONG
        )
    )

def BCryptImportKeyPair(balg, btype, kbuf):
    key = BCRYPT_KEY()
    raise_failed_status(
        _BCryptImportKeyPair(balg, None, btype, ref(key), kbuf, len(kbuf), 0)
        )
    return key

################################################################################

_BCryptSignHash = fun_fact(
    _bcr.BCryptSignHash, (
        NTSTATUS,
        HANDLE,
        PVOID,
        PCHAR,
        ULONG,
        PCHAR,
        ULONG,
        PULONG,
        ULONG
        )
    )

def BCryptSignHash(key, digest, flags=0):
    size = ULONG()
    raise_failed_status(
        _BCryptSignHash(
            key,
            None,
            digest,
            len(digest),
            None,
            0,
            ref(size),
            flags
            )
        )
    signature = byte_buffer(size.value)
    raise_failed_status(
        _BCryptSignHash(
            key,
            None,
            digest,
            len(digest),
            signature,
            len(signature),
            ref(size),
            flags
            )
        )
    return bytes(signature)

################################################################################

_BCryptVerifySignature = fun_fact(
    _bcr.BCryptVerifySignature, (
        NTSTATUS,
        HANDLE,
        PVOID,
        PCHAR,
        ULONG,
        PCHAR,
        ULONG,
        ULONG
        )
    )

def BCryptVerifySignature(key, digest, signature):
    status = _BCryptVerifySignature(
        key,
        None,
        digest,
        len(digest),
        signature,
        len(signature),
        0
        )
    if status < 0 and status != STATUS_INVALID_SIGNATURE:
        raise_failed_status(status)
    return status == 0

################################################################################

_BCryptEncrypt = fun_fact(
    _bcr.BCryptEncrypt, (
        NTSTATUS,
        HANDLE,
        PCHAR,
        ULONG,
        PVOID,
        PCHAR,
        ULONG,
        PCHAR,
        ULONG,
        PULONG,
        ULONG
        )
    )

def BCryptEncrypt(key, input, iv=None, flags=0):
    size = ULONG()
    raise_failed_status(
        _BCryptEncrypt(
            key,
            input,
            len(input),
            None,
            iv,
            0 if iv is None else len(iv),
            None,
            0,
            ref(size),
            flags
            )
        )
    output = byte_buffer(size.value)
    raise_failed_status(
        _BCryptEncrypt(
            key,
            input,
            len(input),
            None,
            iv,
            0 if iv is None else len(iv),
            output,
            size,
            ref(size),
            flags
            )
        )
    return bytes(output)

################################################################################

_BCryptDecrypt = fun_fact(
    _bcr.BCryptDecrypt, (
        NTSTATUS,
        HANDLE,
        PCHAR,
        ULONG,
        PVOID,
        PCHAR,
        ULONG,
        PCHAR,
        ULONG,
        PULONG,
        ULONG
        )
    )

def BCryptDecrypt(key, input, iv=None, flags=0):
    size = ULONG()
    raise_failed_status(
        _BCryptDecrypt(
            key,
            input,
            len(input),
            None,
            iv,
            0 if iv is None else len(iv),
            None,
            0,
            ref(size),
            flags
            )
        )
    output = byte_buffer(size.value)
    raise_failed_status(
        _BCryptDecrypt(
            key,
            input,
            len(input),
            None,
            iv,
            0 if iv is None else len(iv),
            output,
            size,
            ref(size),
            flags
            )
        )
    return bytes(output)

################################################################################
