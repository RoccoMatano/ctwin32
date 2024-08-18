################################################################################
#
# Copyright 2021-2024 Rocco Matano
# SPDX-License-Identifier: MIT
#
################################################################################

from ctwin32.bcrypt import (
    BCRYPT_AES_ALGORITHM,
    BCRYPT_CHAINING_MODE,
    BCRYPT_CHAIN_MODE_CBC,
    BCryptOpenAlgorithmProvider,
    BCryptSetProperty,
    BCryptGenerateSymmetricKey,
    BCryptEncrypt,
    BCryptDecrypt,
    )

################################################################################

CRYPT_BLOCK_LEN = 16
IS_PYAES = False
try:
    import pyaes
    IS_PYAES = True
except ImportError:
    from cryptography.hazmat.primitives.ciphers import (
        Cipher,
        algorithms,
        modes
        )

################################################################################

def simple_py_aes_encrypt(data, key):
    blen = CRYPT_BLOCK_LEN
    if IS_PYAES:
        rng = range(0, len(data), blen)
        aes = pyaes.AESModeOfOperationCBC(key, None)
        return b"".join(aes.encrypt(data[i:i + blen]) for i in rng)
    else:
        aes = Cipher(algorithms.AES(key), modes.CBC(b"\0" * blen))
        encryptor = aes.encryptor()
        return encryptor.update(data) + encryptor.finalize()

################################################################################

def simple_py_aes_decrypt(data, key):
    blen = CRYPT_BLOCK_LEN
    if IS_PYAES:
        rng = range(0, len(data), blen)
        aes = pyaes.AESModeOfOperationCBC(key, None)
        return b"".join(aes.decrypt(data[i:i + blen]) for i in rng)
    else:
        aes = Cipher(algorithms.AES(key), modes.CBC(b"\0" * blen))
        decryptor = aes.decryptor()
        return decryptor.update(data) + decryptor.finalize()

################################################################################

def simple_bc_aes_encrypt(data, key):
    with BCryptOpenAlgorithmProvider(BCRYPT_AES_ALGORITHM) as alg:
        BCryptSetProperty(alg, BCRYPT_CHAINING_MODE, BCRYPT_CHAIN_MODE_CBC)
        with BCryptGenerateSymmetricKey(alg, key) as hkey:
            return BCryptEncrypt(hkey, data)

################################################################################

def simple_bc_aes_decrypt(data, key):
    with BCryptOpenAlgorithmProvider(BCRYPT_AES_ALGORITHM) as alg:
        BCryptSetProperty(alg, BCRYPT_CHAINING_MODE, BCRYPT_CHAIN_MODE_CBC)
        with BCryptGenerateSymmetricKey(alg, key) as hkey:
            return BCryptDecrypt(hkey, data)

################################################################################

_ascii_trans = bytes([i if 32 <= i < 128 else ord(".") for i in range(256)])

################################################################################

def hex_dump(data, bytes_per_line=16):
    lines = []
    hex_chars = bytes_per_line * 3 - 1
    length = len(data)
    offset = 0
    while offset < length:
        chunk_len = min(length - offset, bytes_per_line)
        chunk = data[offset:offset + chunk_len]
        ascii = chunk.translate(_ascii_trans).decode("ascii")
        hexa = " ".join([f"{c:02x}" for c in chunk]).ljust(hex_chars)
        lines.append(f"{offset:08x} | {hexa} | {ascii}")
        offset += chunk_len
    return "\n".join(lines)

################################################################################

if __name__ == "__main__":

    try:
        assert 1 == 2 # noqa: PLR0133
    except AssertionError:
        pass
    else:
        raise RuntimeError("Assertions are not active")

    plain = bytes(range(256))
    key = b"\xf8\xa9V\x9e'#1\xd7\x1a\x85\r)\x02\x8c,\xa9"

    simple_py_aes_enc = simple_py_aes_encrypt(plain, key)
    assert simple_py_aes_decrypt(simple_py_aes_enc, key) == plain

    simple_bc_aes_enc = simple_bc_aes_encrypt(plain, key)
    assert simple_bc_aes_decrypt(simple_bc_aes_enc, key) == plain

    assert simple_py_aes_decrypt(simple_bc_aes_enc, key) == plain
    assert simple_bc_aes_decrypt(simple_py_aes_enc, key) == plain

    assert simple_py_aes_enc == simple_bc_aes_enc

    print(f"\nplain:\n{hex_dump(plain)}")
    print(f"\nencrypted:\n{hex_dump(simple_bc_aes_enc)}")
