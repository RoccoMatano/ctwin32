################################################################################
#
# Copyright 2021-2024 Rocco Matano
# SPDX-License-Identifier: MIT
#
################################################################################

import argparse
from ctwin32.bcrypt import (
    BCRYPT_ECDSA_P256_ALGORITHM,
    BCRYPT_SHA256_ALGORITHM,
    BCRYPT_ECCPRIVATE_BLOB,
    BCRYPT_ECCPUBLIC_BLOB,
    BCryptExportKey,
    BCryptOpenAlgorithmProvider,
    BCryptHash,
    BCryptGenerateKeyPair,
    BCryptFinalizeKeyPair,
    BCryptImportKeyPair,
    BCryptSignHash,
    BCryptVerifySignature,
    )

################################################################################

SIGN_ALGO      = BCRYPT_ECDSA_P256_ALGORITHM
SIGN_ALGO_BITS = 256
HASH_ALGORITHM = BCRYPT_SHA256_ALGORITHM
BLOB_PRIVATE   = BCRYPT_ECCPRIVATE_BLOB
BLOB_PUBLIC    = BCRYPT_ECCPUBLIC_BLOB

################################################################################

def export_key(key, btype, file_name):
    with open(file_name, "wb") as f:
        f.write(BCryptExportKey(key, btype))

################################################################################

def hash_file(file_name):
    with BCryptHash(HASH_ALGORITHM) as hash:
        chunk = 0x10000
        with open(file_name, "rb") as f:
            while data := f.read(chunk):
                hash.update(data)
            return hash.digest()

################################################################################

def create_key_pair(private_name, public_name):
    with BCryptOpenAlgorithmProvider(SIGN_ALGO) as alg:
        with BCryptGenerateKeyPair(alg, SIGN_ALGO_BITS) as key:
            BCryptFinalizeKeyPair(key)
            export_key(key, BLOB_PRIVATE, private_name)
            export_key(key, BLOB_PUBLIC, public_name)

################################################################################

def sign(source_name, key_file, sig_file, out_hex):
    with BCryptOpenAlgorithmProvider(SIGN_ALGO) as alg:
        with open(key_file, "rb") as f:
            kbuf = f.read()
        with BCryptImportKeyPair(alg, BLOB_PRIVATE, kbuf) as key:
            signature = BCryptSignHash(key, hash_file(source_name))
            if out_hex:
                print(signature.hex())
            else:
                with open(sig_file, "wb") as f:
                    f.write(signature)

################################################################################

def verify(source_name, key_file, sig_file):
    with BCryptOpenAlgorithmProvider(SIGN_ALGO) as alg:
        with open(key_file, "rb") as f:
            kbuf = f.read()
        with BCryptImportKeyPair(alg, BLOB_PUBLIC, kbuf) as key:
            with open(sig_file, "rb") as f:
                signature = f.read()
            ok = BCryptVerifySignature(key, hash_file(source_name), signature)
            print(
                "The signature is valid." if ok
                else "Signature verification failed."
                )

################################################################################

def parse_args():
    ape = argparse.ArgumentParser()
    sub = ape.add_subparsers(
        title="available commands",
        dest="cmd",
        help="action",
        metavar="command"
        )

    create = sub.add_parser("create", help="create a new key pair")
    create.add_argument(
        dest="private",
        metavar="<private_keyfile>",
        help="name of private key file"
        )
    create.add_argument(
        dest="public",
        metavar="<public_keyfile>",
        help="name of public key file"
        )

    sign = sub.add_parser("sign", help="create signature for a file")
    sign.add_argument(
        "-k",
        dest="keyfile",
        metavar="<private_keyfile>",
        help="name of private key file",
        required=True
        )
    sign.add_argument(
        "-s",
        dest="sigfile",
        metavar="<output_sigfile>",
        help="name of output file for signature",
        required=True
        )
    sign.add_argument(
        "-x",
        dest="outhex",
        help="output signature as hex string",
        action="store_true"
        )
    sign.add_argument(
        dest="sourcefile",
        metavar="<source_file>",
        help="name of file to sign"
        )

    verify = sub.add_parser("verify", help="verify signature for a file")
    verify.add_argument(
        "-k",
        dest="keyfile",
        metavar="<public_keyfile>",
        help="name of public key file",
        required=True
        )
    verify.add_argument(
        "-s",
        dest="sigfile",
        metavar="<input_sigfile>",
        help="name of signature file",
        required=True
        )
    verify.add_argument(
        dest="sourcefile",
        metavar="<source_file>",
        help="name of file to verify"
        )

    return ape.parse_args()

################################################################################

def main():
    args = parse_args()
    if args.cmd == "create":
        create_key_pair(args.private, args.public)
    elif args.cmd == "sign":
        sign(args.sourcefile, args.keyfile, args.sigfile, args.outhex)
    elif args.cmd == "verify":
        verify(args.sourcefile, args.keyfile, args.sigfile)

################################################################################

if __name__ == "__main__":
    main()

################################################################################
