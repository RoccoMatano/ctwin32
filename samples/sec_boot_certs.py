################################################################################
#
# Copyright 2021-2026 Rocco Matano
# SPDX-License-Identifier: MIT
#
################################################################################
#
# This script extracts and prints the certificates that are used by 'Secure
# Boot' to verify bootloaders.
#
# Note: This code tries to be independent from extension module besides
#       'ctwin32'. That is why 'cryptography' is not used for parsing the
#       certificates. In production code you should *not* do that but rely on
#       proven 'cryptography'.
#
################################################################################

import datetime
from ctwin32 import (
    ERROR_PRIVILEGE_NOT_HELD,
    kernel,
    ntdll,
    SE_SYSTEM_ENVIRONMENT_PRIVILEGE,
    )

################################################################################
####################### begin of shoddy x509 DER parsing #######################
################################################################################

# ASN.1 tag classes
UNIVERSAL = 0x00
CONTEXT_SPECIFIC = 0x80

# Universal tags
TAG_SEQUENCE = 0x30
TAG_INTEGER = 0x02
TAG_BIT_STRING = 0x03
TAG_OCTET_STRING = 0x04
TAG_OBJECT_IDENTIFIER = 0x06
TAG_PRINTABLE_STRING = 0x13
TAG_UTF8_STRING = 0x0C
TAG_UTC_TIME = 0x17
TAG_GENERALIZED_TIME = 0x18

################################################################################

def read_length(data, offset):
    first = data[offset]
    offset += 1

    if first & 0x80 == 0:
        return first, offset

    num_bytes = first & 0x7F
    length = int.from_bytes(data[offset:offset + num_bytes], "big")
    return length, offset + num_bytes

################################################################################

def read_tlv(data, offset):
    tag = data[offset]
    offset += 1

    length, offset = read_length(data, offset)
    value = data[offset:offset + length]
    return tag, length, value, offset + length

################################################################################

def parse_integer(value):
    return int.from_bytes(value, byteorder="big", signed=False)

################################################################################

def parse_oid(value):
    first = value[0]
    oid = [first // 40, first % 40]
    n = 0
    for b in value[1:]:
        n = (n << 7) | (b & 0x7F)
        if not (b & 0x80):
            oid.append(n)
            n = 0
    return ".".join(map(str, oid))

################################################################################

def parse_time(tag, value):
    strv = value.decode("ascii")
    if tag == TAG_UTC_TIME:
        year = 2000 + int(strv[:2])
        strv = strv[2:]
    else:
        year = int(strv[:4])
        strv = strv[4:]
    return datetime.datetime(
        year,
        int(strv[0:2]),
        int(strv[2:4]),
        int(strv[4:6]),
        int(strv[6:8]),
        int(strv[8:10]),
        tzinfo=datetime.UTC
        )

################################################################################

def parse_sequence(data):
    elements = []
    offset = 0
    while offset < len(data):
        tag, _, value, offset = read_tlv(data, offset)
        elements.append((tag, value))
    return elements

################################################################################

X509_ATTR_OIDS = {
    "2.5.4.3": "CN",
    "2.5.4.6": "C",
    "2.5.4.7": "L",
    "2.5.4.8": "ST",
    "2.5.4.10": "O",
    "2.5.4.11": "OU",
    }

################################################################################

def parse_name(data):
    result = []
    offset = 0
    while offset < len(data):
        rdn_tag, _, rdn_value, offset = read_tlv(data, offset)
        if rdn_tag != 0x31:  # SET
            continue

        rdn_offset = 0
        while rdn_offset < len(rdn_value):
            atv_tag, _, atv_value, rdn_offset = read_tlv(rdn_value, rdn_offset)
            if atv_tag != TAG_SEQUENCE:
                continue
            atv_items = parse_sequence(atv_value)
            if len(atv_items) < 2:
                continue
            oid = parse_oid(atv_items[0][1])
            attr = X509_ATTR_OIDS.get(oid, oid)
            val_tag, val_bytes = atv_items[1]
            if val_tag in (TAG_PRINTABLE_STRING, TAG_UTF8_STRING):
                value = val_bytes.decode("utf-8", errors="replace")
            else:
                value = val_bytes.hex()

            result.append((attr, value))

    return ", ".join(f"{t[0]}={t[1]}" for t in reversed(result))

################################################################################

def parse_der_x509(cert_der):
    tag, _, cert_value, _ = read_tlv(cert_der, 0)
    if tag != TAG_SEQUENCE:
        raise ValueError("Not a valid X.509 certificate")

    cert_fields = parse_sequence(cert_value)

    # tbsCertificate
    _, tbs_value = cert_fields[0]
    tbs_fields = parse_sequence(tbs_value)

    idx = 0

    # Optional version
    if tbs_fields[0][0] & 0xA0 == 0xA0:
        idx += 1

    serial = parse_integer(tbs_fields[idx][1])
    idx += 1

    # Skip signature algorithm
    idx += 1

    issuer = parse_name(tbs_fields[idx][1])
    idx += 1

    # Validity
    validity = parse_sequence(tbs_fields[idx][1])
    not_before = parse_time(validity[0][0], validity[0][1])
    not_after = parse_time(validity[1][0], validity[1][1])
    idx += 1

    subject = parse_name(tbs_fields[idx][1])

    return {
        "subject": subject,
        "issuer": issuer,
        "serial_number": serial,
        "not_before": not_before,
        "not_after": not_after,
        }

################################################################################
######################## end of shoddy x509 DER parsing ########################
################################################################################

def extract_der_x509(db):
    # the following corresponds to GUID {a5c059a1-94e4-4aa7-87b5-ab155c2bf072}
    efi_cert_x509 = b"\xa1Y\xc0\xa5\xe4\x94\xa7J\x87\xb5\xab\x15\\+\xf0r"
    result = []
    offs = 0
    LST_HDR_SIZE = 28
    while (offs + LST_HDR_SIZE) < len(db):
        guid = db[offs : offs + 16]
        list_size = int.from_bytes(db[offs + 16 : offs + 20], "little")
        sig_size = int.from_bytes(db[offs + 24 : offs + 28], "little")
        count = (list_size - LST_HDR_SIZE) // sig_size
        sig_offs = offs + LST_HDR_SIZE
        for _ in range(count):
            if guid == efi_cert_x509:
                result.append(db[sig_offs + 16 : sig_offs + sig_size])
            sig_offs += sig_size
        offs += list_size

    return result

################################################################################

if __name__ == "__main__":
    try:
        ntdll.RtlAdjustPrivilege(SE_SYSTEM_ENVIRONMENT_PRIVILEGE, True)
    except OSError as e:
        if e.winerror == ERROR_PRIVILEGE_NOT_HELD:
            print("need FW vars privilege - try running as admin")
        else:
            raise
    else:
        sec_db_guid = "{d719b2cb-3d3a-4596-a3bc-dad00e67656f}"
        db, _ = kernel.GetFirmwareEnvironmentVariableEx("db", sec_db_guid)
        print()
        for der_x509 in extract_der_x509(db):
            cert = parse_der_x509(der_x509)
            print("         subject", cert["subject"])
            print("          issuer", cert["issuer"])
            print("   serial number", cert["serial_number"])
            print("not valid before", cert["not_before"])
            print(" not valid after", cert["not_after"])
            print()

################################################################################
