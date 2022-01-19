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

import ipaddress as _iaddr
from collections import defaultdict as _defdict

from .wtypes import *
from . import (
    ctypes,
    ref,
    fun_fact,
    raise_on_err,
    ERROR_BUFFER_OVERFLOW,
    IF_TYPE_SOFTWARE_LOOPBACK,
    AF_UNSPEC,
    AF_INET,
    AF_INET6,
    GAA_FLAG_SKIP_ANYCAST,
    GAA_FLAG_SKIP_MULTICAST,
    GAA_FLAG_INCLUDE_PREFIX,
    )

_iph = ctypes.windll.iphlpapi

################################################################################

class _STRUCTURE(ctypes.Structure):
    _fields_ = (("Length", ULONG), ("Flags", ULONG))

class _UNION(ctypes.Union):
    _fields_ = (("Alignment", ctypes.c_ulonglong), ("s", _STRUCTURE))
    _anonymous_ = ("s",)

class SOCKADDR(ctypes.Structure):
    _fields_ = (("sa_family", WORD), ("sa_data", BYTE * 14))

PSOCKADDR = ctypes.POINTER(SOCKADDR)

################################################################################

class SOCKET_ADDRESS(ctypes.Structure):
    _fields_ = (
        ("lpSockaddr", PSOCKADDR),
        ("iSockaddrLength", INT)
        )
PSOCKET_ADDRESS = ctypes.POINTER(SOCKET_ADDRESS)

################################################################################

class IP_ADAPTER_UNICAST_ADDRESS(ctypes.Structure):
    pass
PIP_ADAPTER_UNICAST_ADDRESS = ctypes.POINTER(IP_ADAPTER_UNICAST_ADDRESS)

IP_ADAPTER_UNICAST_ADDRESS._fields_ = (
    ("u", _UNION),
    ("Next", PIP_ADAPTER_UNICAST_ADDRESS),
    ("Address", SOCKET_ADDRESS),
    # we do not need any field after 'Address', so we do not define them
    )

################################################################################

class IP_ADAPTER_PREFIX(ctypes.Structure):
    pass
PIP_ADAPTER_PREFIX = ctypes.POINTER(IP_ADAPTER_PREFIX)
IP_ADAPTER_PREFIX._fields_ = (
    ("u", _UNION),
    ("Next", PIP_ADAPTER_PREFIX),
    ("Address", SOCKET_ADDRESS),
    ("PrefixLength", ULONG)
    )

################################################################################

class IP_ADAPTER_ADDRESSES(ctypes.Structure):
    pass
PIP_ADAPTER_ADDRESSES = ctypes.POINTER(IP_ADAPTER_ADDRESSES)
IP_ADAPTER_ADDRESSES._fields_ = (
    ("u", _UNION),
    ("Next", PIP_ADAPTER_ADDRESSES),
    ("AdapterName", PCHAR),
    ("FirstUnicastAddress", PIP_ADAPTER_UNICAST_ADDRESS),
    ("FirstAnycastAddress", PVOID),
    ("FirstMulticastAddress", PVOID),
    ("FirstDnsServerAddress", PVOID),
    ("DnsSuffix", PWSTR),
    ("Description", PWSTR),
    ("FriendlyName", PWSTR),
    ("PhysicalAddress", BYTE * 8),
    ("PhysicalAddressLength", ULONG),
    ("Flags", ULONG),
    ("Mtu", ULONG),
    ("IfType", ULONG),
    ("OperStatus", INT),
    ("Ipv6IfIndex", ULONG),
    ("ZoneIndices", ULONG * 16),
    ("FirstPrefix", PIP_ADAPTER_PREFIX)
    # we do not need any field after 'FirstPrefix',
    # so we do not define them
    )

################################################################################

class S_UN_B(ctypes.Structure):
    _fields_ = (
        ("s_b1", BYTE),
        ("s_b2", BYTE),
        ("s_b3", BYTE),
        ("s_b4", BYTE)
        )
class S_UN_W(ctypes.Structure):
    _fields_ = (("s_w1", WORD), ("s_w2", WORD))
class S_UN(ctypes.Union):
    _fields_ = (
        ("S_un_b", S_UN_B),
        ("S_un_w", S_UN_W),
        ("S_addr", ULONG.__ctype_be__)
        )
class IN_ADDR(ctypes.Structure):
    _fields_ = (("S_un", S_UN),)
PIN_ADDR = ctypes.POINTER(IN_ADDR)

################################################################################

class SOCKADDR_IN(ctypes.Structure):
    _fields_ = (
        ("sin_family", WORD),
        ("sin_port", WORD),
        ("sin_addr", IN_ADDR),
        ("sin_zero", BYTE * 8)
        )
PSOCKADDR_IN = ctypes.POINTER(SOCKADDR_IN)

################################################################################

class IN6_ADDR(ctypes.Union):
    _fields_ = (("Byte", BYTE * 16), ("Word", WORD * 8))
PIN6_ADDR = ctypes.POINTER(IN6_ADDR)

################################################################################

class SOCKADDR_IN6(ctypes.Structure):
    _fields_ = (
        ("sin6_family", WORD),
        ("sin6_port", WORD),
        ("sin6_flowinfo", ULONG),
        ("sin6_addr", IN6_ADDR),
        ("sin6_scope_id", ULONG),
        )
PSOCKADDR_IN6 = ctypes.POINTER(SOCKADDR_IN6)

################################################################################

def _sock_addr_to_ip_addr(p_sock_addr):
    fam = p_sock_addr.contents.sa_family
    if fam == AF_INET:
        addr = ctypes.cast(p_sock_addr, PSOCKADDR_IN).contents
        return _iaddr.IPv4Address(addr.sin_addr.S_un.S_addr)
    elif fam == AF_INET6:
        addr = ctypes.cast(p_sock_addr, PSOCKADDR_IN6).contents
        ip = _iaddr.IPv6Address(bytes(addr.sin6_addr.Byte))
        if addr.sin6_scope_id:
            ip = _iaddr.IPv6Address(f"{ip}%{addr.sin6_scope_id}")
        return ip
    else:
        raise ValueError(f"unsupported address family: {fam}")

################################################################################

_GetAdaptersAddresses = fun_fact(
    _iph.GetAdaptersAddresses, (
        ULONG,
        ULONG,
        ULONG,
        PVOID,
        PIP_ADAPTER_ADDRESSES,
        PULONG
        )
    )

################################################################################

def _best_prefix_len(ip, prefixes):
    best_len = 0
    for pfx, plen in prefixes:
        skip = (
            ip.version != pfx.version or
            best_len > plen or
            best_len and plen == ip.max_prefixlen
            )
        if not skip:
            mask = -1 << (ip.max_prefixlen - plen)
            if int(ip) & mask == int(pfx) & mask:
                best_len = plen
    if best_len:
        return best_len
    raise ValueError("no matching prefix found")

################################################################################

def _adapter_addresses_to_interfaces(p_adresses, include_loopback):
    result = _defdict(list)
    while p_adresses:
        adptr_addr = p_adresses.contents
        p_adresses = adptr_addr.Next
        not_loopback = adptr_addr.IfType != IF_TYPE_SOFTWARE_LOOPBACK
        if not_loopback or include_loopback:
            pfx_ptr = adptr_addr.FirstPrefix
            prefixes = []
            while pfx_ptr:
                pfx = pfx_ptr.contents
                pfx_ptr = pfx.Next
                prefix = _sock_addr_to_ip_addr(pfx.Address.lpSockaddr)
                prefixes.append((prefix, pfx.PrefixLength))
            adptr_name = ctypes.string_at(adptr_addr.AdapterName).decode()
            pfua = adptr_addr.FirstUnicastAddress
            while pfua:
                fua = pfua.contents
                pfua = fua.Next
                ip = _sock_addr_to_ip_addr(fua.Address.lpSockaddr)
                plen = _best_prefix_len(ip, prefixes)
                result[adptr_name].append(_iaddr.ip_interface(f"{ip}/{plen}"))

    return dict(result) # no more default values

################################################################################

def get_host_interfaces(version=4, include_loopback=False):
    "returns the list of the ip interfaces of the local network adapters"

    fam = AF_INET
    if version != 4 and  version != 6:
        fam = AF_UNSPEC
    elif version == 6:
        fam = AF_INET6

    flags = (
        GAA_FLAG_INCLUDE_PREFIX |
        GAA_FLAG_SKIP_ANYCAST |
        GAA_FLAG_SKIP_MULTICAST
        )
    blen = ULONG(16 * 1024)
    error = ERROR_BUFFER_OVERFLOW
    while error == ERROR_BUFFER_OVERFLOW:
        buffer = ctypes.create_string_buffer(blen.value)
        p_addr = ctypes.cast(buffer, PIP_ADAPTER_ADDRESSES)
        error = _GetAdaptersAddresses(fam, flags, None, p_addr, ref(blen))
    raise_on_err(error)

    return _adapter_addresses_to_interfaces(p_addr, include_loopback)

################################################################################
