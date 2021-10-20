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
import ipaddress as _iaddr
from collections import defaultdict as _defdict

from . import (
    _fun_fact,
    ERROR_BUFFER_OVERFLOW,
    IF_TYPE_SOFTWARE_LOOPBACK,
    AF_UNSPEC,
    AF_INET,
    AF_INET6,
    GAA_FLAG_SKIP_ANYCAST,
    GAA_FLAG_SKIP_MULTICAST,
    GAA_FLAG_INCLUDE_PREFIX,
    )

_ref = _ct.byref
_iph = _ct.windll.iphlpapi

################################################################################

class _STRUCTURE(_ct.Structure):
    _fields_ = (("Length", _wt.ULONG), ("Flags", _wt.ULONG))

class _UNION(_ct.Union):
    _fields_ = (("Alignment", _ct.c_ulonglong), ("s", _STRUCTURE))
    _anonymous_ = ("s",)

class SOCKADDR(_ct.Structure):
    _fields_ = (("sa_family", _wt.WORD), ("sa_data", _wt.BYTE * 14))

LPSOCKADDR = PSOCKADDR = _ct.POINTER(SOCKADDR)

################################################################################

class SOCKET_ADDRESS(_ct.Structure):
    _fields_ = (
        ("lpSockaddr", PSOCKADDR),
        ("iSockaddrLength", _wt.INT)
        )
PSOCKET_ADDRESS = _ct.POINTER(SOCKET_ADDRESS)

################################################################################

class IP_ADAPTER_UNICAST_ADDRESS(_ct.Structure):
    pass
PIP_ADAPTER_UNICAST_ADDRESS = _ct.POINTER(IP_ADAPTER_UNICAST_ADDRESS)

IP_ADAPTER_UNICAST_ADDRESS._fields_ = (
    ("u", _UNION),
    ("Next", PIP_ADAPTER_UNICAST_ADDRESS),
    ("Address", SOCKET_ADDRESS),
    # we do not need any field after 'Address', so we do not define them
    )

################################################################################

class IP_ADAPTER_PREFIX(_ct.Structure):
    pass
PIP_ADAPTER_PREFIX = _ct.POINTER(IP_ADAPTER_PREFIX)
IP_ADAPTER_PREFIX._fields_ = (
    ("u", _UNION),
    ("Next", PIP_ADAPTER_PREFIX),
    ("Address", SOCKET_ADDRESS),
    ("PrefixLength", _wt.ULONG)
    )

################################################################################

class IP_ADAPTER_ADDRESSES(_ct.Structure):
    pass
PIP_ADAPTER_ADDRESSES = _ct.POINTER(IP_ADAPTER_ADDRESSES)
IP_ADAPTER_ADDRESSES._fields_ = (
    ("u", _UNION),
    ("Next", PIP_ADAPTER_ADDRESSES),
    ("AdapterName", _wt.PCHAR),
    ("FirstUnicastAddress", PIP_ADAPTER_UNICAST_ADDRESS),
    ("FirstAnycastAddress", _wt.LPVOID),
    ("FirstMulticastAddress", _wt.LPVOID),
    ("FirstDnsServerAddress", _wt.LPVOID),
    ("DnsSuffix", _wt.LPWSTR),
    ("Description", _wt.LPWSTR),
    ("FriendlyName", _wt.LPWSTR),
    ("PhysicalAddress", _wt.BYTE * 8),
    ("PhysicalAddressLength", _wt.ULONG),
    ("Flags", _wt.ULONG),
    ("Mtu", _wt.ULONG),
    ("IfType", _wt.ULONG),
    ("OperStatus", _wt.INT),
    ("Ipv6IfIndex", _wt.ULONG),
    ("ZoneIndices", _wt.ULONG * 16),
    ("FirstPrefix", PIP_ADAPTER_PREFIX)
    # we do not need any field after 'FirstPrefix',
    # so we do not define them
    )

################################################################################

class S_UN_B(_ct.Structure):
    _fields_ = (
        ("s_b1", _wt.BYTE),
        ("s_b2", _wt.BYTE),
        ("s_b3", _wt.BYTE),
        ("s_b4", _wt.BYTE)
        )
class S_UN_W(_ct.Structure):
    _fields_ = (("s_w1", _wt.WORD), ("s_w2", _wt.WORD))
class S_UN(_ct.Union):
    _fields_ = (
        ("S_un_b", S_UN_B),
        ("S_un_w", S_UN_W),
        ("S_addr", _wt.ULONG.__ctype_be__)
        )
class IN_ADDR(_ct.Structure):
    _fields_ = (("S_un", S_UN),)
PIN_ADDR = _ct.POINTER(IN_ADDR)

################################################################################

class SOCKADDR_IN(_ct.Structure):
    _fields_ = (
        ("sin_family", _wt.WORD),
        ("sin_port", _wt.WORD),
        ("sin_addr", IN_ADDR),
        ("sin_zero", _wt.BYTE * 8)
        )
PSOCKADDR_IN = _ct.POINTER(SOCKADDR_IN)

################################################################################

class IN6_ADDR(_ct.Union):
    _fields_ = (("Byte", _wt.BYTE * 16), ("Word", _wt.WORD * 8))
PIN6_ADDR = _ct.POINTER(IN6_ADDR)

################################################################################

class SOCKADDR_IN6(_ct.Structure):
    _fields_ = (
        ("sin6_family", _wt.WORD),
        ("sin6_port", _wt.WORD),
        ("sin6_flowinfo", _wt.ULONG),
        ("sin6_addr", IN6_ADDR),
        ("sin6_scope_id", _wt.ULONG),
        )
PSOCKADDR_IN6 = _ct.POINTER(SOCKADDR_IN6)

################################################################################

def _sock_addr_to_ip_addr(p_sock_addr):
    fam = p_sock_addr.contents.sa_family
    if fam == AF_INET:
        addr = _ct.cast(p_sock_addr, PSOCKADDR_IN).contents
        return _iaddr.IPv4Address(addr.sin_addr.S_un.S_addr)
    elif fam == AF_INET6:
        addr = _ct.cast(p_sock_addr, PSOCKADDR_IN6).contents
        ip = _iaddr.IPv6Address(bytes(addr.sin6_addr.Byte))
        if addr.sin6_scope_id:
            ip = _iaddr.IPv6Address(f"{ip}%{addr.sin6_scope_id}")
        return ip
    else:
        raise ValueError(f"unsupported address family: {fam}")

################################################################################

_GetAdaptersAddresses = _fun_fact(
    _iph.GetAdaptersAddresses, (
        _wt.ULONG,
        _wt.ULONG,
        _wt.ULONG,
        _wt.LPVOID,
        PIP_ADAPTER_ADDRESSES,
        _wt.PULONG
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
        adapter_address = p_adresses.contents
        p_adresses = adapter_address.Next
        not_loopback = adapter_address.IfType != IF_TYPE_SOFTWARE_LOOPBACK
        if not_loopback or include_loopback:
            pfx_ptr = adapter_address.FirstPrefix
            prefixes = []
            while pfx_ptr:
                pfx = pfx_ptr.contents
                pfx_ptr = pfx.Next
                prefix = _sock_addr_to_ip_addr(pfx.Address.lpSockaddr)
                prefixes.append((prefix, pfx.PrefixLength))
            adapter_name = _ct.string_at(adapter_address.AdapterName).decode()
            pfua = adapter_address.FirstUnicastAddress
            while pfua:
                fua = pfua.contents
                pfua = fua.Next
                ip = _sock_addr_to_ip_addr(fua.Address.lpSockaddr)
                plen = _best_prefix_len(ip, prefixes)
                result[adapter_name].append(_iaddr.ip_interface(f"{ip}/{plen}"))

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
    blen = _wt.ULONG(16 * 1024)
    error = ERROR_BUFFER_OVERFLOW
    while error == ERROR_BUFFER_OVERFLOW:
        buffer = _ct.create_string_buffer(blen.value)
        p_addr = _ct.cast(buffer, PIP_ADAPTER_ADDRESSES)
        error = _GetAdaptersAddresses(fam, flags, None, p_addr, _ref(blen))
    if error:
        raise _ct.WinError(error)

    return _adapter_addresses_to_interfaces(p_addr, include_loopback)

################################################################################
