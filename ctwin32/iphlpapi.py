################################################################################
#
# Copyright 2021-2025 Rocco Matano
# SPDX-License-Identifier: MIT
#
################################################################################

import ipaddress as _iaddr
from types import SimpleNamespace as _namespace
from collections import defaultdict as _defdict
from dataclasses import dataclass as _dtacls, field as _field

import ctypes
from .wtypes import (
    byte_buffer,
    string_buffer,
    BYTE,
    Struct,
    Union,
    DWORD,
    GUID,
    INT,
    PCHAR,
    PGUID,
    POINTER,
    PPVOID,
    PULONG,
    PULONGLONG,
    PVOID,
    PWSTR,
    SIZE_T,
    ULONG,
    ULONGLONG,
    WORD,
    )
from . import (
    ApiDll,
    ref,
    raise_on_err,
    ERROR_BUFFER_OVERFLOW,
    IF_TYPE_SOFTWARE_LOOPBACK,
    AF_UNSPEC,
    AF_INET,
    AF_INET6,
    )

_iph = ApiDll("iphlpapi.dll")

################################################################################

GAA_FLAG_SKIP_UNICAST                = 0x0001
GAA_FLAG_SKIP_ANYCAST                = 0x0002
GAA_FLAG_SKIP_MULTICAST              = 0x0004
GAA_FLAG_SKIP_DNS_SERVER             = 0x0008
GAA_FLAG_INCLUDE_PREFIX              = 0x0010
GAA_FLAG_SKIP_FRIENDLY_NAME          = 0x0020
GAA_FLAG_INCLUDE_WINS_INFO           = 0x0040
GAA_FLAG_INCLUDE_GATEWAYS            = 0x0080
GAA_FLAG_INCLUDE_ALL_INTERFACES      = 0x0100
GAA_FLAG_INCLUDE_ALL_COMPARTMENTS    = 0x0200
GAA_FLAG_INCLUDE_TUNNEL_BINDINGORDER = 0x0400
GAA_FLAG_SKIP_DNS_INFO               = 0x0800

################################################################################

class _STRUCTURE(Struct):
    _fields_ = (("Length", ULONG), ("Flags", ULONG))

class _UNION(Union):
    _fields_ = (("Alignment", ULONGLONG), ("s", _STRUCTURE))
    _anonymous_ = ("s",)

class SOCKADDR(Struct):
    _fields_ = (("sa_family", WORD), ("sa_data", BYTE * 14))

PSOCKADDR = POINTER(SOCKADDR)

################################################################################

class SOCKET_ADDRESS(Struct):
    _fields_ = (
        ("lpSockaddr", PSOCKADDR),
        ("iSockaddrLength", INT)
        )
PSOCKET_ADDRESS = POINTER(SOCKET_ADDRESS)

################################################################################

class IP_ADAPTER_UNICAST_ADDRESS(Struct):
    pass
PIP_ADAPTER_UNICAST_ADDRESS = POINTER(IP_ADAPTER_UNICAST_ADDRESS)

IP_ADAPTER_UNICAST_ADDRESS._fields_ = (
    ("u", _UNION),
    ("Next", PIP_ADAPTER_UNICAST_ADDRESS),
    ("Address", SOCKET_ADDRESS),
    # we do not need any field after 'Address', so we do not define them
    )

################################################################################

class IP_ADAPTER_PREFIX(Struct):
    pass
PIP_ADAPTER_PREFIX = POINTER(IP_ADAPTER_PREFIX)
IP_ADAPTER_PREFIX._fields_ = (
    ("u", _UNION),
    ("Next", PIP_ADAPTER_PREFIX),
    ("Address", SOCKET_ADDRESS),
    ("PrefixLength", ULONG)
    )

################################################################################

class IP_ADAPTER_ADDRESSES(Struct):
    pass
PIP_ADAPTER_ADDRESSES = POINTER(IP_ADAPTER_ADDRESSES)
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

class S_UN_B(Struct):
    _fields_ = (
        ("s_b1", BYTE),
        ("s_b2", BYTE),
        ("s_b3", BYTE),
        ("s_b4", BYTE)
        )

class S_UN_W(Struct):
    _fields_ = (("s_w1", WORD), ("s_w2", WORD))

class S_UN(Union):
    _fields_ = (
        ("S_un_b", S_UN_B),
        ("S_un_w", S_UN_W),
        ("S_addr", ULONG.__ctype_be__)
        )

class IN_ADDR(Struct):
    _fields_ = (("S_un", S_UN),)
PIN_ADDR = POINTER(IN_ADDR)

################################################################################

class SOCKADDR_IN(Struct):
    _fields_ = (
        ("sin_family", WORD),
        ("sin_port", WORD),
        ("sin_addr", IN_ADDR),
        ("sin_zero", BYTE * 8)
        )
PSOCKADDR_IN = POINTER(SOCKADDR_IN)

################################################################################

class IN6_ADDR(Union):
    _fields_ = (("Byte", BYTE * 16), ("Word", WORD * 8))
PIN6_ADDR = POINTER(IN6_ADDR)

################################################################################

class SOCKADDR_IN6(Struct):
    _fields_ = (
        ("sin6_family", WORD),
        ("sin6_port", WORD),
        ("sin6_flowinfo", ULONG),
        ("sin6_addr", IN6_ADDR),
        ("sin6_scope_id", ULONG),
        )
PSOCKADDR_IN6 = POINTER(SOCKADDR_IN6)

################################################################################

class SOCKADDR_INET(Union):
    _fields_ = (
        ("Ipv4", SOCKADDR_IN),
        ("Ipv6", SOCKADDR_IN6),
        ("si_family", WORD),
        )

    def get_ipaddr(self):
        fam = self.Ipv4.sin_family
        if fam == AF_INET:
            return _iaddr.IPv4Address(self.Ipv4.sin_addr.S_un.S_addr)
        elif fam == AF_INET6:
            return _iaddr.IPv6Address(bytes(self.Ipv6.sin6_addr.Byte))
        else:
            raise ValueError(f"unsupported address family: {fam}")

################################################################################

@_dtacls
class Ifaces:
    idx: int = -1
    guid: str = ""
    alias: str = ""
    phys_addr: bytes = 6 * b"\0"
    ifaces: list = _field(default_factory=list)

    @staticmethod
    def sortkey(iface):
        return iface.idx


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

_GetAdaptersAddresses = _iph.fun_fact(
    "GetAdaptersAddresses", (
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
            (best_len and plen == ip.max_prefixlen)
            )
        if not skip:
            mask = -1 << (ip.max_prefixlen - plen)
            if int(ip) & mask == int(pfx) & mask:
                best_len = plen

    return best_len if best_len else ip.max_prefixlen

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
            phy_len = adptr_addr.PhysicalAddressLength
            phy_addr = bytes(adptr_addr.PhysicalAddress[:phy_len])
            result[adptr_name].append(phy_addr)
            pfua = adptr_addr.FirstUnicastAddress
            while pfua:
                fua = pfua.contents
                pfua = fua.Next
                ip = _sock_addr_to_ip_addr(fua.Address.lpSockaddr)
                plen = _best_prefix_len(ip, prefixes)
                result[adptr_name].append(_iaddr.ip_interface(f"{ip}/{plen}"))

    return dict(result)  # no more default values

################################################################################

def _ver_to_fam(ver):
    return AF_INET if ver == 4 else (AF_INET6 if ver == 6 else AF_UNSPEC)

################################################################################

def _get_phy_and_ifaces(version, include_loopback):
    fam = _ver_to_fam(version)
    flags = (
        GAA_FLAG_INCLUDE_PREFIX |
        GAA_FLAG_SKIP_ANYCAST |
        GAA_FLAG_SKIP_MULTICAST
        )
    blen = ULONG(16 * 1024)
    error = ERROR_BUFFER_OVERFLOW
    while error == ERROR_BUFFER_OVERFLOW:
        buffer = byte_buffer(blen.value)
        p_addr = ctypes.cast(buffer, PIP_ADAPTER_ADDRESSES)
        error = _GetAdaptersAddresses(fam, flags, None, p_addr, ref(blen))
    raise_on_err(error)
    return _adapter_addresses_to_interfaces(p_addr, include_loopback)

################################################################################

def get_host_interfaces(version=4, include_loopback=False):
    "returns a dict that maps adapters giuds to a list of ip interfaces"
    phys_and_if = _get_phy_and_ifaces(version, include_loopback)
    return {g: lst[1:] for g, lst in phys_and_if.items()}

################################################################################

def _guid_to_idx_and_alias(guid):
    luid = ConvertInterfaceGuidToLuid(guid)
    alias = ConvertInterfaceLuidToAlias(luid)
    idx = 1
    while True:
        try:
            if luid == ConvertInterfaceIndexToLuid(idx):
                return idx, alias
            idx += 1
        except OSError:
            break
    raise ValueError(f"no index found for '{guid}'")

################################################################################

def netifaces(version=4, include_loopback=False):
    "returns a list of Iface objects describing the network adapters"
    result = []
    phys_and_if = _get_phy_and_ifaces(version, include_loopback)
    for guid, lst in phys_and_if.items():
        idx, alias = _guid_to_idx_and_alias(guid)
        result.append(Ifaces(idx, guid, alias, lst[0], lst[1:]))
    return sorted(result, key=Ifaces.sortkey)

################################################################################

IF_MAX_PHYS_ADDRESS_LENGTH = 32

class MIB_IPNET_ROW2(Struct):
    _fields_ = (
        ("Address", SOCKADDR_INET),
        ("InterfaceIndex", ULONG),
        ("InterfaceLuid", ULONGLONG),
        ("PhysicalAddress", BYTE * IF_MAX_PHYS_ADDRESS_LENGTH),
        ("PhysicalAddressLength", DWORD),
        ("State", DWORD),
        ("Flags", BYTE),
        ("ReachabilityTime", ULONG),
        )

class IP_ADDRESS_PREFIX(Struct):
    _fields_ = (
        ("Prefix", SOCKADDR_INET),
        ("PrefixLength", BYTE),
        )

class MIB_IPFORWARD_ROW2(Struct):
    _fields_ = (
        ("InterfaceLuid", ULONGLONG),
        ("InterfaceIndex", ULONG),
        ("DestinationPrefix", IP_ADDRESS_PREFIX),
        ("NextHop", SOCKADDR_INET),
        ("SitePrefixLength", BYTE),
        ("ValidLifetime", ULONG),
        ("PreferredLifetime", ULONG),
        ("Metric", ULONG),
        ("Protocol", INT),
        ("Loopback", BYTE),
        ("AutoconfigureAddress", BYTE),
        ("Publish", BYTE),
        ("Immortal", BYTE),
        ("Age", ULONG),
        ("Origin", INT),
        )

################################################################################

FreeMibTable = _iph.fun_fact("FreeMibTable", (None, PVOID))

################################################################################

_GetIpNetTable2 = _iph.fun_fact("GetIpNetTable2", (DWORD, WORD, PPVOID))

def GetIpNetTable2(version=0):
    ptr = PVOID()
    raise_on_err(_GetIpNetTable2(_ver_to_fam(version), ref(ptr)))
    try:
        num = ctypes.cast(ptr, PULONG).contents.value

        class MIB_IPNETTABLE2(Struct):
            _fields_ = (
                ("NumEntries", ULONG),
                ("Table", MIB_IPNET_ROW2 * num),
                )

        return [
            _namespace(
                index=e.InterfaceIndex,
                luid=e.InterfaceLuid,
                if_type=e.InterfaceLuid >> 48,
                phys_addr=e.PhysicalAddress[:e.PhysicalAddressLength],
                addr=e.Address.get_ipaddr(),
                state=e.State,
                flags=e.Flags,
                reach_time=e.ReachabilityTime
                )
            for e in MIB_IPNETTABLE2.from_address(ptr.value).Table
            ]

    finally:
        FreeMibTable(ptr)

################################################################################

_GetIpForwardTable2 = _iph.fun_fact("GetIpForwardTable2", (DWORD, WORD, PPVOID))

def GetIpForwardTable2(version=0):
    ptr = PVOID()
    raise_on_err(_GetIpForwardTable2(_ver_to_fam(version), ref(ptr)))
    try:
        num = ctypes.cast(ptr, PULONG).contents.value

        class MIB_IPFORWARD_TABLE2(Struct):
            _fields_ = (
                ("NumEntries", ULONG),
                ("Table", MIB_IPFORWARD_ROW2 * num),
                )

        return [
            _namespace(
                index=e.InterfaceIndex,
                luid=e.InterfaceLuid,
                if_type=e.InterfaceLuid >> 48,
                dest_pfx=_namespace(
                    prefix=e.DestinationPrefix.Prefix.get_ipaddr(),
                    prefix_len=e.DestinationPrefix.PrefixLength,
                    ),
                next_hop=e.NextHop.get_ipaddr(),
                site_pfx_len=e.SitePrefixLength,
                valid_lifetime=e.ValidLifetime,
                preferred_lifetime=e.PreferredLifetime,
                metric=e.Metric,
                protocol=e.Protocol,
                Loopback=bool(e.Loopback),
                AutoconfigureAddress=bool(e.AutoconfigureAddress),
                Publish=bool(e.Publish),
                Immortal=bool(e.Immortal),
                age=e.Age,
                Origin=e.Origin,
                )
            for e in MIB_IPFORWARD_TABLE2.from_address(ptr.value).Table
            ]

    finally:
        FreeMibTable(ptr)

################################################################################

def gateways(version=0):
    any4 = _iaddr.IPv4Address("0.0.0.0") # noqa: S104
    any6 = _iaddr.IPv6Address("::")
    result = _defdict(list)
    for row in GetIpForwardTable2(version):
        if row.dest_pfx.prefix_len:
            continue
        if row.next_hop.version == 4:
            if row.next_hop == any4:
                continue
        elif row.next_hop.version == 6:
            if row.next_hop == any6:
                continue
        else:
            continue

        result[row.luid].append(row.next_hop)
    return dict(result)  # no more default values

################################################################################

_ConvertInterfaceGuidToLuid = _iph.fun_fact(
    "ConvertInterfaceGuidToLuid",
    (DWORD, PGUID, PULONGLONG)
    )

def ConvertInterfaceGuidToLuid(guid):
    guid = GUID(guid)
    luid = ULONGLONG()
    raise_on_err(_ConvertInterfaceGuidToLuid(ref(guid), ref(luid)))
    return luid.value

################################################################################

_ConvertInterfaceIndexToLuid = _iph.fun_fact(
    "ConvertInterfaceIndexToLuid",
    (DWORD, ULONG, PULONGLONG)
    )

def ConvertInterfaceIndexToLuid(idx):
    luid = ULONGLONG()
    raise_on_err(_ConvertInterfaceIndexToLuid(idx, ref(luid)))
    return luid.value

################################################################################

_ConvertInterfaceLuidToAlias = _iph.fun_fact(
    "ConvertInterfaceLuidToAlias",
    (DWORD, PULONGLONG, PWSTR, SIZE_T)
    )

IF_MAX_STRING_SIZE = 256

def ConvertInterfaceLuidToAlias(luid):
    luid = ULONGLONG(luid)
    size = SIZE_T(IF_MAX_STRING_SIZE + 1)
    alias = string_buffer(size.value)
    raise_on_err(_ConvertInterfaceLuidToAlias(ref(luid), alias, size))
    return alias.value

################################################################################

_ConvertInterfaceLuidToName = _iph.fun_fact(
    "ConvertInterfaceLuidToNameW",
    (DWORD, PULONGLONG, PWSTR, SIZE_T)
    )

def ConvertInterfaceLuidToName(luid):
    luid = ULONGLONG(luid)
    size = SIZE_T(IF_MAX_STRING_SIZE + 1)
    name = string_buffer(size.value)
    raise_on_err(_ConvertInterfaceLuidToName(ref(luid), name, size))
    return name.value

################################################################################
