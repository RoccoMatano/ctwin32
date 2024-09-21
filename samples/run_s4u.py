################################################################################
#
# Copyright 2021-2024 Rocco Matano
# SPDX-License-Identifier: MIT
#
################################################################################
#
# This sample demonstrates password-less logons via 'S4U' (service for user).
#
################################################################################

import sys
import ctypes
from ctwin32 import advapi, kernel, ntdll, secur, user
from ctwin32 import (
    CREATE_NEW_CONSOLE,
    ERROR_NOT_FOUND,
    MAXIMUM_ALLOWED,
    Network,
    PROCESS_QUERY_LIMITED_INFORMATION,
    SE_ASSIGNPRIMARYTOKEN_PRIVILEGE,
    SE_GROUP_ENABLED,
    SE_GROUP_ENABLED_BY_DEFAULT,
    SE_GROUP_LOGON_ID,
    SE_IMPERSONATE_PRIVILEGE,
    SE_TCB_PRIVILEGE,
    SecurityImpersonation,
    TOKEN_DUPLICATE,
    TokenImpersonation,
    UOI_USER_SID,
    WinInteractiveSid,
    WinRestrictedCodeSid,
    )
from ctwin32.wtypes import (
    WCHAR,
    wchar_len_sz,
    WCHAR_SIZE,
    WinError,
    ULONG,
    UNICODE_STRING,
    )

################################################################################

def proc_by_name(name, desired_acc, inherit=False):
    name = name.lower()
    for p in ntdll.enum_processes():
        if name == p.name.lower():
            return kernel.OpenProcess(desired_acc, inherit, p.pid)
    raise WinError(ERROR_NOT_FOUND)

################################################################################

def enable_s4u_privileges():
    required = [SE_TCB_PRIVILEGE, SE_ASSIGNPRIMARYTOKEN_PRIVILEGE]
    try:
        # either we are running in an highly privileged process (e.g. SYSTEM)
        # where we can simply enable the requires privileges...
        advapi.enable_privileges(required)
    except OSError:
        pass
    else:
        return

    # ... or we need to run in a process that is somewhat privileged (e.g.
    # administrator) so we can fetch and impersonate the SYSTEM identity
    advapi.enable_privileges([SE_IMPERSONATE_PRIVILEGE])
    wlo, qli = ("winlogon.exe", PROCESS_QUERY_LIMITED_INFORMATION)
    with proc_by_name(wlo, qli) as proc:
        with advapi.OpenProcessToken(proc, TOKEN_DUPLICATE) as tok:
            dup_tok_args = (
                tok,
                MAXIMUM_ALLOWED,
                kernel.SECURITY_ATTRIBUTES(),
                SecurityImpersonation,
                TokenImpersonation,
                )
            with advapi.DuplicateTokenEx(*dup_tok_args) as dup:
                advapi.enable_token_privileges(dup, required)
                advapi.SetThreadToken(dup)

################################################################################

def kerb_s4u_logon(upn, realm, flags=0):
    """Create a self contained KERB_S4U_LOGON structure as required for
    calling LsaLogonUser().
    """
    wlu = wchar_len_sz(upn)     # aka 'user name'
    wlr = wchar_len_sz(realm)   # aka 'domain name'

    class KERB_S4U_LOGON(ctypes.Structure):
        KerbS4ULogon = 12
        _fields_ = (
            ("MessageType", ULONG),
            ("Flags", ULONG),
            ("ClientUpn", UNICODE_STRING),
            ("ClientRealm", UNICODE_STRING),
            ("upn_buf", WCHAR * wlu),
            ("realm_buf", WCHAR * wlr),
            )

        def __init__(self, upn, realm, flags):
            blu = wlu * WCHAR_SIZE
            blr = wlr * WCHAR_SIZE
            addr = ctypes.addressof(self)
            super().__init__(
                self.KerbS4ULogon,
                flags,
                (blu - WCHAR_SIZE, blu, addr + __class__.upn_buf.offset),
                (blr - WCHAR_SIZE, blr, addr + __class__.realm_buf.offset),
                upn,
                realm
                )

    return KERB_S4U_LOGON(upn, realm, flags)

################################################################################

def get_additional_groups():
    attr2 = SE_GROUP_ENABLED_BY_DEFAULT | SE_GROUP_ENABLED
    attr1 = attr2 | SE_GROUP_LOGON_ID
    sid1 = user.GetUserObjectInformation(
        user.GetProcessWindowStation(),
        UOI_USER_SID
        ).raw
    if not sid1:
        # most likely running in session 0
        sid1 = advapi.CreateWellKnownSid(WinRestrictedCodeSid)
        attr1= attr2
    sid2 = advapi.CreateWellKnownSid(WinInteractiveSid)
    return advapi.make_token_groups(((sid1, attr1), (sid2, attr2)))

################################################################################

def logon_s4u(user, domain, add_groups):
    lsa = secur.LsaConnectUntrusted()
    try:
        auth_pkg = secur.LsaLookupAuthenticationPackage(lsa, "Negotiate")
        ks4u = kerb_s4u_logon(user, domain)
        return secur.LsaLogonUser(
            lsa,
            "run_s4u",
            Network,
            auth_pkg,
            ks4u,
            add_groups,
            "run_s4u",
            )
    finally:
        secur.LsaDeregisterLogonProcess(lsa)

################################################################################

if __name__ == "__main__":
    try:
        enable_s4u_privileges()
    except OSError:
        print("Not enough privileges - try to run as administrator.")
        sys.exit(1)

    name = sys.argv[1]
    lst = name.split("\\", 1)
    domain, name = lst if len(lst) > 1 else (".", name)

    token, _ = logon_s4u(name, domain, get_additional_groups())
    advapi.create_process_as_user(
        token,
        ["cmd.exe", "/K", "whoami /user"],
        CREATE_NEW_CONSOLE
        )

################################################################################

