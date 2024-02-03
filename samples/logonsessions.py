################################################################################
#
# Copyright 2021-2024 Rocco Matano
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

# inspired by
# https://docs.microsoft.com/en-us/sysinternals/downloads/logonsessions

import sys
from ctwin32.advapi import running_as_admin
from ctwin32.secur import LsaEnumerateLogonSessions

if __name__ == "__main__":
    if not running_as_admin():
        m = "Need to run as administrator in order to enumerate logon sessions."
        print(m, file=sys.stderr)
        sys.exit(1)

    verbose = "-verbose" in sys.argv
    lotypes = [
        "(none)",
        "???UNDEFINED???",
        "Interactive",
        "Network",
        "Batch",
        "Service",
        "Proxy",
        "Unlock",
        "NetworkCleartext",
        "NewCredentials",
        "RemoteInteractive",
        "CachedInteractive",
        "CachedRemoteInteractive",
        "CachedUnlock"
        ]

    def fmtt(dt):
        return dt.isoformat(" ", "seconds")

    for idx, ses in enumerate(LsaEnumerateLogonSessions()):
        lot = (
            lotypes[ses.LogonType] if 0 <= ses.LogonType < len(lotypes)
            else f"{ses.LogonType} (unknown)"
            )
        print(f"\n[{idx}] Logon session {ses.LogonId:016x}")
        print(f"    User name:    {ses.UserName}")
        print(f"    Auth Package: {ses.AuthenticationPackage}")
        print(f"    Logon type:   {lot}")
        print(f"    Session:      {ses.Session}")
        print(f"    Logon time:   {fmtt(ses.LogonTime)}")
        print(f"    Logon server: {ses.LogonServer}")
        print(f"    User flags:   0x{ses.UserFlags:x}")

        if not verbose:
            continue

        lf = ses.LastLogonInfo.FailedAttemptCountSinceLastSuccessfulLogon
        print(f"    DNS domain:   {ses.DnsDomainName}")
        print(f"    UPN:          {ses.Upn}")
        print(f"    Last suc lo:  {ses.LastLogonInfo.LastSuccessfulLogon}")
        print(f"    Last fail lo: {ses.LastLogonInfo.LastFailedLogon}")
        print(f"    Failed cnt:   {lf}")
        print(f"    Logon script: {ses.LogonScript}")
        print(f"    Prof. path:   {ses.ProfilePath}")
        print(f"    Home dir:     {ses.HomeDirectory}")
        print(f"    Home drive:   {ses.HomeDirectoryDrive}")
        print(f"    Logoff time:  {fmtt(ses.LogoffTime)}")
        print(f"    Kickoff time: {fmtt(ses.KickOffTime)}")
        print(f"    Pw last set:  {fmtt(ses.PasswordLastSet)}")
        print(f"    Pw can chng:  {fmtt(ses.PasswordCanChange)}")
        print(f"    Pw must chng: {fmtt(ses.PasswordMustChange)}")
