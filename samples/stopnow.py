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

import sys
import argparse
from ctwin32 import (
    ntdll,
    user,
    misc,
    EWX_POWEROFF,
    EWX_REBOOT,
    EWX_LOGOFF,
    SE_SHUTDOWN_PRIVILEGE,
    WTSActive
    )

################################################################################

def parse_args():
    ape = argparse.ArgumentParser()
    grp = ape.add_mutually_exclusive_group(required=True)
    grp.add_argument("-s", "--shutdown", action="store_true")
    grp.add_argument("-r", "--restart", action="store_true")
    grp.add_argument("-l", "--logout", action="store_true")
    grp.add_argument("-e", "--hibernate", action="store_true")
    grp.add_argument("-y", "--standby", action="store_true")
    grp.add_argument("-k", "--lock", action="store_true")
    grp.add_argument("-d", "--disconnect", action="store_true")
    return ape.parse_args()

################################################################################

def disconnect_rdp():
    for info in misc.WTSEnumerateSessions():
        if info.State == WTSActive:
            if info.pWinStationName.startswith("RDP-Tcp"):
                misc.WTSDisconnectSession(info.SessionId)

################################################################################

def main():
    args = parse_args()

    if args.shutdown or args.restart:
        try:
            ntdll.RtlAdjustPrivilege(SE_SHUTDOWN_PRIVILEGE, True)
        except OSError as e:
            print(e, file=sys.stderr)
            sys.exit(1)

    if args.shutdown:
        user.ExitWindowsEx(EWX_POWEROFF, 0)

    elif args.restart:
        user.ExitWindowsEx(EWX_REBOOT, 0)

    elif args.logout:
        user.ExitWindowsEx(EWX_LOGOFF, 0)

    elif args.hibernate:
        misc.SetSuspendState(True, False, False)

    elif args.standby:
        misc.SetSuspendState(False, False, False)

    elif args.lock:
        user.LockWorkStation()

    elif args.disconnect:
        disconnect_rdp()

################################################################################

if __name__ == "__main__":
    main()

################################################################################
