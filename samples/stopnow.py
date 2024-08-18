################################################################################
#
# Copyright 2021-2024 Rocco Matano
# SPDX-License-Identifier: MIT
#
################################################################################

import sys
import argparse
from ctwin32 import (
    ntdll,
    user,
    powrprof,
    wtsapi,
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
    for info in wtsapi.WTSEnumerateSessions():
        if info.State == WTSActive:
            if info.pWinStationName.startswith("RDP-Tcp"):
                wtsapi.WTSDisconnectSession(info.SessionId)

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
        powrprof.SetSuspendState(True, False, False)

    elif args.standby:
        powrprof.SetSuspendState(False, False, False)

    elif args.lock:
        user.LockWorkStation()

    elif args.disconnect:
        disconnect_rdp()

################################################################################

if __name__ == "__main__":
    main()

################################################################################
