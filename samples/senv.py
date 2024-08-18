################################################################################
#
# Copyright 2021-2024 Rocco Matano
# SPDX-License-Identifier: MIT
#
################################################################################

import sys
import argparse
from ctwin32 import (
    ctypes,
    user,
    advapi,
    shell,
    wtypes,
    HWND_BROADCAST,
    WM_SETTINGCHANGE,
    SMTO_NORMAL,
    REG_SZ,
    REG_EXPAND_SZ,
    KEY_READ,
    KEY_WRITE,
    )

################################################################################

def env_var_root(system=False, access=KEY_READ):
    if system:
        pth = r"SYSTEM\CurrentControlSet\Control\Session Manager"
        return advapi.RegOpenKeyEx(advapi.HKLM, pth, access)
    else:
        return advapi.HKCU

################################################################################

def env_var_key(root, access=KEY_READ):
    return advapi.RegOpenKeyEx(root, "Environment", access)

################################################################################

def is_persistent_env_var(name, system=False):
    with env_var_root(system) as root:
        with env_var_key(root) as key:
            result = False
            try:
                val, typ = advapi.RegQueryValueEx(key, name)
                result = (typ in (REG_SZ, REG_EXPAND_SZ)) and bool(val)
            except OSError:
                pass
            return result

################################################################################

def broadcast_env_change():
    estr = wtypes.string_buffer("Environment")
    user.SendMessageTimeout(
        HWND_BROADCAST,
        WM_SETTINGCHANGE,
        0,
        ctypes.addressof(estr),
        SMTO_NORMAL,
        500
        )

################################################################################

def persist_env_var(name, value, system=False, do_broadcast=False):
    access = KEY_WRITE | KEY_READ
    with env_var_root(system, access) as root:
        with env_var_key(root, access) as key:
            if not value:
                advapi.RegDeleteValue(key, name)
            else:
                advapi.reg_set_str(key, name, value)
        if do_broadcast:
            broadcast_env_change()

################################################################################

def persist_user_env_block(nv_dict, system=False):
    for n, v in nv_dict.items():
        persist_env_var(n, v, system, False)
    broadcast_env_change()

################################################################################

def get_env_block(system=False):
    with env_var_root(system) as root:
        with env_var_key(root, KEY_READ) as key:
            return {
                nam: val for nam, val, typ in advapi.reg_enum_values(key)
                if typ in (REG_SZ, REG_EXPAND_SZ)
                }

################################################################################

def parse_args():
    ape = argparse.ArgumentParser(
        description="set environment variables persistently (like setx)"
        )
    ape.add_argument(
        "-s",
        "--system",
        action="store_true",
        help="set system variable (as opposed to user variable)"
        )
    ape.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="print final variables"
        )
    ape.add_argument("name", help="name of variable")
    ape.add_argument(
        "value",
        help="value of variable (omitting it will delete the variable)",
        nargs="?",
        default="",
        )
    return ape.parse_args()

################################################################################

def main(name, value, system, verbose):
    persist_env_var(name, value, system, True)
    if verbose:
        print(f"variables for {'system' if args.system else 'user'}:")
        for k, v in get_env_block(args.system).items():
            print(f"    {k} = {v}")

################################################################################

if __name__ == "__main__":
    args = parse_args()

    # Setting system variables requires administrative privileges.
    if args.system and not advapi.running_as_admin():
        shell.elevate(sys.executable, *sys.argv)
    else:
        main(args.name, args.value, args.system, args.verbose)

################################################################################
