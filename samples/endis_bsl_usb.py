################################################################################
#
# Copyright 2021-2024 Rocco Matano
# SPDX-License-Identifier: MIT
#
################################################################################

# Note: This sample will only do something meaningful if there is a
# Basler-USB-camera (https://www.baslerweb.com/) connected and the related
# driver installed.

import sys
import time
import msvcrt
from ctwin32 import setupapi, shell, advapi

################################################################################

def clear_keys():
    # Remove any keys that are present in the input queue.
    while msvcrt.kbhit():
        msvcrt.getch()

################################################################################

def main():
    print("press any key to stop...\n")

    guid = setupapi.SetupDiClassGuidsFromNameEx("PylonUSB")[0]

    # In a loop keep disabling and enabling all devices that belong to the
    # above device class until a key is pressed.

    clear_keys()
    while not msvcrt.kbhit():
        setupapi.disable_devices(guid)
        print("disabled")
        time.sleep(0.3)
        setupapi.enable_devices(guid)
        print("enabled")
        # Enabling is faster. So we wait a bit longer to get a duty cycle of
        # approx. 50%.
        time.sleep(1)

    clear_keys()

################################################################################

if __name__ == "__main__":

    # Enabling and disabling devices requires administrative privileges.
    if not advapi.running_as_admin():
        shell.elevate(sys.executable, __file__)
    else:
        main()

################################################################################
