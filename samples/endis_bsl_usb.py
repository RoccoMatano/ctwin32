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
