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
#
# This sample was inspired by
# https://www.codeproject.com/Articles/5363023/How-to-Restart-a-USB-Port
#
################################################################################

import sys
import ctypes
from ctwin32 import (
    advapi,
    cfgmgr,
    kernel,
    ntdll,
    setupapi,
    CTL_CODE,
    ERROR_PATH_NOT_FOUND,
    FILE_ANY_ACCESS,
    FILE_DEVICE_UNKNOWN,
    METHOD_BUFFERED,
    SPDRP_LOCATION_INFORMATION,
    )
from ctwin32.wtypes import (
    GUID,
    ULONG,
    )

################################################################################

class USB_CYCLE_PORT_PARAMS(ctypes.Structure):
    _fields_ = (
        ("ConnectionIndex", ULONG),
        ("StatusReturned", ULONG),
        )

################################################################################

def restart_usb_port(device_id):
    # Step 1: find the USB device in the device manager
    devinst = cfgmgr.CM_Locate_DevNode(device_id)

    # Step 2: Determine the USB port number.
    # SPDRP codes are zero based while CM_DRP codes are one based
    prop = SPDRP_LOCATION_INFORMATION + 1
    location, _ = cfgmgr.CM_Get_DevNode_Registry_Property(devinst, prop)
    # must be like "Port_#0004.Hub_#0014"
    try:
        portnumber = int(location.removeprefix("Port_#").split(".")[0])
    except ValueError as e:
        e.args = (f"{device_id} -> not a direct child of a hub",)
        raise

    # Step 3: the USB hub is the parent device
    hub = cfgmgr.CM_Get_Parent(devinst)

    # Step 4: scan all USB hubs for this devinst to get its device path
    guid = GUID("f18a0e88-c30c-11d0-8815-00a0c906bed8")
    for info_set, did in setupapi.enum_dev_interfaces(guid):
        path, deinda = setupapi.SetupDiGetDeviceInterfaceDetail(info_set, did)
        if deinda.DevInst == hub:
            break
    else:
        raise ctypes.WinError(ERROR_PATH_NOT_FOUND)

    # Step 5: open the hub
    with kernel.create_file(path) as hhub:

        # Step 6: call IOCTL_USB_HUB_CYCLE_PORT
        FILE_DEVICE_USB = FILE_DEVICE_UNKNOWN
        USB_HUB_CYCLE_PORT = 273
        ioctl = CTL_CODE(
            FILE_DEVICE_USB,
            USB_HUB_CYCLE_PORT,
            METHOD_BUFFERED,
            FILE_ANY_ACCESS
            )
        olen = ctypes.sizeof(USB_CYCLE_PORT_PARAMS)
        params = USB_CYCLE_PORT_PARAMS(portnumber, 0)
        buf = kernel.DeviceIoControl(hhub, ioctl, params, olen)

    result = USB_CYCLE_PORT_PARAMS.from_buffer(buf)
    ntdll.raise_failed_status(result.StatusReturned)

################################################################################

if __name__ == "__main__":
    if advapi.running_as_admin():
        # first arg has to be a `device ID`, e.g.
        # "USB\VID_046D&PID_0825\0FE2C940" (a direct child of a hub)
        # since this contains a `&` it needs to be quoted on the command line.
        restart_usb_port(sys.argv[1])
    else:
        print("restarting an USB port requires administrative privileges.")

################################################################################
