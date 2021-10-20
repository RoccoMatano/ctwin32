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

# demonstrate device enumerators from setupapi

from ctwin32.setupapi import (
    enum_info_set,
    SetupDiGetClassDevs,
    SetupDiGetDeviceInstanceId,
    get_device_enumerators,
    get_device_classes,
    SetupDiClassNameFromGuid,
    desc_from_info_set,
    )

for e in get_device_enumerators():
    print(f"\nEnumerator {e}:")
    for iset, ddat in enum_info_set(SetupDiGetClassDevs(enumerator=e)):
        try:
            desc = desc_from_info_set(iset, ddat)
        except OSError:
            desc = "UNKNOWN"
        iid = SetupDiGetDeviceInstanceId(iset, ddat)
        print(f"  {desc:50s} {iid}")

for g in get_device_classes():
    cn = SetupDiClassNameFromGuid(g)
    print(f"\nDevice class {g}, {cn}:")
    for iset, ddat in enum_info_set(SetupDiGetClassDevs(guid=g)):
        try:
            desc = desc_from_info_set(iset, ddat)
        except OSError:
            desc = "UNKNOWN"
        iid = SetupDiGetDeviceInstanceId(iset, ddat)
        print(f"  {desc:50s} {iid}")
