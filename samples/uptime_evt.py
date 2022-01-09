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

from ctwin32 import advapi
import datetime

BOOT_EVENT_ID = 6009

def boot_time():
    log = advapi.OpenEventLog(None, "System")
    try:
        some_events = advapi.ReadEventLog(log)
        while some_events:
            for e in some_events:
                if (e.EventID & 0xffff) == BOOT_EVENT_ID:
                    return e.TimeGenerated
            some_events = advapi.ReadEventLog(log)
    finally:
        advapi.CloseEventLog(log)

def up_time():
    result = boot_time()
    if result:
        result = datetime.datetime.now() - result
    return result

if __name__ == "__main__":
    print(f"This computer was booted on {boot_time()}.")
    print(f"It has been running for {up_time()}.")
