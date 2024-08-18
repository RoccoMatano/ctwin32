################################################################################
#
# Copyright 2021-2024 Rocco Matano
# SPDX-License-Identifier: MIT
#
################################################################################

from ctwin32 import advapi
import datetime

BOOT_EVENT_ID = 6009

def boot_time():
    with advapi.OpenEventLog("System") as log:
        some_events = advapi.ReadEventLog(log)
        while some_events:
            for e in some_events:
                if (e.EventID & 0xffff) == BOOT_EVENT_ID:
                    return e.TimeGenerated
            some_events = advapi.ReadEventLog(log)
    raise OSError("no boot event found")

def up_time(time_boot=None):
    if time_boot is None:
        time_boot = boot_time()
    utime = datetime.datetime.now(time_boot.tzinfo) - time_boot
    # ignore milliseconds
    return datetime.timedelta(seconds=int(utime.total_seconds()))

if __name__ == "__main__":
    t_boot = boot_time()
    print(f"This computer was booted on {t_boot}.")
    print(f"It has been running for {up_time(t_boot)}.")
