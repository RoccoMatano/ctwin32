################################################################################
#
# Copyright 2021-2024 Rocco Matano
# SPDX-License-Identifier: MIT
#
################################################################################

from ctwin32 import iphlpapi

################################################################################

if_types = {
    1: "Other",
    6: "Ethernet",
    9: "Token ring",
    23: "PPP",
    24: "Loopback",
    37: "ATM",
    71: "802.11 wireless",
    }

################################################################################

nl_neighbor_states = {
    0: "Unreachable",
    1: "Incomplete",
    2: "Probe",
    3: "Delay",
    4: "Stale",
    5: "Reachable",
    6: "Permanent",
    }

################################################################################

def ift_str(ift):
    if ift in if_types:
        return if_types[ift]
    return f"other ({ift})"

################################################################################

def state_str(state):
    if state in nl_neighbor_states:
        return nl_neighbor_states[state]
    return f"unknown ({state})"

################################################################################

for e in iphlpapi.GetIpNetTable2():
    mac = "-".join(f"{b:02x}" for b in e.phys_addr)
    ift = ift_str(e.if_type)
    st = state_str(e.state)
    print(
        f"idx: {e.index}, {ift:8s}, {st:11s}, MAC: {mac:17s}, IP: {e.addr:s}"
        )

################################################################################
