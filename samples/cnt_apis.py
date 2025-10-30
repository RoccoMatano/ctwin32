################################################################################
#
# Copyright 2021-2025 Rocco Matano
# SPDX-License-Identifier: MIT
#
################################################################################
#
# This script uses a simple heuristic to determine the number of APIs wrapped
# by ctwin32.
#
################################################################################

from pathlib import Path
from types import FunctionType
from importlib import import_module
import ctwin32

################################################################################

def is_api(mod, name):
    obj = getattr(mod, name)
    omod = getattr(obj, "__module__", "ctypes")
    return (
        name[0] <= "Z" and
        omod not in ("ctypes", "ctwin32.wtypes") and
        isinstance(obj, (FunctionType, ctwin32._ApiFuncPtr))
        )

################################################################################

apis = set()
for mod_file in Path(ctwin32.__file__).parent.glob("*.py"):
    mod = import_module(f".{mod_file.stem}", "ctwin32")
    apis |= {name for name in dir(mod) if is_api(mod, name)}

print(f"Number of APIs: {len(apis)}\n")
for a in sorted(apis):
    print(a)
