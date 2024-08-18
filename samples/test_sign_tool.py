################################################################################
#
# Copyright 2021-2024 Rocco Matano
# SPDX-License-Identifier: MIT
#
################################################################################

import sys
import shutil
import pathlib
import contextlib
import subprocess

DEFAULT_PREFIX = "$default_prefix$"
prefix = sys.argv[1] if len(sys.argv) >= 2 else DEFAULT_PREFIX
tool = pathlib.Path(__file__).resolve().parent / "rm_sign_tool.py"

def run(*args):
    cmd = [sys.executable, tool]
    cmd.extend(map(str, args))
    subprocess.run(cmd, check=True)

def unlink(pth):
    with contextlib.suppress(OSError):
        pth.unlink()

private = pathlib.Path(f"{prefix}.private.key")
public = pathlib.Path(f"{prefix}.public.key")
signature = pathlib.Path(f"{prefix}.{tool.name}.sig")
fake = pathlib.Path(f"{prefix}.{tool.name}.fake")

try:
    print("going to create keys")
    run("create", private, public)
    print("created keys\n")

    print("going to sign hash")
    run("sign", "-k", private, "-s", signature, tool)
    print("created signature\n")

    print("going to verify hash")
    print("-> ", end="")
    sys.stdout.flush()
    run("verify", "-k", public, "-s", signature, tool)
    print("done verification\n")

    print("demonstrating verification failure")
    print("-> ", end="")
    sys.stdout.flush()
    shutil.copyfile(tool, fake)
    with open(fake, "at") as f:
        f.write("\0")
    run("verify", "-k", public, "-s", signature, fake)
    print("done demonstration\n")
finally:
    if prefix == DEFAULT_PREFIX:
        unlink(private)
        unlink(public)
        unlink(signature)
        unlink(fake)
