################################################################################
#
# Copyright 2021-2023 Rocco Matano
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
