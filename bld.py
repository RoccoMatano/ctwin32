import sys
import subprocess
import argparse
from pathlib import Path
import setuptools.build_meta as backend

################################################################################

THIS_SCRIPT = Path(__file__).resolve()

################################################################################

def perform_action(args):
    if args.action not in ("build_sdist", "build_wheel"):
        raise ValueError(f"unknown action: '{args.action}'")
    getattr(backend, args.action)(str(THIS_SCRIPT.parent / "dist"))

################################################################################

def initiate_actions():
    # distutils - that setuptools.build_meta is based on - currently do NOT
    # support to execute more than one action per process. Therefore we
    # have to use a child process for every action.
    common = [sys.executable, str(THIS_SCRIPT), "--action"]
    subprocess.run([*common, "build_sdist"], check=True)
    subprocess.run([*common, "build_wheel"], check=True)

################################################################################

if __name__ == "__main__":
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("--action")
    args = parser.parse_args()
    if not args.action:
        initiate_actions()
    else:
        perform_action(args)

################################################################################
