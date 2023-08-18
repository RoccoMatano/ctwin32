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

    opt = {"--build-option": args.build_option} if args.build_option else {}
    getattr(backend, args.action)(str(THIS_SCRIPT.parent / "dist"), opt)

################################################################################

def initiate_actions():
    # distutils - that setuptools.build_meta is based on - currently do NOT
    # support to execute more than one action per process. Therefore we
    # have to use a child process for every action.
    common = [sys.executable, str(THIS_SCRIPT), "--action"]
    subprocess.run([*common, "build_sdist"], check=True)
    for tag in ("win_amd64", "win32", "win_arm64"):
        cmd = [*common, "build_wheel", "--build-option", f"-p {tag}"]
        subprocess.run(cmd, check=True)

################################################################################

if __name__ == "__main__":
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("--action")
    parser.add_argument("--build-option")
    args = parser.parse_args()
    if not args.action:
        initiate_actions()
    else:
        perform_action(args)

################################################################################
