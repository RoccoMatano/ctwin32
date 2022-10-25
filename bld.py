import sys
import subprocess
from pathlib import Path

subprocess.run([sys.executable, 'setup.py', 'clean', '--all'])
subprocess.run([sys.executable, 'setup.py', 'sdist'])

bdir = Path(__file__).parent / "build"
platform_file = bdir / "platform.tag"
bdir.mkdir(exist_ok=True)

for tag in ("win_amd64", "win32", "win_arm64"):
    with open(platform_file, "wt") as f:
        f.write(tag)
    subprocess.run([sys.executable, 'setup.py', 'bdist_wheel'])
