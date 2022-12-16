import sys
import subprocess
from pathlib import Path

def setup(*args):
    subprocess.run([sys.executable, 'setup.py'] + list(args))

setup('clean', '--all')
setup('sdist')
for tag in ("win_amd64", "win32", "win_arm64"):
    setup('-p', tag, 'bdist_wheel')
