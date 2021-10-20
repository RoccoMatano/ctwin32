import sys
import subprocess

subprocess.run([sys.executable, 'setup.py', 'clean', '--all'])
subprocess.run([sys.executable, 'setup.py', 'bdist_wheel'])
