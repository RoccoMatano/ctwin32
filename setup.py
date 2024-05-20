import sys
import argparse
from setuptools import setup
from wheel.bdist_wheel import bdist_wheel

################################################################################

# trying to build on non Windows OS is useless
if sys.platform != "win32":
    raise OSError("building ctwin32 on non Windows OS is futile")

################################################################################

# enable setting the platform tag from the outside

parser = argparse.ArgumentParser(add_help=False)
parser.add_argument("-p", "--platform-name", default="")
args, remain = parser.parse_known_args()
remain.insert(0, sys.argv[0])
sys.argv = remain
PLATFORM_NAME = args.platform_name

class hacked_bdist_wheel(bdist_wheel):
    def get_tag(self):
        impl, abi_tag, platform = super().get_tag()
        return (impl, abi_tag, PLATFORM_NAME if PLATFORM_NAME else platform)

################################################################################

setup(cmdclass={"bdist_wheel": hacked_bdist_wheel})

################################################################################
