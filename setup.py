import sys
import argparse
from setuptools import setup

################################################################################

# trying to build on non Windows OS is useless
if sys.platform != "win32":
    raise OSError("building ctwin32 on non Windows OS is futile")

################################################################################

parser = argparse.ArgumentParser(add_help=False)
parser.add_argument("-p", "--platform-name", default="")
args, remain = parser.parse_known_args()
remain.insert(0, sys.argv[0])
sys.argv = remain
PLATFORM_NAME = args.platform_name

################################################################################

# hack to ensure platform tag can be set from the outside
from wheel.bdist_wheel import bdist_wheel

class hacked_bdist_wheel(bdist_wheel):
    def get_tag(self):
        impl, abi_tag, platform = super().get_tag()
        return (impl, abi_tag, PLATFORM_NAME if PLATFORM_NAME else platform)

################################################################################

setup(cmdclass={'bdist_wheel': hacked_bdist_wheel})

################################################################################
