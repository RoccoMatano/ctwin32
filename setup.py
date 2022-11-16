import sys
from pathlib import Path
from setuptools import setup
from ctwin32 import version

################################################################################

# trying to build on non Windows OS is useless
if sys.platform != "win32":
    raise OSError("building ctwin32 on non Windows OS is futile")

################################################################################

# hack to ensure platform tag can be set from the outside
from wheel.bdist_wheel import bdist_wheel

class hacked_bdist_wheel(bdist_wheel):
    def get_tag(self):
        impl, abi_tag, plat_name = bdist_wheel.get_tag(self)
        platform_file = Path(__file__).parent / "build" / "platform.tag"
        try:
            with open(platform_file, "rt") as f:
                plat_name = f.read().strip()
        except Exception:
            pass
        return (impl, abi_tag, plat_name)

################################################################################

github_url = "https://github.com/RoccoMatano/ctwin32"
params = {
    "cmdclass": {'bdist_wheel': hacked_bdist_wheel},
    "name": "ctwin32",
    "version": version,
    "description": "Access selected win32 APIs through ctypes.",
    "long_description_content_type": "text/markdown",
    "author": "Rocco Matano",
    "license": "MIT License",
    "packages": ["ctwin32"],
    "install_requires": [],
    "author_email": " ",
    "platforms": ["win32"],
    "url": github_url,
    "project_urls": {"Changelog": f"{github_url}/blob/master/changelog.md"},
    "python_requires": ">=3.6",
    "classifiers": [
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python",
        "Operating System :: Microsoft :: Windows",
        "Environment :: Win32 (MS Windows)",
        "Intended Audience :: Developers",
        "Programming Language :: Python :: 3.6",
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        ]
    }

with open("README.md", "rt") as readme:
    params["long_description"] = readme.read()

setup(**params)

################################################################################
