from setuptools import setup
from ctwin32 import version

################################################################################

# hack to ensure two things:
#   - platform tag can be set from the outside
#   - temporaries are kept to be able to build several wheels
from wheel.bdist_wheel import bdist_wheel
class hacked_bdist_wheel(bdist_wheel):
    def get_tag(self):
        # get pristine tags
        impl, abi_tag, plat_name = bdist_wheel.get_tag(self)

        #overwrite platform tag from global
        plat_name = global_platform_tag
        # keep temporaries, so we can build another wheel from them
        self.keep_temp = True

        return (impl, abi_tag, plat_name)

################################################################################

empty = " "
params = {
    "cmdclass": {'bdist_wheel': hacked_bdist_wheel},
    "name" : "ctwin32",
    "version" : version,
    "description" : "Access selected win32 APIs through ctypes.",
    "long_description_content_type": "text/markdown",
    "author" : "Rocco Matano",
    "license" : "MIT License",
    "packages": ["ctwin32"],
    "install_requires" : [],
    "author_email": empty,
    "platforms": ["win32"],
    "url": "https://github.com/RoccoMatano/ctwin32",
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
        ]
    }

with open("README.md", "rt") as readme:
    params["long_description"] = readme.read()

# Apply Windows platform tags to make clear, that ctwin32 can only be used on
# Windows.

global_platform_tag = "win_amd64"
setup(**params)

global_platform_tag = "win32"
setup(**params)

################################################################################
