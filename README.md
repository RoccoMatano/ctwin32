# ![](https://raw.githubusercontent.com/RoccoMatano/ctwin32/master/doc/images/ctwin32.ico) ctwin32


[![PyPI - Version](https://img.shields.io/pypi/v/ctwin32.svg)](https://pypi.org/project/ctwin32)
[![PyPI - Python Version](https://img.shields.io/pypi/pyversions/ctwin32.svg)](https://pypi.org/project/ctwin32)
[![License - MIT](https://img.shields.io/badge/license-MIT-green)](https://spdx.org/licenses/MIT.html)

-----

ctwin32 is a pure Python module, that wraps some Windows APIs (win32) by using
[ctypes](https://docs.python.org/3/library/ctypes.html). Since it is my personal
playground, the selection of supported APIs and the way those are wrapped are
solely dictated by my needs and preferences.

ctwin32 is *__definitely__* not a replacement for [pywin32](https://pypi.org/project/pywin32/),
although it serves that purpose for me (in conjunction with [comtypes](https://pypi.org/project/comtypes/)).
Compared with pywin32 the coverage of ctwin32 is less than tiny.

-----

Note: Even though ctwin32 is a pure Python module, it can of course only be used
on Windows. Therefore, the wheel packages provided are intentionally tagged with
the x86, x64 and and arm64 Windows platform tags (in terms of content, those are
the same). This is just to keep
[pip](https://packaging.python.org/tutorials/installing-packages/)
from installing them on a non-Windows OS.
