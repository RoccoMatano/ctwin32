# ![logo](https://raw.githubusercontent.com/RoccoMatano/ctwin32/master/doc/images/ctwin32.ico) ctwin32

[![winonly](https://img.shields.io/badge/Windows-0078D6?style=plastic&logo=windows)](.)
[![PyPI - Version](https://img.shields.io/pypi/v/ctwin32.svg)](https://pypi.org/project/ctwin32)
[![PyPI - Python Version](https://img.shields.io/pypi/pyversions/ctwin32.svg)](https://pypi.org/project/ctwin32)
[![License - MIT](https://img.shields.io/badge/license-MIT-green)](https://spdx.org/licenses/MIT.html)
[![PyPI - Stats](https://img.shields.io/pypi/dm/ctwin32)](https://pypistats.org/packages/ctwin32)

-----

ctwin32 is a pure Python module, that wraps some Windows APIs ([win32](
https://learn.microsoft.com/en-us/windows/win32/api/)) by using
[ctypes](https://docs.python.org/3/library/ctypes.html). Since it is my personal
playground, the selection of supported APIs and the way those are wrapped are
solely dictated by my needs and preferences.

ctwin32 is *__definitely__* not a replacement for
[pywin32](https://pypi.org/project/pywin32/), although it serves that purpose
for me (in conjunction with [comtypes](https://pypi.org/project/comtypes/)).
Compared with pywin32 the coverage of ctwin32 is downright tiny.

While there is already another Python module that does something very similar
to ctwin32 ([pywin32-ctypes](https://github.com/enthought/pywin32-ctypes)),
it has a different purpose (namely to serve the internal needs of its
[creator](https://www.enthought.com/)).

See the
[samples directory](https://github.com/RoccoMatano/ctwin32/tree/master/samples)
for several instances of how ctwin32 can be used.

-----

Note: Even though ctwin32 is a pure Python module, it can of course only be used
on Windows. For the first three years or so, packages were tagged with the
Windows platform tags to prevent
[pip](https://packaging.python.org/tutorials/installing-packages/) from using
them on other operating systems. However, it became futile to try to prevent
this when after only one year the `sdist` package was also released. In the
absence of suitable wheel packages for other operating systems, this would mean
that `pip install ctwin32` would now use the `sdist` package to install
`ctwin32` anyway. Therefore, a universal wheel is now distributed and it is
up to the user to be smart enough to use it on Windows only.
