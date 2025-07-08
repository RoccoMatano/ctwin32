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

ctwin32 is not a replacement for
[pywin32](https://pypi.org/project/pywin32/), although it serves that purpose
for me (in conjunction with [comtypes](https://pypi.org/project/comtypes/)).
Compared with pywin32 the coverage of ctwin32 is downright tiny.

Here is an example of a classic ‘Hello world’ program:
```python
from ctwin32 import user, gdi, wndcls, wtypes
from ctwin32 import WM_CREATE, WM_PAINT, WM_DESTROY
from ctwin32 import DT_CENTER, DT_SINGLELINE, DT_VCENTER

class HelloWnd(wndcls.SimpleWnd):

    DT_FLAGS = DT_CENTER | DT_SINGLELINE | DT_VCENTER
    MSG = "Hello from ctwin32!"

    def on_message(self, msg, wp, lp):

        if msg == WM_CREATE:
            lf = wtypes.LOGFONT(
                lfHeight=-72,
                lfFaceName = "MS Shell Dlg"
                )
            self.font = gdi.CreateFontIndirect(lf)
            return 0

        if msg == WM_PAINT:
            hdc, ps = self.begin_paint()
            oldfont = gdi.SelectObject(hdc, self.font)
            user.DrawText(hdc, self.MSG, self.client_rect(), self.DT_FLAGS)
            gdi.SelectObject(hdc, oldfont)
            self.end_paint(ps)
            return 0

        if msg == WM_DESTROY:
            gdi.DeleteObject(self.font)
            user.PostQuitMessage(0)
            return 0

        return self.def_win_proc(msg, wp, lp)

if __name__ == "__main__":

    icon = wndcls.load_ctwin32_ico()
    wnd = HelloWnd(wndcls.WndCreateParams("Hello Window", icon))
    wnd.show()

    while msg := user.GetMessage():
        user.TranslateMessage(msg)
        user.DispatchMessage(msg)
```

See the
[samples directory](https://github.com/RoccoMatano/ctwin32/tree/master/samples)
for several instances of how ctwin32 can be used.

While there is already another Python module that does something very similar
to ctwin32 ([pywin32-ctypes](https://github.com/enthought/pywin32-ctypes)),
it has a different purpose (namely to serve the internal needs of its
[creator](https://www.enthought.com/)).

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
