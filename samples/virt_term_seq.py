################################################################################
#
# Copyright 2021-2023 Rocco Matano
#
# Permission is hereby granted, free of charge, to any person obtaining a
# copy of this software and associated documentation files (the "Software"),
# to deal in the Software without restriction, including without limitation
# the rights to use, copy, modify, merge, publish, distribute, sublicense,
# and/or sell copies of the Software, and to permit persons to whom the
# Software is furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included
# in all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
# THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
# FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
# DEALINGS IN THE SOFTWARE.
#
################################################################################
#
# This example demonstrates how to make a console window of a current Windows
# version (Win10 >= 1909?) interpret 'virtual terminal sequences'. It is
# derived from
# https://learn.microsoft.com/en-us/windows/console/console-virtual-terminal-sequences
#
################################################################################

from ctwin32 import kernel

# enable 'virtual terminal sequences'
kernel.enable_virt_term()

print("\x1b[31mThis text has a red foreground using SGR.31.\r\n")
print("\x1b[1mThis text has a bright (bold) red foreground using SGR.1 to affect the previous color setting.\r\n")
print("\x1b[mThis text has returned to default colors using SGR.0 implicitly.\r\n")
print("\x1b[34;46mThis text shows the foreground and background change at the same time.\r\n")
print("\x1b[0mThis text has returned to default colors using SGR.0 explicitly.\r\n")
print("\x1b[31;32;33;34;35;36;101;102;103;104;105;106;107mThis text attempts to apply many colors in the same command. Note the colors are applied from left to right so only the right-most option of foreground cyan (SGR.36) and background bright white (SGR.107) is effective.\r\n")
print("\x1b[39mThis text has restored the foreground color only.\r\n")
print("\x1b[49mThis text has restored the background color only.\r\n")
