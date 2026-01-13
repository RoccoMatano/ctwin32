################################################################################
#
# Copyright 2021-2026 Rocco Matano
# SPDX-License-Identifier: MIT
#
################################################################################

import sys
import time
import subprocess
from ctwin32 import kernel, UNICODE_STRING_MAX_CHARS

################################################################################

class NamedPipe:

    class ServerConnection:

        def __init__(self, hdl):
            self.hdl = hdl

        def __enter__(self):
            kernel.ConnectNamedPipe(self.hdl)
            return self

        def __exit__(self, typ, val, tb):
            kernel.FlushFileBuffers(self.hdl)
            kernel.DisconnectNamedPipe(self.hdl)
            self.hdl = None

    def __init__(self, name, *, server_end=False):
        self.name = name
        if server_end:
            self.server_end = True
            self.hdl = kernel.create_named_pipe(self.name)
        else:
            self.server_end = False
            self.hdl = kernel.create_file(self.name)

    def __enter__(self):
        return self

    def __exit__(self, typ, val, tb):
        self.hdl.close()
        self.hdl = None

    def connect(self):
        if not self.server_end:
            raise ValueError("not server")
        return self.ServerConnection(self.hdl)

    def read(self):
        return kernel.read_file_text(self.hdl, UNICODE_STRING_MAX_CHARS)

    def write(self, txt):
        kernel.write_file_text(self.hdl, txt)

################################################################################

PIPE_NAME = r"\\.\pipe\b52s_6060842"
CMD_STOP = "++stop++stop++stop++"
CMD_START = "++start++start++start++"

################################################################################

def run_server():

    print("server was started")

    with NamedPipe(PIPE_NAME, server_end=True) as pipe:
        while True:
            print("server is waiting for request")
            with pipe.connect():
                print("server got client connection")
                try:
                    txt = pipe.read()
                except BrokenPipeError:
                    print("server broken pipe")
                    continue
                print(f"server received '{txt}'")
                pipe.write("".join(reversed(txt)))
                if txt == CMD_STOP:
                    print("server stops")
                    break

################################################################################

def main(args):

    if args and args[0] == CMD_START:
        run_server()
        return

    try:
        print("client trying to open pipe")
        pipe = NamedPipe(PIPE_NAME)
    except FileNotFoundError:
        if not args:
            print("server not running, no args -> nothing to do")
            return
        print("starting server")
        subprocess.Popen([sys.executable, __file__, CMD_START])
        time.sleep(0.1)
        pipe = NamedPipe(PIPE_NAME)

    with pipe:
        if not args:
            args = [CMD_STOP]
        pipe.write(" ".join(args))
        txt = pipe.read()
        print(f"client received '{txt}'")

################################################################################

if __name__ == "__main__":
    main(sys.argv[1:])

################################################################################
