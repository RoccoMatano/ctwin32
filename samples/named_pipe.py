################################################################################
#
# Copyright 2021-2024 Rocco Matano
# SPDX-License-Identifier: MIT
#
################################################################################

import sys
import time
import subprocess
from ctwin32 import kernel, UNICODE_STRING_MAX_CHARS

################################################################################

class NamedPipe:

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

    def connect(self):
        if not self.server_end:
            raise ValueError("not server")
        kernel.ConnectNamedPipe(self.hdl)

    def disconnect(self):
        if not self.server_end:
            raise ValueError("not server")
        kernel.FlushFileBuffers(self.hdl)
        kernel.DisconnectNamedPipe(self.hdl)

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
            pipe.connect()
            print("server got client connection")

            try:
                txt = pipe.read()
            except BrokenPipeError:
                print("server broken pipe")
                pipe.disconnect()
                continue
            print(f"server received '{txt}'")
            pipe.write("".join(reversed(txt)))
            pipe.disconnect()
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
