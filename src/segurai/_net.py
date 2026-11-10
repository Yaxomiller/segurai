"""An HTTP server that never shares its port.

The standard library's HTTP server sets SO_REUSEADDR, so a restarted server
can take its port back at once instead of waiting for old connections to
time out. On Linux and macOS that is all it does. On Windows the same option
lets a SECOND process bind a port that is already in use, after which
connections go to either one. Segurai could then start "successfully" while
an older server - or a hostile program - answers its dashboard or gateway.

Windows has a separate option for exclusive use, so the server uses that
instead. Starting a second server on a busy port then fails, as it should,
with "address already in use".
"""

from __future__ import annotations

import os
import socket
from http.server import ThreadingHTTPServer

__all__ = ["ExclusiveHTTPServer"]


class ExclusiveHTTPServer(ThreadingHTTPServer):
    if os.name == "nt":
        allow_reuse_address = False

        def server_bind(self) -> None:
            self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)
            super().server_bind()
