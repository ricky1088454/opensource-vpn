"""Line-delimited JSON protocol helpers."""

from __future__ import annotations

import json
import socket
from typing import Any, Dict


class ProtocolError(Exception):
    pass


def send_message(sock: socket.socket, message: Dict[str, Any]) -> None:
    payload = json.dumps(message).encode("utf-8") + b"\n"
    sock.sendall(payload)


def recv_message(sock: socket.socket) -> Dict[str, Any]:
    buff = bytearray()
    while True:
        chunk = sock.recv(1)
        if not chunk:
            if not buff:
                raise ConnectionError("Connection closed")
            break
        if chunk == b"\n":
            break
        buff.extend(chunk)

    try:
        return json.loads(buff.decode("utf-8"))
    except json.JSONDecodeError as exc:
        raise ProtocolError("Invalid JSON message") from exc
