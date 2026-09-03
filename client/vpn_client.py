"""TLS VPN client with AES-protected tunnel packets."""

from __future__ import annotations

import argparse
import json
import logging
import socket
import ssl
import threading
from typing import Callable, Dict, Optional

from vpn_core.config_loader import load_config
from vpn_core.crypto import decrypt_message, encrypt_message
from vpn_core.logging_utils import configure_logging
from vpn_core.protocol import recv_message, send_message

LOGGER = logging.getLogger("vpn.client")


class VPNClient:
    def __init__(self, config: Dict):
        self.server_host = config.get("server_host", "127.0.0.1")
        self.server_port = int(config.get("server_port", 8443))
        self.username = config["username"]
        self.password = config["password"]
        self.virtual_ip = config["virtual_ip"]
        self.shared_secret = config["shared_secret"]

        tls_config = config.get("tls", {})
        self.cafile = tls_config.get("cafile")
        self.client_cert = tls_config.get("certfile")
        self.client_key = tls_config.get("keyfile")

        self._socket: Optional[ssl.SSLSocket] = None
        self._shutdown = threading.Event()

    def _ssl_context(self) -> ssl.SSLContext:
        context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        if self.cafile:
            context.load_verify_locations(cafile=self.cafile)
        else:
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
        if self.client_cert and self.client_key:
            context.load_cert_chain(self.client_cert, self.client_key)
        return context

    def connect(self) -> None:
        context = self._ssl_context()
        raw_sock = socket.create_connection((self.server_host, self.server_port))
        self._socket = context.wrap_socket(raw_sock, server_hostname=self.server_host)

        send_message(
            self._socket,
            {
                "type": "auth",
                "username": self.username,
                "password": self.password,
                "virtual_ip": self.virtual_ip,
            },
        )
        auth_result = recv_message(self._socket)
        if not auth_result.get("success"):
            raise PermissionError("Authentication failed")
        LOGGER.info("Connected and authenticated as %s", self.username)

    def send_packet(self, destination_ip: str, payload: str) -> None:
        if not self._socket:
            raise RuntimeError("Client is not connected")
        packet = {
            "src_ip": self.virtual_ip,
            "dst_ip": destination_ip,
            "payload": payload,
        }
        encrypted = encrypt_message(self.shared_secret, json.dumps(packet).encode("utf-8"))
        send_message(self._socket, {"type": "packet", "payload": encrypted})

    def listen(self, on_packet: Optional[Callable[[Dict], None]] = None) -> None:
        if not self._socket:
            raise RuntimeError("Client is not connected")
        while not self._shutdown.is_set():
            incoming = recv_message(self._socket)
            if incoming.get("type") != "packet":
                continue
            decrypted = decrypt_message(self.shared_secret, incoming["payload"])
            packet = json.loads(decrypted.decode("utf-8"))
            if on_packet:
                on_packet(packet)
            else:
                LOGGER.info(
                    "Packet received %s -> %s: %s",
                    packet.get("src_ip"),
                    packet.get("dst_ip"),
                    packet.get("payload"),
                )

    def close(self) -> None:
        self._shutdown.set()
        if self._socket:
            self._socket.close()
            self._socket = None


def main() -> None:
    parser = argparse.ArgumentParser(description="Open-source VPN client")
    parser.add_argument("--config", required=True, help="Path to client JSON/YAML config")
    args = parser.parse_args()

    config = load_config(args.config)
    configure_logging(config.get("log_level", "INFO"))

    client = VPNClient(config)
    try:
        client.connect()

        listener = threading.Thread(target=client.listen, daemon=True)
        listener.start()

        while True:
            command = input("vpn> ").strip()
            if command in {"quit", "exit"}:
                break
            if command.startswith("send "):
                _, destination, *message = command.split()
                client.send_packet(destination, " ".join(message))
                continue
            print("Commands: send <dst_ip> <message> | quit")
    except KeyboardInterrupt:
        LOGGER.info("Client interrupted")
    finally:
        client.close()


if __name__ == "__main__":
    main()
