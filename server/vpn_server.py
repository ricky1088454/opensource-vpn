"""Threaded TLS VPN server with authenticated packet routing."""

from __future__ import annotations

import argparse
import json
import logging
import socket
import ssl
import threading
from dataclasses import dataclass
from typing import Dict, Optional, Tuple

from vpn_core.auth import Authenticator
from vpn_core.config_loader import load_config
from vpn_core.crypto import decrypt_message, encrypt_message
from vpn_core.logging_utils import configure_logging
from vpn_core.protocol import ProtocolError, recv_message, send_message
from vpn_core.routing import RoutingTable

LOGGER = logging.getLogger("vpn.server")


@dataclass
class ClientSession:
    client_id: str
    virtual_ip: str
    socket: ssl.SSLSocket


class VPNServer:
    def __init__(self, config: Dict):
        self.host = config.get("host", "127.0.0.1")
        self.port = int(config.get("port", 8443))
        self.shared_secret = config["shared_secret"]
        self.auth = Authenticator(config.get("users", {}))
        self.routing = RoutingTable()
        self._sessions: Dict[str, ClientSession] = {}
        self._sessions_lock = threading.Lock()
        self._shutdown = threading.Event()
        self._listener: Optional[socket.socket] = None

        tls_config = config.get("tls", {})
        self.certfile = tls_config.get("certfile")
        self.keyfile = tls_config.get("keyfile")
        self.cafile = tls_config.get("cafile")

    def _ssl_context(self) -> ssl.SSLContext:
        context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        if self.certfile and self.keyfile:
            context.load_cert_chain(self.certfile, self.keyfile)
        else:
            raise ValueError("TLS certfile and keyfile are required for server")
        if self.cafile:
            context.load_verify_locations(cafile=self.cafile)
        return context

    def start(self) -> None:
        context = self._ssl_context()
        raw_server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        raw_server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        raw_server.bind((self.host, self.port))
        raw_server.listen(10)
        self._listener = raw_server
        LOGGER.info("VPN server listening on %s:%s", self.host, self.port)

        while not self._shutdown.is_set():
            try:
                raw_client, addr = raw_server.accept()
                client_sock = context.wrap_socket(raw_client, server_side=True)
                thread = threading.Thread(
                    target=self._handle_client,
                    args=(client_sock, addr),
                    daemon=True,
                )
                thread.start()
            except OSError:
                break

    def stop(self) -> None:
        self._shutdown.set()
        if self._listener:
            self._listener.close()
        with self._sessions_lock:
            for session in list(self._sessions.values()):
                session.socket.close()
            self._sessions.clear()

    def _authenticate(self, client_sock: ssl.SSLSocket) -> Tuple[str, str]:
        auth_message = recv_message(client_sock)
        if auth_message.get("type") != "auth":
            raise ProtocolError("Expected auth message")

        username = auth_message.get("username", "")
        password = auth_message.get("password", "")
        virtual_ip = auth_message.get("virtual_ip", "")

        if not self.auth.validate(username, password):
            send_message(client_sock, {"type": "auth_result", "success": False})
            raise PermissionError("Authentication failed")

        send_message(client_sock, {"type": "auth_result", "success": True})
        return username, virtual_ip

    def _handle_client(self, client_sock: ssl.SSLSocket, addr: Tuple[str, int]) -> None:
        client_id = f"{addr[0]}:{addr[1]}"
        virtual_ip = ""
        try:
            username, virtual_ip = self._authenticate(client_sock)
            session = ClientSession(client_id=username, virtual_ip=virtual_ip, socket=client_sock)
            with self._sessions_lock:
                self._sessions[username] = session
            self.routing.add_route(virtual_ip, username)
            LOGGER.info("Client authenticated: %s (%s)", username, virtual_ip)

            while not self._shutdown.is_set():
                incoming = recv_message(client_sock)
                if incoming.get("type") != "packet":
                    continue
                decrypted = decrypt_message(self.shared_secret, incoming["payload"])
                packet = json.loads(decrypted.decode("utf-8"))
                self._route_packet(packet)
        except (ConnectionError, OSError, PermissionError, ProtocolError, ValueError) as exc:
            LOGGER.info("Client disconnected (%s): %s", client_id, exc)
        finally:
            if virtual_ip:
                self.routing.remove_route(virtual_ip)
            with self._sessions_lock:
                for username, session in list(self._sessions.items()):
                    if session.socket is client_sock:
                        self._sessions.pop(username, None)
                        break
            client_sock.close()

    def _route_packet(self, packet: Dict) -> None:
        destination_ip = packet.get("dst_ip")
        source_ip = packet.get("src_ip")
        destination_client = self.routing.resolve(destination_ip)
        if not destination_client:
            LOGGER.warning("No route for destination %s", destination_ip)
            return

        with self._sessions_lock:
            session = self._sessions.get(destination_client)
        if not session:
            LOGGER.warning("Route exists but client session missing for %s", destination_ip)
            return

        outbound = {
            "type": "packet",
            "payload": encrypt_message(self.shared_secret, json.dumps(packet).encode("utf-8")),
            "meta": {"src_ip": source_ip, "dst_ip": destination_ip},
        }
        send_message(session.socket, outbound)


def main() -> None:
    parser = argparse.ArgumentParser(description="Open-source VPN server")
    parser.add_argument("--config", required=True, help="Path to server JSON/YAML config")
    args = parser.parse_args()

    config = load_config(args.config)
    configure_logging(config.get("log_level", "INFO"))

    server = VPNServer(config)
    try:
        server.start()
    except KeyboardInterrupt:
        LOGGER.info("Shutdown requested")
    finally:
        server.stop()


if __name__ == "__main__":
    main()
