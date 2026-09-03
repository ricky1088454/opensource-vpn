import socket
import tempfile
import threading
import time
import unittest
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from datetime import datetime, timedelta, timezone

from client.vpn_client import VPNClient
from server.vpn_server import VPNServer
from vpn_core.auth import Authenticator


def _free_port() -> int:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind(("127.0.0.1", 0))
    _, port = sock.getsockname()
    sock.close()
    return int(port)


def _generate_cert(cert_path: Path, key_path: Path) -> None:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "OpenSource VPN"),
        x509.NameAttribute(NameOID.COMMON_NAME, "127.0.0.1"),
    ])
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.now(timezone.utc) - timedelta(minutes=1))
        .not_valid_after(datetime.now(timezone.utc) + timedelta(days=2))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName("127.0.0.1")]), critical=False)
        .sign(key, hashes.SHA256())
    )

    key_path.write_bytes(
        key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))


class IntegrationTests(unittest.TestCase):
    def test_server_routes_packets_between_clients(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            cert_path = tmp_path / "server.crt"
            key_path = tmp_path / "server.key"
            _generate_cert(cert_path, key_path)

            port = _free_port()
            users = {
                "alice": Authenticator.hash_password("alice123"),
                "bob": Authenticator.hash_password("bob123"),
            }
            server_config = {
                "host": "127.0.0.1",
                "port": port,
                "shared_secret": "integration-secret",
                "users": users,
                "tls": {
                    "certfile": str(cert_path),
                    "keyfile": str(key_path),
                },
            }

            server = VPNServer(server_config)
            server_thread = threading.Thread(target=server.start, daemon=True)
            server_thread.start()
            time.sleep(0.3)

            alice = VPNClient(
                {
                    "server_host": "127.0.0.1",
                    "server_port": port,
                    "username": "alice",
                    "password": "alice123",
                    "virtual_ip": "10.8.0.2",
                    "shared_secret": "integration-secret",
                    "tls": {},
                }
            )
            bob = VPNClient(
                {
                    "server_host": "127.0.0.1",
                    "server_port": port,
                    "username": "bob",
                    "password": "bob123",
                    "virtual_ip": "10.8.0.3",
                    "shared_secret": "integration-secret",
                    "tls": {},
                }
            )

            received = []
            stop_event = threading.Event()

            try:
                alice.connect()
                bob.connect()

                def bob_listener():
                    while not stop_event.is_set():
                        bob.listen(lambda packet: received.append(packet))

                listener = threading.Thread(target=bob_listener, daemon=True)
                listener.start()

                alice.send_packet("10.8.0.3", "hello")
                time.sleep(0.5)
                self.assertTrue(received)
                self.assertEqual(received[0]["payload"], "hello")
                self.assertEqual(received[0]["src_ip"], "10.8.0.2")
            finally:
                stop_event.set()
                alice.close()
                bob.close()
                server.stop()


if __name__ == "__main__":
    unittest.main()
