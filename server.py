import ipaddress
import json
import socket
from http import HTTPStatus
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.parse import parse_qs, urlparse
from urllib.request import Request, urlopen


ROOT = Path(__file__).parent
STATIC_DIR = ROOT / "web"
MAX_RESPONSE_BYTES = 1_000_000


def is_public_ip(ip_string: str) -> bool:
    ip = ipaddress.ip_address(ip_string)
    return not (
        ip.is_private
        or ip.is_loopback
        or ip.is_link_local
        or ip.is_multicast
        or ip.is_reserved
        or ip.is_unspecified
    )


def is_public_hostname(hostname: str, resolver=socket.getaddrinfo) -> bool:
    try:
        ipaddress.ip_address(hostname)
        return is_public_ip(hostname)
    except ValueError:
        pass

    try:
        results = resolver(hostname, None, type=socket.SOCK_STREAM)
    except socket.gaierror:
        return False

    if not results:
        return False

    for record in results:
        address = record[4][0]
        if not is_public_ip(address):
            return False
    return True


def validate_target_url(raw_url: str) -> str:
    if not raw_url:
        raise ValueError("Missing URL.")

    parsed = urlparse(raw_url.strip())
    if parsed.scheme not in {"http", "https"}:
        raise ValueError("Only http and https URLs are allowed.")
    if not parsed.hostname:
        raise ValueError("Invalid URL.")
    if not is_public_hostname(parsed.hostname):
        raise ValueError("Target host is not allowed.")

    return parsed.geturl()


class VPNRequestHandler(SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=str(STATIC_DIR), **kwargs)

    def do_GET(self):
        parsed = urlparse(self.path)
        if parsed.path == "/api/fetch":
            self._handle_fetch(parsed.query)
            return
        if parsed.path == "/health":
            self._json_response(HTTPStatus.OK, {"status": "ok"})
            return
        super().do_GET()

    def _handle_fetch(self, query: str):
        params = parse_qs(query)
        raw_url = params.get("url", [""])[0]

        try:
            target_url = validate_target_url(raw_url)
        except ValueError as exc:
            self._json_response(HTTPStatus.BAD_REQUEST, {"error": str(exc)})
            return

        try:
            req = Request(
                target_url,
                method="GET",
                headers={
                    "User-Agent": "opensource-vpn-web-proxy/1.0",
                    "Accept": "text/html,application/xhtml+xml,text/plain,*/*",
                },
            )
            with urlopen(req, timeout=15) as resp:
                raw = resp.read(MAX_RESPONSE_BYTES + 1)
                if len(raw) > MAX_RESPONSE_BYTES:
                    self._json_response(
                        HTTPStatus.REQUEST_ENTITY_TOO_LARGE,
                        {"error": "Remote response exceeded size limit."},
                    )
                    return

                content_type = resp.headers.get("Content-Type", "text/plain")
                text = raw.decode("utf-8", errors="replace")
                self._json_response(
                    HTTPStatus.OK,
                    {"url": target_url, "contentType": content_type, "content": text},
                )
        except HTTPError as exc:
            self._json_response(
                HTTPStatus.BAD_GATEWAY,
                {"error": f"Remote server returned HTTP {exc.code}."},
            )
        except URLError:
            self._json_response(
                HTTPStatus.BAD_GATEWAY,
                {"error": "Unable to reach remote target."},
            )
        except TimeoutError:
            self._json_response(
                HTTPStatus.GATEWAY_TIMEOUT,
                {"error": "Request to remote target timed out."},
            )

    def _json_response(self, status: HTTPStatus, payload: dict):
        body = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def run() -> None:
    server = ThreadingHTTPServer(("0.0.0.0", 8080), VPNRequestHandler)
    print("Server running on http://0.0.0.0:8080")
    server.serve_forever()


if __name__ == "__main__":
    run()
