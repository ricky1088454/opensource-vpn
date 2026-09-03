"""Simple thread-safe routing table for virtual VPN IPs."""

from __future__ import annotations

import threading
from typing import Dict, Optional


class RoutingTable:
    def __init__(self):
        self._routes: Dict[str, str] = {}
        self._lock = threading.Lock()

    def add_route(self, virtual_ip: str, client_id: str) -> None:
        with self._lock:
            self._routes[virtual_ip] = client_id

    def remove_route(self, virtual_ip: str) -> None:
        with self._lock:
            self._routes.pop(virtual_ip, None)

    def resolve(self, virtual_ip: str) -> Optional[str]:
        with self._lock:
            return self._routes.get(virtual_ip)
