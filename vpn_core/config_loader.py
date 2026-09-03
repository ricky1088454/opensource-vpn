"""Configuration loading helpers for VPN client and server."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict


def load_config(path: str) -> Dict[str, Any]:
    """Load VPN configuration from JSON or YAML."""
    config_path = Path(path)
    if not config_path.exists():
        raise FileNotFoundError(f"Config file not found: {config_path}")

    suffix = config_path.suffix.lower()
    raw = config_path.read_text(encoding="utf-8")

    if suffix == ".json":
        return json.loads(raw)
    if suffix in {".yml", ".yaml"}:
        try:
            import yaml  # type: ignore
        except ImportError as exc:
            raise RuntimeError("YAML support requires PyYAML") from exc
        loaded = yaml.safe_load(raw)
        return loaded or {}
    raise ValueError("Unsupported config format. Use .json, .yaml, or .yml")
