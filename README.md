# opensource-vpn

An open-source VPN application built with Python. It includes a TLS-enabled VPN server, a CLI VPN client, AES-encrypted packet transport, username/password authentication, virtual IPv4 routing, and JSON/YAML configuration support.

## Project structure

- `server/` - VPN server implementation
- `client/` - VPN client implementation
- `vpn_core/` - Shared protocol, auth, crypto, routing, config, and logging utilities
- `config/` - Example JSON and YAML configuration files
- `tests/` - Unit and integration tests
- `docs/` - Documentation

## Features

- TLS/SSL secured client-server channel
- AES-GCM payload encryption for tunneled packets
- Username/password authentication with hashed credentials
- Virtual IPv4 routing between connected clients
- Configurable via JSON or YAML files
- CLI interfaces for server and client
- Logging, error handling, and graceful shutdown

## Setup

1. Install dependencies:
   ```bash
   python -m pip install cryptography pyyaml
   ```
2. Generate server TLS certificate and key in `certs/` (`server.crt`, `server.key`).
3. Generate password hashes for `config/server.*` users:
   ```bash
   python -c "from vpn_core.auth import Authenticator; print(Authenticator.hash_password('your-password'))"
   ```
4. Update `config/server.json` and `config/client.json` as needed.

## Usage

Start server:

```bash
python -m server.vpn_server --config config/server.json
```

Start client:

```bash
python -m client.vpn_client --config config/client.json
```

Client commands:

- `send <dst_ip> <message>`
- `quit`

See `docs/quickstart.md` for a quick multi-client flow.

## Tests

Run tests with:

```bash
python -m unittest discover -s tests
```
