# Quick Start

1. Generate TLS certificates and place them under `certs/`.
2. Start the server:
   ```bash
   python -m server.vpn_server --config config/server.json
   ```
3. Start one or more clients:
   ```bash
   python -m client.vpn_client --config config/client.json
   ```
4. Send packets from the client shell:
   ```text
   send 10.8.0.3 hello-from-alice
   ```
