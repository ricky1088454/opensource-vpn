# opensource-vpn

An open-source, browser-based "web VPN" proxy you can use from a Chromebook without needing a terminal on the Chromebook.

## What this is

This project provides a simple web app and Python backend that let you browse web pages through a remote server using just a browser UI.

- Chromebook-friendly: use it from Chrome, no local terminal needed
- Web UI built with HTML/CSS/JavaScript
- Backend written in Python (standard library only)
- Basic security checks to block localhost/private-network targets

> Note: This is a web proxy experience, not a full system-level VPN tunnel for all device traffic.

## Quick start

1. Clone this repo on a server or computer where Python 3 is installed.
2. Start the server:

```bash
python server.py
```

3. Open the shown URL (default `http://localhost:8080`) in your browser.
4. In the web app, enter the site you want to open through the proxy.

## Chromebook usage (no terminal on Chromebook)

1. Deploy or run this server on another machine/VPS.
2. Open the server URL in Chromebook Chrome.
3. Use the built-in form to browse through the proxy.

## Tests

Run:

```bash
python -m unittest discover -s tests
```
