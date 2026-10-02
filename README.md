# JA4 Lab

A Python networking and security project exploring JA4 and JA4H fingerprinting.

## Project 1 — What's My Fingerprint?

A local HTTPS server that inspects a client's TLS ClientHello and HTTP request.

### Features

- Parses TLS ClientHello data
- Calculates JA4 fingerprints
- Displays TLS version
- Displays cipher suites
- Displays TLS extensions
- Extracts SNI
- Extracts ALPN
- Displays HTTP header order
- Generates JA4H-style HTTP fingerprint information

## Project Structure

```text
ja4-lab/
├── 01_echo_server/
│   ├── fingerprints.py
│   ├── server.py
│   └── tls_parser.py
├── 02_network_inventory/
├── 03_mismatch_detector/
└── README.md