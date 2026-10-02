# JA4 Lab

A Python networking and security project exploring JA4 and JA4H fingerprinting.

## Project 1: What's My Fingerprint?

A local HTTPS server that inspects a client's TLS ClientHello and HTTP request to generate fingerprint information.

### Features

- Parses raw TLS ClientHello data
- Calculates JA4 fingerprints
- Displays TLS version
- Displays cipher suites
- Displays TLS extensions
- Extracts SNI
- Extracts ALPN
- Shows HTTP header order
- Calculates JA4H-style HTTP fingerprints
- Converts TLS IDs into human-readable names

## Project Structure

```text
ja4-lab/
├── 01_echo_server/
│   ├── server.py
│   ├── tls_parser.py
│   └── fingerprints.py
├── .gitignore
└── README.md