# JA4 Lab

A Python networking and security project exploring JA4 and JA4H fingerprinting.

## Project 1 — What's My Fingerprint?

A local HTTPS server that inspects a client's TLS ClientHello and HTTP request.

### Features

- Parses raw TLS ClientHello data
- Calculates JA4 fingerprints
- Displays TLS version
- Displays cipher suites
- Displays TLS extensions
- Extracts SNI
- Extracts ALPN
- Extracts signature algorithms
- Converts common TLS IDs into human-readable names
- Displays HTTP header order
- Generates JA4H-style HTTP fingerprint information

### How It Works

```text
Browser
   |
   | TLS ClientHello
   v
Python Server
   |
   ├── Parse TLS version
   ├── Parse cipher suites
   ├── Parse TLS extensions
   ├── Parse signature algorithms
   ├── Extract SNI
   ├── Extract ALPN
   └── Calculate JA4
          |
          v
      TLS Handshake
          |
          | HTTP Request
          v
     Analyze HTTP headers
          |
          v
        JA4H
```

### Run Project 1

```bash
cd 01_echo_server
```

Generate a local self-signed certificate:

```bash
openssl req -x509 \
  -newkey rsa:2048 \
  -keyout key.pem \
  -out cert.pem \
  -sha256 \
  -days 365 \
  -nodes \
  -subj "/CN=localhost"
```

Run the server:

```bash
python server.py
```

Then visit:

```text
https://localhost:8443
```

## Project 2 — Network Fingerprint Inventory

This project captures authorized network traffic and compares JA4-family fingerprints across different applications such as Chrome and curl.

### Workflow

```text
Application Traffic
      |
      v
Wireshark Capture
      |
      v
PCAPNG File
      |
      v
FoxIO JA4 Analyzer
      |
      v
JSON Results
      |
      v
SQLite Database
      |
      v
Streamlit Dashboard
```

### Tools Used

- Python
- Wireshark
- tshark
- FoxIO JA4+
- SQLite
- pandas
- Streamlit

### Database

Fingerprint observations are stored in SQLite.
To view how many observations were collected for each application:

```sql
SELECT application, COUNT(*)
FROM observations
GROUP BY application;
```

Example result:

```text
Chrome|12
curl|8
```

### Dashboard

The Streamlit dashboard displays:

- Total observations
- Unique JA4 fingerprints
- Observed domains
- Devices
- Most common JA4 fingerprints
- Fingerprints grouped by application
- Chrome vs curl fingerprint differences

Run the dashboard with:

```bash
cd 02_network_inventory
streamlit run dashboard.py
```

Then open:

```text
http://localhost:8501
```

## Project Structure

```text
ja4-lab/
├── 01_echo_server/
│   ├── fingerprints.py
│   ├── server.py
│   └── tls_parser.py
│
├── 02_network_inventory/
│   ├── dashboard.py
│   ├── database.py
│   └── import_results.py
│
├── .gitignore
└── README.md
```