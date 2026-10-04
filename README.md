# JA4 Lab

A Python networking and security project exploring JA4 and JA4H fingerprinting through TLS inspection, network fingerprint inventory, and User-Agent mismatch detection.

---

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

---

## Project 2 — Network Fingerprint Inventory

This project captures authorized network traffic and compares JA4-family fingerprints across applications such as Chrome and curl.

Traffic is captured with Wireshark, analyzed using the FoxIO JA4 implementation, stored in SQLite, and displayed through a Streamlit dashboard.

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

The database records information such as:

- Application
- Device
- Source and destination
- Domain
- JA4
- JA4H
- JA4S
- Notes

To view how many observations were collected for each application:

```sql
SELECT application, COUNT(*)
FROM observations
GROUP BY application;
```

### Import Fingerprints

Example Chrome import:

```bash
python import_results.py results.json Chrome
```

Example curl import:

```bash
python import_results.py curl_results.json curl
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

---

## Project 3 — User-Agent vs JA4 Mismatch Detector

This project implements a Python reverse proxy that compares what a client claims to be in its HTTP User-Agent with the JA4 fingerprint generated from its TLS ClientHello.

The detector also uses JA4H-style HTTP characteristics such as header composition and ordering to identify suspicious requests.

The goal is to demonstrate how a client can change its User-Agent while its underlying TLS and HTTP behavior can still reveal inconsistencies.

### How It Works

```text
Client
   |
   | HTTPS Request
   v
Python Reverse Proxy
   |
   ├── Inspect TLS ClientHello
   |       |
   |       └── Calculate JA4
   |
   ├── Inspect HTTP Request
   |       |
   |       ├── User-Agent
   |       └── JA4H / Header Behavior
   |
   ├── Compare User-Agent with known JA4 fingerprints
   |
   ├── Calculate suspicion score
   |
   +-----------------------+
   |                       |
   v                       v
Normal                 Suspicious
   |                       |
   +-----------+-----------+
               |
               v
        Forward to Backend
```

### Detection Logic

The proxy compares three main signals:

1. **User-Agent identity**

   Determines what application the request claims to be, such as Chrome or curl.

2. **JA4 fingerprint**

   The TLS ClientHello is fingerprinted and compared with fingerprints previously collected in Project 2.

3. **JA4H-style HTTP behavior**

   The detector checks characteristics such as browser-specific headers and the size and structure of the HTTP header set.

A request is assigned a suspicion score based on mismatches between these signals.

### Example — Normal curl

```text
User-Agent: curl/8.7.1
Claimed client: curl
Known JA4 client: curl
Suspicion score: 0
Suspicious: False
```

The User-Agent and JA4 fingerprint agree, so the request is not flagged.

### Example — curl Pretending to Be Chrome

Changing curl's User-Agent does not change its underlying TLS fingerprint.

```text
User-Agent: Mozilla/5.0 ... Chrome/153.0.0.0 ...
Claimed client: chrome
Known JA4 client: curl
Suspicion score: 100
Suspicious: True
```

Reasons can include:

```text
User-Agent claims Chrome, but JA4 was previously observed with curl.
Chrome User-Agent has very few typical Chrome browser headers.
JA4H-style HTTP profile contains an unusually small header set for a Chrome request.
```

### Example — Real Chrome

```text
Claimed client: chrome
Known JA4 client: Chrome
Suspicion score: 0
Suspicious: False
```

This demonstrates that the detector can distinguish between a real Chrome request and curl using a spoofed Chrome User-Agent.

### Run Project 3

Start the backend server:

```bash
cd 03_mismatch_detector
python backend.py
```

The backend runs at:

```text
http://127.0.0.1:8080
```

In another terminal, start the reverse proxy:

```bash
cd 03_mismatch_detector
python proxy.py
```

The proxy runs at:

```text
https://localhost:8444
```

### Test Normal curl

```bash
curl -k https://localhost:8444
```

### Test curl Pretending to Be Chrome

```bash
curl -k \
-A "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/153.0.0.0 Safari/537.36" \
https://localhost:8444
```

The second request should be flagged as suspicious because the HTTP User-Agent claims Chrome while the JA4 fingerprint matches curl.

---

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
├── 03_mismatch_detector/
│   ├── backend.py
│   ├── detector.py
│   ├── fake_chrome.py
│   ├── fingerprints.py
│   ├── proxy.py
│   └── tls_parser.py
│
├── .gitignore
└── README.md
```

## Security and Privacy

This lab is intended for educational use and testing on systems and network traffic that you own or are authorized to inspect.

Local certificates, private keys, packet captures, fingerprint databases, and generated result files are excluded from the repository through `.gitignore`.

The mismatch detector is an educational demonstration and should not be treated as a production bot-detection system.