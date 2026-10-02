import html
import socket
import ssl
import time

from tls_parser import (
    parse_client_hello
)

from fingerprints import (
    calculate_ja4,
    calculate_ja4h
)


HOST = "0.0.0.0"
PORT = 8443


def peek_tls_record(
    connection: socket.socket
) -> bytes:

    connection.settimeout(5)

    # First get enough bytes for
    # the TLS record header.
    while True:

        data = connection.recv(
            5,
            socket.MSG_PEEK
        )

        if len(data) >= 5:
            break

        time.sleep(0.01)

    record_length = int.from_bytes(
        data[3:5],
        "big"
    )

    total_length = (
        5 + record_length
    )

    while True:

        data = connection.recv(
            total_length,
            socket.MSG_PEEK
        )

        if len(data) >= total_length:

            return data[
                :total_length
            ]

        time.sleep(0.01)


def read_http_request(
    tls_socket
):

    data = b""

    while b"\r\n\r\n" not in data:

        chunk = tls_socket.recv(
            4096
        )

        if not chunk:
            break

        data += chunk

        if len(data) > 65536:

            raise ValueError(
                "HTTP headers too large"
            )

    text = data.decode(
        "iso-8859-1"
    )

    lines = text.split(
        "\r\n"
    )

    request_line = lines[0]

    method, path, version = (
        request_line.split(
            " ",
            2
        )
    )

    headers = []

    for line in lines[1:]:

        if not line:
            break

        if ":" not in line:
            continue

        name, value = line.split(
            ":",
            1
        )

        headers.append(
            (
                name.strip(),
                value.strip()
            )
        )

    return (
        method,
        path,
        version,
        headers
    )


def make_page(
    ja4,
    ja4h,
    client_address
):

    cipher_html = "".join(
        f"<li><code>{html.escape(c)}</code></li>"
        for c in ja4["ciphers"]
    )

    extension_html = "".join(
        f"<li><code>{html.escape(e)}</code></li>"
        for e in ja4["extensions"]
    )

    header_html = "".join(
        f"<li><code>{html.escape(h)}</code></li>"
        for h in ja4h["headers"]
    )

    alpn = ", ".join(
        ja4["alpn"]
    ) or "None"

    page = f"""
<!doctype html>

<html>

<head>

<meta charset="utf-8">

<title>What's My Fingerprint?</title>

<style>

body {{
    background: #111;
    color: #eee;
    font-family:
        -apple-system,
        BlinkMacSystemFont,
        sans-serif;
    max-width: 900px;
    margin: 60px auto;
    padding: 20px;
}}

h1 {{
    font-size: 42px;
}}

.card {{
    background: #191919;
    border: 1px solid #333;
    padding: 25px;
    margin: 20px 0;
    border-radius: 12px;
}}

.fingerprint {{
    font-family: monospace;
    font-size: 18px;
    word-break: break-all;
    background: #080808;
    padding: 15px;
    border-radius: 8px;
}}

table {{
    width: 100%;
    border-collapse: collapse;
}}

td {{
    padding: 9px;
    border-bottom: 1px solid #333;
}}

code {{
    font-family: monospace;
}}

</style>

</head>

<body>

<h1>What's My Fingerprint?</h1>

<p>
This page shows how your client looks
at the TLS and HTTP layers.
</p>


<div class="card">

<h2>JA4</h2>

<div class="fingerprint">
{html.escape(ja4["fingerprint"])}
</div>

<table>

<tr>
<td>TLS Version</td>
<td>{html.escape(ja4["tls_version"])}</td>
</tr>

<tr>
<td>Raw TLS Version</td>
<td>{html.escape(ja4["tls_version_raw"])}</td>
</tr>

<tr>
<td>SNI</td>
<td>{html.escape(str(ja4["sni"]))}</td>
</tr>

<tr>
<td>Cipher Count</td>
<td>{ja4["cipher_count"]}</td>
</tr>

<tr>
<td>Extension Count</td>
<td>{ja4["extension_count"]}</td>
</tr>

<tr>
<td>ALPN</td>
<td>{html.escape(alpn)}</td>
</tr>

</table>

</div>


<div class="card">

<h2>JA4 components</h2>

<p>
A:
<code>{html.escape(ja4["a"])}</code>
</p>

<p>
B:
<code>{html.escape(ja4["b"])}</code>
</p>

<p>
C:
<code>{html.escape(ja4["c"])}</code>
</p>

</div>


<div class="card">

<h2>Cipher Suites</h2>

<ul>
{cipher_html}
</ul>

</div>


<div class="card">

<h2>TLS Extensions</h2>

<ul>
{extension_html}
</ul>

</div>


<div class="card">

<h2>JA4H</h2>

<div class="fingerprint">
{html.escape(ja4h["fingerprint"])}
</div>

<table>

<tr>
<td>HTTP Version</td>
<td>{html.escape(ja4h["http_version"])}</td>
</tr>

<tr>
<td>Method</td>
<td>{html.escape(ja4h["method"])}</td>
</tr>

<tr>
<td>Headers</td>
<td>{ja4h["header_count"]}</td>
</tr>

<tr>
<td>Language</td>
<td>{html.escape(ja4h["language"])}</td>
</tr>

</table>

<h3>Header order</h3>

<ul>
{header_html}
</ul>

</div>


<div class="card">

Client:
<code>
{html.escape(client_address[0])}
</code>

</div>

</body>

</html>
"""

    return page


def main():

    context = ssl.SSLContext(
        ssl.PROTOCOL_TLS_SERVER
    )

    context.load_cert_chain(
        certfile="cert.pem",
        keyfile="key.pem"
    )

    # Keep Project 1 simple.
    # Browser will use HTTP/1.1 rather
    # than HTTP/2.

    context.set_alpn_protocols(
        ["http/1.1"]
    )

    server = socket.socket(
        socket.AF_INET,
        socket.SOCK_STREAM
    )

    server.setsockopt(
        socket.SOL_SOCKET,
        socket.SO_REUSEADDR,
        1
    )

    server.bind(
        (HOST, PORT)
    )

    server.listen()

    print(
        f"Listening on https://localhost:{PORT}"
    )

    while True:

        connection, address = server.accept()

        try:

            # IMPORTANT:
            #
            # MSG_PEEK lets us inspect
            # ClientHello without consuming it.

            raw_client_hello = (
                peek_tls_record(
                    connection
                )
            )

            hello = parse_client_hello(
                raw_client_hello
            )

            ja4 = calculate_ja4(
                hello
            )

            print(
                "\nJA4:",
                ja4["fingerprint"]
            )

            tls_socket = (
                context.wrap_socket(
                    connection,
                    server_side=True
                )
            )

            (
                method,
                path,
                http_version,
                headers
            ) = read_http_request(
                tls_socket
            )

            ja4h = calculate_ja4h(
                method,
                http_version,
                headers
            )

            print(
                "JA4H:",
                ja4h["fingerprint"]
            )

            page = make_page(
                ja4,
                ja4h,
                address
            )

            encoded = page.encode(
                "utf-8"
            )

            response = (
                "HTTP/1.1 200 OK\r\n"
                "Content-Type: text/html; "
                "charset=utf-8\r\n"
                f"Content-Length: "
                f"{len(encoded)}\r\n"
                "Connection: close\r\n"
                "\r\n"
            ).encode("ascii")

            tls_socket.sendall(
                response + encoded
            )

            tls_socket.close()

        except Exception as error:

            print(
                "Connection error:",
                error
            )

            connection.close()


if __name__ == "__main__":
    main()
