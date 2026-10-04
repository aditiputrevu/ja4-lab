import html
import http.client
import socket
import ssl
import time

from tls_parser import parse_client_hello

from fingerprints import (
    calculate_ja4,
    calculate_ja4h,
)

from detector import detect_mismatch


HOST = "0.0.0.0"
PORT = 8444

BACKEND_HOST = "127.0.0.1"
BACKEND_PORT = 8080


def peek_tls_record(
    connection: socket.socket
) -> bytes:

    connection.settimeout(5)

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


def forward_request(
    method,
    path,
    headers
):

    connection = (
        http.client.HTTPConnection(
            BACKEND_HOST,
            BACKEND_PORT,
            timeout=5
        )
    )

    forward_headers = {}

    for name, value in headers:

        lower = name.lower()

        if lower in (
            "host",
            "connection",
            "content-length",
        ):
            continue

        forward_headers[name] = value

    forward_headers["Host"] = (
        f"{BACKEND_HOST}:"
        f"{BACKEND_PORT}"
    )

    connection.request(
        method,
        path,
        headers=forward_headers
    )

    response = (
        connection.getresponse()
    )

    body = response.read()

    response_headers = (
        response.getheaders()
    )

    status = response.status
    reason = response.reason

    connection.close()

    return (
        status,
        reason,
        response_headers,
        body
    )


def send_response(
    tls_socket,
    status,
    reason,
    headers,
    body,
    detection
):

    header_lines = []

    for name, value in headers:

        lower = name.lower()

        if lower in (
            "connection",
            "content-length",
        ):
            continue

        header_lines.append(
            f"{name}: {value}"
        )

    header_lines.append(
        f"Content-Length: {len(body)}"
    )

    header_lines.append(
        "Connection: close"
    )

    header_lines.append(
        "X-JA4-Suspicious: "
        + str(
            detection["suspicious"]
        ).lower()
    )

    header_lines.append(
        "X-JA4-Score: "
        + str(
            detection["score"]
        )
    )

    response_head = (
        f"HTTP/1.1 "
        f"{status} "
        f"{reason}\r\n"
        + "\r\n".join(
            header_lines
        )
        + "\r\n\r\n"
    )

    tls_socket.sendall(
        response_head.encode(
            "iso-8859-1"
        )
        + body
    )


def print_detection(
    address,
    detection
):

    print(
        "\n"
        + "=" * 70
    )

    print(
        "REQUEST FROM:",
        address[0]
    )

    print(
        "User-Agent:",
        detection["user_agent"]
    )

    print(
        "Claimed client:",
        detection["claimed_client"]
    )

    print(
        "JA4:",
        detection["ja4"]
    )

    print(
        "JA4H:",
        detection["ja4h"]
    )

    print(
        "Known JA4 client:",
        detection["observed_client"]
    )

    print(
        "Suspicion score:",
        detection["score"]
    )

    print(
        "Suspicious:",
        detection["suspicious"]
    )

    if detection["reasons"]:

        print("\nReasons:")

        for reason in detection[
            "reasons"
        ]:

            print(
                "-",
                reason
            )

    print(
        "=" * 70
    )


def main():

    context = ssl.SSLContext(
        ssl.PROTOCOL_TLS_SERVER
    )

    context.load_cert_chain(
        certfile="cert.pem",
        keyfile="key.pem"
    )

    # Keep it HTTP/1.1 for now.
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
        "JA4 mismatch detector running:"
    )

    print(
        f"https://localhost:{PORT}"
    )

    print(
        "Forwarding to:"
    )

    print(
        f"http://"
        f"{BACKEND_HOST}:"
        f"{BACKEND_PORT}"
    )

    while True:

        connection, address = (
            server.accept()
        )

        try:

            raw_client_hello = (
                peek_tls_record(
                    connection
                )
            )

            hello = (
                parse_client_hello(
                    raw_client_hello
                )
            )

            ja4 = calculate_ja4(
                hello
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

            detection = (
                detect_mismatch(
                    headers,
                    ja4,
                    ja4h
                )
            )

            print_detection(
                address,
                detection
            )

            (
                status,
                reason,
                response_headers,
                body
            ) = forward_request(
                method,
                path,
                headers
            )

            send_response(
                tls_socket,
                status,
                reason,
                response_headers,
                body,
                detection
            )

            tls_socket.close()

        except Exception as error:

            print(
                "Connection error:",
                error
            )

            try:
                connection.close()

            except Exception:
                pass


if __name__ == "__main__":
    main()