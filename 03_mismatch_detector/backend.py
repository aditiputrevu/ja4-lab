from http.server import HTTPServer, BaseHTTPRequestHandler


class BackendHandler(BaseHTTPRequestHandler):

    def do_GET(self):

        body = """
        <html>
        <head>
            <title>JA4 Proxy Backend</title>
        </head>

        <body>
            <h1>Request reached the backend</h1>

            <p>
            The JA4 mismatch detector successfully
            forwarded this request.
            </p>
        </body>
        </html>
        """

        body_bytes = body.encode("utf-8")

        self.send_response(200)

        self.send_header(
            "Content-Type",
            "text/html"
        )

        self.send_header(
            "Content-Length",
            str(len(body_bytes))
        )

        self.end_headers()

        self.wfile.write(body_bytes)


def main():

    server = HTTPServer(
        ("127.0.0.1", 8080),
        BackendHandler
    )

    print(
        "Backend running on "
        "http://127.0.0.1:8080"
    )

    server.serve_forever()


if __name__ == "__main__":
    main()