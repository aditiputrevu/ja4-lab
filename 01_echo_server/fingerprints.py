import hashlib

from tls_parser import (
    ClientHello,
    is_grease,
)


TLS_VERSIONS = {
    0x0304: "13",  # TLS 1.3
    0x0303: "12",  # TLS 1.2
    0x0302: "11",  # TLS 1.1
    0x0301: "10",  # TLS 1.0
    0x0300: "s3",  # SSL 3.0
    0x0002: "s2",  # SSL 2.0
    0xFEFF: "d1",  # DTLS 1.0
    0xFEFD: "d2",  # DTLS 1.2
    0xFEFC: "d3",  # DTLS 1.3
}


def sha256_12(value: str) -> str:
    """
    Return the first 12 lowercase hexadecimal
    characters of a SHA-256 digest.
    """

    return hashlib.sha256(
        value.encode("utf-8")
    ).hexdigest()[:12]


def hex4(value: int) -> str:
    """
    Convert an integer to a four-character
    lowercase hexadecimal string.

    Example:
        4865 -> "1301"
    """

    return f"{value:04x}"


def ja4_alpn(protocols: list[str]) -> str:
    """
    JA4 uses the first and last character
    of the first ALPN protocol.

    Examples:
        h2       -> h2
        http/1.1 -> h1

    If no ALPN exists:
        00
    """

    if not protocols:
        return "00"

    first_protocol = protocols[0]

    if not first_protocol:
        return "00"

    encoded = first_protocol.encode(
        "utf-8",
        errors="replace",
    )

    first_byte = encoded[0]
    last_byte = encoded[-1]

    def is_ascii_alphanumeric(value: int) -> bool:
        return (
            48 <= value <= 57      # 0-9
            or 65 <= value <= 90   # A-Z
            or 97 <= value <= 122  # a-z
        )

    if (
        is_ascii_alphanumeric(first_byte)
        and is_ascii_alphanumeric(last_byte)
    ):
        if len(encoded) == 1:
            character = chr(first_byte)

            # JA4 treats a one-character value
            # as both first and last character.
            return character + character

        return (
            chr(first_byte)
            + chr(last_byte)
        )

    # If first/last bytes are not normal ASCII,
    # JA4 works with the hexadecimal representation.

    hex_value = encoded.hex()

    if len(encoded) == 1:
        return hex_value

    return (
        hex_value[0]
        + hex_value[-1]
    )


def calculate_ja4(
    hello: ClientHello
) -> dict:
    """
    Calculate a JA4 TLS client fingerprint.

    Returns both the fingerprint and useful
    human-readable pieces for the webpage.
    """

    # -----------------------------------------
    # 1. Remove GREASE
    # -----------------------------------------

    ciphers = [
        cipher
        for cipher in hello.cipher_suites
        if not is_grease(cipher)
    ]

    extensions = [
        extension
        for extension in hello.extensions
        if not is_grease(extension)
    ]

    signature_algorithms = [
        algorithm
        for algorithm in hello.signature_algorithms
        if not is_grease(algorithm)
    ]

    # -----------------------------------------
    # 2. Determine TLS version
    # -----------------------------------------

    supported_versions = [
        version
        for version in hello.supported_versions
        if not is_grease(version)
    ]

    if supported_versions:
        tls_version_raw = max(
            supported_versions
        )

    else:
        tls_version_raw = (
            hello.legacy_version
        )

    tls_version = TLS_VERSIONS.get(
        tls_version_raw,
        "00",
    )

    # -----------------------------------------
    # 3. JA4_a
    # -----------------------------------------

    # TLS over TCP
    transport = "t"

    # SNI extension 0x0000 means domain.
    sni_indicator = (
        "d"
        if 0x0000 in extensions
        else "i"
    )

    cipher_count = min(
        len(ciphers),
        99,
    )

    extension_count = min(
        len(extensions),
        99,
    )

    alpn_value = ja4_alpn(
        hello.alpn_protocols
    )

    ja4_a = (
        f"{transport}"
        f"{tls_version}"
        f"{sni_indicator}"
        f"{cipher_count:02d}"
        f"{extension_count:02d}"
        f"{alpn_value}"
    )

    # -----------------------------------------
    # 4. JA4_b
    # Cipher hash
    # -----------------------------------------

    cipher_values = [
        hex4(cipher)
        for cipher in ciphers
    ]

    cipher_values.sort()

    cipher_string = ",".join(
        cipher_values
    )

    if cipher_values:
        ja4_b = sha256_12(
            cipher_string
        )
    else:
        ja4_b = "000000000000"

    # -----------------------------------------
    # 5. JA4_c
    # Extension + signature algorithm hash
    # -----------------------------------------

    extension_values = []

    for extension in extensions:

        # JA4 omits SNI and ALPN from the
        # extension hash because they are
        # already represented in JA4_a.

        if extension in (
            0x0000,  # SNI
            0x0010,  # ALPN
        ):
            continue

        extension_values.append(
            hex4(extension)
        )

    extension_values.sort()

    extension_string = ",".join(
        extension_values
    )

    # Signature algorithms stay in the order
    # they appeared in ClientHello.

    signature_values = [
        hex4(algorithm)
        for algorithm
        in signature_algorithms
    ]

    signature_string = ",".join(
        signature_values
    )

    if extension_values:

        if signature_values:
            ja4_c_input = (
                extension_string
                + "_"
                + signature_string
            )

        else:
            ja4_c_input = (
                extension_string
            )

        ja4_c = sha256_12(
            ja4_c_input
        )

    else:
        ja4_c = "000000000000"

    # -----------------------------------------
    # 6. Final JA4
    # -----------------------------------------

    fingerprint = (
        f"{ja4_a}_"
        f"{ja4_b}_"
        f"{ja4_c}"
    )

    return {
        "fingerprint": fingerprint,

        "a": ja4_a,
        "b": ja4_b,
        "c": ja4_c,

        "tls_version": tls_version,

        "tls_version_raw": (
            f"0x{tls_version_raw:04x}"
        ),

        "sni": hello.server_name,

        "cipher_count": len(
            ciphers
        ),

        "extension_count": len(
            extensions
        ),

        "ciphers": [
            hex4(cipher)
            for cipher in ciphers
        ],

        "extensions": [
            hex4(extension)
            for extension in extensions
        ],

        "signature_algorithms": [
            hex4(algorithm)
            for algorithm
            in signature_algorithms
        ],

        "alpn": (
            hello.alpn_protocols
        ),
    }


def calculate_ja4h(
    method: str,
    http_version: str,
    headers: list[tuple[str, str]],
) -> dict:
    """
    Educational JA4H-style HTTP fingerprint
    used by our local project.

    It preserves header order, which is useful
    later for the User-Agent mismatch detector.
    """

    # -----------------------------------------
    # HTTP method
    # -----------------------------------------

    method_code = (
        method.lower()[:2]
    )

    # -----------------------------------------
    # HTTP version
    # -----------------------------------------

    version_map = {
        "HTTP/1.0": "10",
        "HTTP/1.1": "11",
        "HTTP/2": "20",
        "HTTP/3": "30",
    }

    version_code = version_map.get(
        http_version,
        "00",
    )

    # -----------------------------------------
    # Normalize header names
    # -----------------------------------------

    header_names = [
        name.lower()
        for name, _ in headers
    ]

    # -----------------------------------------
    # Cookie
    # -----------------------------------------

    cookie_header = None

    for name, value in headers:

        if name.lower() == "cookie":
            cookie_header = value
            break

    cookie_indicator = (
        "c"
        if cookie_header
        else "n"
    )

    # -----------------------------------------
    # Referer
    # -----------------------------------------

    has_referer = (
        "referer"
        in header_names
    )

    referer_indicator = (
        "r"
        if has_referer
        else "n"
    )

    # -----------------------------------------
    # Header order
    # -----------------------------------------

    normal_headers = []

    for name in header_names:

        if name in (
            "cookie",
            "referer",
        ):
            continue

        # Ignore HTTP/2 pseudo headers
        # if we add HTTP/2 later.

        if name.startswith(":"):
            continue

        normal_headers.append(
            name
        )

    header_count = min(
        len(normal_headers),
        99,
    )

    # -----------------------------------------
    # Accept-Language
    # -----------------------------------------

    accept_language = None

    for name, value in headers:

        if (
            name.lower()
            == "accept-language"
        ):
            accept_language = value
            break

    if accept_language:

        primary_language = (
            accept_language
            .split(",")[0]
            .split(";")[0]
            .replace("-", "")
            .lower()
        )

        language = (
            primary_language[:4]
            .ljust(4, "0")
        )

    else:
        language = "0000"

    # -----------------------------------------
    # Header hash
    # -----------------------------------------

    header_string = ",".join(
        normal_headers
    )

    if normal_headers:
        header_hash = sha256_12(
            header_string
        )
    else:
        header_hash = (
            "000000000000"
        )

    # -----------------------------------------
    # Cookie hashes
    # -----------------------------------------

    cookie_names_hash = (
        "000000000000"
    )

    cookie_values_hash = (
        "000000000000"
    )

    if cookie_header:

        cookies = []

        for item in cookie_header.split(";"):

            item = item.strip()

            if not item:
                continue

            if "=" in item:

                name, value = item.split(
                    "=",
                    1,
                )

            else:

                name = item
                value = ""

            cookies.append(
                (
                    name.strip(),
                    value.strip(),
                )
            )

        # Sort by cookie name to make output
        # deterministic.

        cookies.sort(
            key=lambda pair: pair[0]
        )

        cookie_names = ",".join(
            name
            for name, _
            in cookies
        )

        cookie_values = ",".join(
            f"{name}={value}"
            for name, value
            in cookies
        )

        if cookies:

            cookie_names_hash = (
                sha256_12(
                    cookie_names
                )
            )

            cookie_values_hash = (
                sha256_12(
                    cookie_values
                )
            )

    # -----------------------------------------
    # First section
    # -----------------------------------------

    ja4h_a = (
        f"{method_code}"
        f"{version_code}"
        f"{cookie_indicator}"
        f"{referer_indicator}"
        f"{header_count:02d}"
        f"{language}"
    )

    # -----------------------------------------
    # Final fingerprint
    # -----------------------------------------

    fingerprint = (
        f"{ja4h_a}_"
        f"{header_hash}_"
        f"{cookie_names_hash}_"
        f"{cookie_values_hash}"
    )

    return {
        "fingerprint": (
            fingerprint
        ),

        "method": method,

        "http_version": (
            http_version
        ),

        "header_count": (
            header_count
        ),

        "headers": (
            normal_headers
        ),

        "language": (
            language
        ),

        "has_cookie": bool(
            cookie_header
        ),

        "has_referer": (
            has_referer
        ),
    }