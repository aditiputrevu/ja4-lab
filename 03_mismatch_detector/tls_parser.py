from dataclasses import dataclass


@dataclass
class ClientHello:
    legacy_version: int
    supported_versions: list[int]
    cipher_suites: list[int]
    extensions: list[int]
    signature_algorithms: list[int]
    alpn_protocols: list[str]
    server_name: str | None


def read_u16(data: bytes, offset: int) -> tuple[int, int]:
    value = int.from_bytes(data[offset:offset + 2], "big")
    return value, offset + 2


def is_grease(value: int) -> bool:
    high = (value >> 8) & 0xff
    low = value & 0xff

    return high == low and (low & 0x0f) == 0x0a


def parse_sni(data: bytes) -> str | None:
    if len(data) < 5:
        return None

    offset = 2

    while offset + 3 <= len(data):
        name_type = data[offset]
        offset += 1

        name_length, offset = read_u16(data, offset)

        name = data[offset:offset + name_length]
        offset += name_length

        if name_type == 0:
            try:
                return name.decode("utf-8")
            except UnicodeDecodeError:
                return None

    return None


def parse_alpn(data: bytes) -> list[str]:
    protocols = []

    if len(data) < 2:
        return protocols

    offset = 2

    while offset < len(data):
        length = data[offset]
        offset += 1

        protocol = data[offset:offset + length]
        offset += length

        try:
            protocols.append(protocol.decode("ascii"))
        except UnicodeDecodeError:
            protocols.append(protocol.hex())

    return protocols


def parse_supported_versions(data: bytes) -> list[int]:
    if not data:
        return []

    length = data[0]
    offset = 1
    end = min(offset + length, len(data))

    versions = []

    while offset + 2 <= end:
        version, offset = read_u16(data, offset)
        versions.append(version)

    return versions


def parse_signature_algorithms(data: bytes) -> list[int]:
    if len(data) < 2:
        return []

    total_length = int.from_bytes(data[:2], "big")

    offset = 2
    end = min(offset + total_length, len(data))

    algorithms = []

    while offset + 2 <= end:
        algorithm, offset = read_u16(data, offset)
        algorithms.append(algorithm)

    return algorithms


def parse_client_hello(record: bytes) -> ClientHello:
    if len(record) < 9:
        raise ValueError("TLS record is too short")

    # TLS content type 22 = handshake
    if record[0] != 22:
        raise ValueError("Expected TLS Handshake record")

    handshake = record[5:]

    # Handshake type 1 = ClientHello
    if handshake[0] != 1:
        raise ValueError("Expected ClientHello")

    # Skip handshake type + 3-byte length
    body = handshake[4:]

    if len(body) < 34:
        raise ValueError("Incomplete ClientHello")

    offset = 0

    # Legacy TLS version
    legacy_version, offset = read_u16(body, offset)

    # 32-byte random
    offset += 32

    # Session ID
    session_id_length = body[offset]
    offset += 1
    offset += session_id_length

    # Cipher suites
    cipher_length, offset = read_u16(body, offset)
    cipher_end = offset + cipher_length

    cipher_suites = []

    while offset + 2 <= cipher_end:
        cipher, offset = read_u16(body, offset)
        cipher_suites.append(cipher)

    # Compression methods
    compression_length = body[offset]
    offset += 1 + compression_length

    # Old ClientHello may contain no extensions
    if offset >= len(body):
        return ClientHello(
            legacy_version=legacy_version,
            supported_versions=[],
            cipher_suites=cipher_suites,
            extensions=[],
            signature_algorithms=[],
            alpn_protocols=[],
            server_name=None,
        )

    extension_total_length, offset = read_u16(body, offset)
    extension_end = min(offset + extension_total_length, len(body))

    extensions = []
    supported_versions = []
    signature_algorithms = []
    alpn_protocols = []
    server_name = None

    while offset + 4 <= extension_end:
        extension_type, offset = read_u16(body, offset)
        extension_length, offset = read_u16(body, offset)

        extension_data = body[offset:offset + extension_length]
        offset += extension_length

        extensions.append(extension_type)

        if extension_type == 0x0000:
            server_name = parse_sni(extension_data)

        elif extension_type == 0x000D:
            signature_algorithms = parse_signature_algorithms(extension_data)

        elif extension_type == 0x0010:
            alpn_protocols = parse_alpn(extension_data)

        elif extension_type == 0x002B:
            supported_versions = parse_supported_versions(extension_data)

    return ClientHello(
        legacy_version=legacy_version,
        supported_versions=supported_versions,
        cipher_suites=cipher_suites,
        extensions=extensions,
        signature_algorithms=signature_algorithms,
        alpn_protocols=alpn_protocols,
        server_name=server_name,
    )