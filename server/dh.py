"""Non-standard Diffie-Hellman used by the client login handshake.

Client (VerifyUtils.java:50-57):
    privateKey a = BigInteger(1536, random)
    m = BigInteger(2048, random), q = BigInteger(1024, random)
    p = q^a mod m          -> sent as Base64( p.toByteArray() )
Server:
    b = random 1024-bit
    p_resp = q^b mod m     -> response data.p = Base64( p_resp.toByteArray() )
    shared = p^b mod m
Session key (client VerifyUtils.java:78-82):
    s = p_resp^a mod m ; key = last 32 bytes of s.toByteArray()
which equals (shared mod 2^256) as unsigned big-endian, as long as the shared
value's two's-complement encoding is at least 32 bytes (probability of the
contrary is ~2^-784).
"""

import secrets


def java_bigint_bytes(x: int) -> bytes:
    """Minimal two's-complement big-endian encoding of a non-negative int,
    matching java.math.BigInteger.toByteArray() (extra 0x00 when the top bit
    of the last byte would be set)."""
    if x == 0:
        return b"\x00"
    return x.to_bytes(x.bit_length() // 8 + 1, "big")


def parse_bigint(b64_value: bytes) -> int:
    """Client sends Base64 of BigInteger.toByteArray(); BigInteger(1, bytes)
    on the client side parses it as positive, leading zero bytes are ignored."""
    return int.from_bytes(b64_value, "big")


def server_exponent() -> int:
    return secrets.randbits(1024) | (1 << 1023)


def derive_key(shared: int) -> bytes:
    """Last 32 bytes of shared.toByteArray() == shared mod 2^256 big-endian."""
    return (shared & ((1 << 256) - 1)).to_bytes(32, "big")
