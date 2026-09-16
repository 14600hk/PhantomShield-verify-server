"""Ed25519 signatures — reference implementation from RFC 8032 (public domain).

Pure Python, no third-party dependencies. Used to sign login / first-heartbeat
payloads; the client verifies with the Ed25519 public key compiled into
Internals.publicKey() (SPKI DER, Base64).
"""

import hashlib
import secrets

_Q = 2 ** 255 - 19
_L = 2 ** 252 + 27742317777372353535851937790883648493
_D = None
_G = None


def _modp_inv(x):
    return pow(x, _Q - 2, _Q)


def _sha512_modl(s: bytes) -> int:
    """RFC 8032: the r and h scalars are reduced modulo the GROUP ORDER l,
    not the field prime q. Reducing mod q produced self-consistent but
    externally invalid signatures (caught by cross-checking against an
    independent Ed25519 implementation)."""
    return int.from_bytes(hashlib.sha512(s).digest(), "little") % _L


def _params():
    global _D, _G
    if _D is None:
        _D = -121665 * _modp_inv(121666) % _Q
        gy = 4 * _modp_inv(5) % _Q
        gx = _recover_x(gy, 0)
        _G = (gx, gy, 1, gx * gy % _Q)
    return _D, _G


def _point_add(P, Q):
    _D, _ = _params()
    q = _Q
    A = (P[1] - P[0]) * (Q[1] - Q[0]) % q
    B = (P[1] + P[0]) * (Q[1] + Q[0]) % q
    C = 2 * P[3] * Q[3] * _D % q
    D = 2 * P[2] * Q[2] % q
    E, F, G, H = B - A, D - C, D + C, B + A
    return (E * F % q, G * H % q, F * G % q, E * H % q)


def _point_mul(s: int, P):
    Q = (0, 1, 1, 0)  # neutral element
    while s > 0:
        if s & 1:
            Q = _point_add(Q, P)
        P = _point_add(P, P)
        s >>= 1
    return Q


def _point_equal(P, Q):
    q = _Q
    if (P[0] * Q[2] - Q[0] * P[2]) % q != 0:
        return False
    if (P[1] * Q[2] - Q[1] * P[2]) % q != 0:
        return False
    return True


_SQRT_M1 = None


def _recover_x(y, sign):
    global _SQRT_M1
    q = _Q
    if y >= q:
        return None
    if _SQRT_M1 is None:
        _SQRT_M1 = pow(2, (q - 1) // 4, q)
    x2 = (y * y - 1) * _modp_inv(_D * y * y + 1) % q
    if x2 == 0:
        if sign:
            return None
        return 0
    x = pow(x2, (q + 3) // 8, q)
    if (x * x - x2) % q != 0:
        x = x * _SQRT_M1 % q
    if (x * x - x2) % q != 0:
        return None
    if (x & 1) != sign:
        x = q - x
    return x


def point_compress(P) -> bytes:
    q = _Q
    zinv = _modp_inv(P[2])
    x = P[0] * zinv % q
    y = P[1] * zinv % q
    return int.to_bytes(y | ((x & 1) << 255), 32, "little")


def point_decompress(s: bytes):
    q = _Q
    if len(s) != 32:
        return None
    y = int.from_bytes(s, "little")
    sign = y >> 255
    y &= (1 << 255) - 1
    x = _recover_x(y, sign)
    if x is None:
        return None
    return (x, y, 1, x * y % q)


def _secret_expand(secret: bytes):
    if len(secret) != 32:
        raise ValueError("Ed25519 seed must be 32 bytes")
    h = hashlib.sha512(secret).digest()
    a = int.from_bytes(h[:32], "little")
    a &= (1 << 254) - 8
    a |= (1 << 254)
    return a, h[32:]


def secret_to_public(secret: bytes) -> bytes:
    _params()
    a, _ = _secret_expand(secret)
    return point_compress(_point_mul(a, _G))


def generate_seed() -> bytes:
    return secrets.token_bytes(32)


def sign(secret: bytes, msg: bytes) -> bytes:
    _params()
    a, prefix = _secret_expand(secret)
    A = point_compress(_point_mul(a, _G))
    r = _sha512_modl(prefix + msg)
    R = _point_mul(r, _G)
    Rs = point_compress(R)
    h = _sha512_modl(Rs + A + msg)
    s = (r + h * a) % _L
    return Rs + int.to_bytes(s, 32, "little")


def verify(public: bytes, msg: bytes, signature: bytes) -> bool:
    _params()
    if len(public) != 32 or len(signature) != 64:
        return False
    A = point_decompress(public)
    if not A:
        return False
    Rs = signature[:32]
    R = point_decompress(Rs)
    if not R:
        return False
    s = int.from_bytes(signature[32:], "little")
    if s >= _L:
        return False
    h = _sha512_modl(Rs + public + msg)
    sB = _point_mul(s, _G)
    hA = _point_mul(h, A)
    return _point_equal(sB, _point_add(R, hA))


def spki_der(public: bytes) -> bytes:
    """RFC 8410 SubjectPublicKeyInfo DER for an Ed25519 public key.

    The client parses it via java.security KeyFactory (X509EncodedKeySpec):
    prefix 302a300506032b6570032100 + 32-byte key.
    """
    return bytes.fromhex("302a300506032b6570032100") + public
