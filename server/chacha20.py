"""ChaCha20 stream cipher — faithful port of the client's Java implementation.

Source of truth: phantomshield-internals/src/main/java/tech/skidonion/verification/crypto/ChaCha20.java

Semantics that MUST match the Java code:
- 12-byte IETF nonce: block counter lives in matrix[12], nonce words in 13/14/15.
- The counter increments after every 64-byte keystream block is generated,
  including a trailing partial block, so a message of len bytes advances the
  stream by ceil(len/64) blocks (the tail remainder of the last block is discarded).
- encrypt and decrypt are the same XOR operation.
- The counter is 32-bit with carry into matrix[13] only (Java int arithmetic).
"""

_MASK32 = 0xFFFFFFFF


def _rotl(v: int, c: int) -> int:
    return ((v << c) | (v >> (32 - c))) & _MASK32


class ChaCha20:
    KEY_SIZE = 32
    NONCE_SIZE_REF = 8
    NONCE_SIZE_IETF = 12

    def __init__(self, key: bytes, nonce: bytes, counter: int = 0):
        if len(key) != self.KEY_SIZE:
            raise ValueError("key must be 32 bytes")
        m = [0x61707865, 0x3320646E, 0x79622D32, 0x6B206574]
        m += [int.from_bytes(key[i * 4:(i + 1) * 4], "little") for i in range(8)]
        if len(nonce) == self.NONCE_SIZE_IETF:
            m += [counter & _MASK32,
                  int.from_bytes(nonce[0:4], "little"),
                  int.from_bytes(nonce[4:8], "little"),
                  int.from_bytes(nonce[8:12], "little")]
        elif len(nonce) == self.NONCE_SIZE_REF:
            m += [0, 0,
                  int.from_bytes(nonce[0:4], "little"),
                  int.from_bytes(nonce[4:8], "little")]
        else:
            raise ValueError("nonce must be 8 or 12 bytes")
        self._m = m

    @property
    def counter(self) -> int:
        return self._m[12]

    def _keystream_block(self) -> bytes:
        x = list(self._m)
        for _ in range(10):
            # column rounds
            self._quarter(x, 0, 4, 8, 12)
            self._quarter(x, 1, 5, 9, 13)
            self._quarter(x, 2, 6, 10, 14)
            self._quarter(x, 3, 7, 11, 15)
            # diagonal rounds
            self._quarter(x, 0, 5, 10, 15)
            self._quarter(x, 1, 6, 11, 12)
            self._quarter(x, 2, 7, 8, 13)
            self._quarter(x, 3, 4, 9, 14)
        out = bytearray(64)
        for i in range(16):
            out[4 * i:4 * i + 4] = ((x[i] + self._m[i]) & _MASK32).to_bytes(4, "little")
        # Java: counter++ after each generated block, carry into matrix[13]
        self._m[12] = (self._m[12] + 1) & _MASK32
        if self._m[12] == 0:
            self._m[13] = (self._m[13] + 1) & _MASK32
        return bytes(out)

    @staticmethod
    def _quarter(x, a, b, c, d):
        x[a] = (x[a] + x[b]) & _MASK32
        x[d] = _rotl(x[d] ^ x[a], 16)
        x[c] = (x[c] + x[d]) & _MASK32
        x[b] = _rotl(x[b] ^ x[c], 12)
        x[a] = (x[a] + x[b]) & _MASK32
        x[d] = _rotl(x[d] ^ x[a], 8)
        x[c] = (x[c] + x[d]) & _MASK32
        x[b] = _rotl(x[b] ^ x[c], 7)

    def crypt(self, data: bytes) -> bytes:
        """XOR data with the keystream, advancing the stream by ceil(len/64) blocks."""
        out = bytearray(len(data))
        pos, n = 0, len(data)
        while n > 0:
            ks = self._keystream_block()
            take = min(64, n)
            for i in range(take):
                out[pos + i] = data[pos + i] ^ ks[i]
            pos += take
            n -= take
        return bytes(out)

    # Java-compatible aliases
    encrypt = crypt
    decrypt = crypt


def magic_key(magic: bytes) -> int:
    """Derive the per-response magic counter from the 16-byte magic value.

    Mirrors VerifyUtils.java:192-203:
      base = base | magic[i]&0xFF; i%4==3 -> magicKey ^= base, base=0; else base <<= 8
    """
    mk = 0
    base = 0
    for i in range(16):
        base = (base | (magic[i] & 0xFF)) & _MASK32
        if i % 4 == 3:
            mk ^= base
            base = 0
        else:
            base = (base << 8) & _MASK32
    return mk & _MASK32
