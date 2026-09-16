"""HWID parsing for the Phantom-Shield client machine ID.

Client encoding (MachineIDUtils.generate, MachineIDUtils.java:23-106):
    raw = 0xFF 0x04 | <4..8 random bytes> | 0x00
          | 0x01 <u16 len> hostname | 0x02 <u16 len> "user.home-user.name"
          | 0x03 <u8 len> 16B uuid-file | 0x00 | <random pad> | 0x04 0xFF
    hex  = for each byte i: lowercase hex of (raw[i] ^ UNIQUE[i % 8])
Because the noise/pad bytes are random per call, the server must compare the
semantic TLV fields (hostname / userdir / uuid), never the raw string.
"""

UNIQUE = bytes([82, 0xF9, 0xA3, 0xCB, 0x8F, 0x6B, 0x81, 0x08])


def decode(hex_str: str) -> bytes:
    encoded = bytes.fromhex(hex_str.strip().lower())
    return bytes(b ^ UNIQUE[i % len(UNIQUE)] for i, b in enumerate(encoded))


def parse(hex_str: str):
    """Return dict {host, userdir, uuid} with None for absent fields.
    Returns None if the structure is malformed (bad header/tail)."""
    try:
        raw = decode(hex_str)
    except ValueError:
        return None
    if len(raw) < 6:
        return None
    if raw[0] != 0xFF or raw[1] != 0x04:
        return None
    if raw[-1] != 0xFF or raw[-2] != 0x04:
        return None

    info = {"host": None, "userdir": None, "uuid": None}
    i = 2
    # skip the random noise bytes up to (and past) the 0x00 separator
    while i < len(raw) and raw[i] != 0x00:
        i += 1
    i += 1
    while i < len(raw) - 2:
        tag = raw[i]
        if tag == 0x00:
            break
        if tag == 0x01:
            if i + 3 > len(raw):
                break
            n = int.from_bytes(raw[i + 1:i + 3], "big")
            info["host"] = raw[i + 3:i + 3 + n].decode("utf-8", "replace")
            i += 3 + n
        elif tag == 0x02:
            if i + 3 > len(raw):
                break
            n = int.from_bytes(raw[i + 1:i + 3], "big")
            info["userdir"] = raw[i + 3:i + 3 + n].decode("utf-8", "replace")
            i += 3 + n
        elif tag == 0x03:
            if i + 2 > len(raw):
                break
            n = raw[i + 1]
            info["uuid"] = raw[i + 2:i + 2 + n].hex()
            i += 2 + n
            break  # uuid block is last before the 0x00 terminator
        else:
            break
    return info


def matches(stored: dict, current: dict) -> bool:
    """Every semantic field present in both must be equal; fields the client
    omitted (budget overflow) are not compared. Requires at least one match."""
    checked = 0
    for key in ("host", "userdir", "uuid"):
        s, c = stored.get(key), current.get(key)
        if s is not None and c is not None:
            if s != c:
                return False
            checked += 1
    return checked > 0
