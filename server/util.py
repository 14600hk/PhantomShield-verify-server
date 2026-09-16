"""Small shared helpers."""

import json


def java_string_hash(s: str) -> int:
    """Java String.hashCode(): h = 31*h + c with 32-bit signed overflow.
    Used as the key for cloud constants (VerifyUtils.getCloudConstant)."""
    h = 0
    for ch in s:
        h = (31 * h + ord(ch)) & 0xFFFFFFFF
    if h >= 2 ** 31:
        h -= 2 ** 32
    return h


def dump(obj) -> str:
    return json.dumps(obj, separators=(",", ":"), ensure_ascii=False)
