"""Core verification protocol: POST /api/verify/login and /api/verify/heartbeat.

Contract (verified against phantomshield-internals VerifyUtils.java):
- All requests are POST, Content-Type: application/x-www-form-urlencoded.
- Responses must be HTTP 2xx with single-line UTF-8 JSON; the client treats
  anything else as a network failure (-1). So we ALWAYS answer 200 + JSON.
- Login response: {"code":0,"entity":{"signature":b64,"data":{...}}}; the
  signature is over the client-side minjson re-serialization of `data`
  (document order, compact separators, integers as plain digits, non-ASCII
  kept raw UTF-8).
- Heartbeat: one endpoint, three plaintext types keyed by "+", "_" or "-".
  The session ChaCha20 stream is continuous across all messages: each message
  advances the block counter by ceil(len/64); the response is encrypted with
  the stream continued right after the request was decrypted.
"""

import base64
import collections
import json
import secrets
import threading
import time

from . import db, dh, ed25519, hwid as hwid_mod
from .chacha20 import ChaCha20, magic_key

_STREAM_LOCKS = {}
_STREAM_LOCKS_GUARD = threading.Lock()

_KEYS = {"seed": None, "pub": None}


def load_keys(keys_dir):
    """Load (or create) the Ed25519 seed used to sign every response."""
    seed_file = keys_dir / "ed25519_seed.bin"
    pub_file = keys_dir / "ed25519_public.bin"
    if seed_file.exists():
        seed = seed_file.read_bytes()
    else:
        seed = ed25519.generate_seed()
        keys_dir.mkdir(parents=True, exist_ok=True)
        seed_file.write_bytes(seed)
    _KEYS["seed"] = seed
    _KEYS["pub"] = ed25519.secret_to_public(seed)
    pub_file.write_bytes(_KEYS["pub"])


def _lock_for(token: str) -> threading.Lock:
    with _STREAM_LOCKS_GUARD:
        lock = _STREAM_LOCKS.get(token)
        if lock is None:
            lock = threading.Lock()
            _STREAM_LOCKS[token] = lock
        return lock


def _b64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def _compact(obj) -> bytes:
    """Byte-for-byte the JSON the client's minjson rebuilds from the parsed
    response: document order, no whitespace, ints as digits, raw UTF-8."""
    return json.dumps(obj, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def _sign(payload: bytes) -> str:
    return _b64(ed25519.sign(_KEYS["seed"], payload))


def _form(form: dict, key: str, default: str = "") -> str:
    vals = form.get(key)
    return vals[0] if vals else default


def _err(code: int) -> str:
    return json.dumps({"code": code}, separators=(",", ":"))


def _ok(entity) -> str:
    return json.dumps({"code": 0, "entity": entity}, separators=(",", ":"), ensure_ascii=False)


# ---------------------------------------------------------------- login ----

def handle_login(form: dict, headers, ip: str) -> str:
    try:
        return _login(form, headers, ip)
    except Exception:
        import traceback
        traceback.print_exc()
        db.add_log("error", _form(form, "username"), ip, "login handler exception")
        return _err(-1)


def _login(form: dict, headers, ip: str) -> str:
    username = _form(form, "username")
    password = _form(form, "password")
    hashed = _form(form, "e", "false").lower() == "true"

    def fail(code: int, log_detail: str = "") -> str:
        db.add_log("login-fail", username, ip, log_detail or f"code={code}")
        return _err(code)

    if db.get_setting("service_stopped") == "1":
        return fail(6, "service stopped")
    if db.get_setting("maintenance") == "1":
        return fail(9, "maintenance")

    user = db.get_user_by_name(username)
    if user is None:
        return fail(4, "no such user")
    import hashlib
    if hashed:
        expect = password.lower()
    else:
        expect = hashlib.md5(password.encode("utf-8")).hexdigest()
    if user["password_md5"].lower() != expect:
        return fail(4, "wrong password")
    if user["status"] == "banned":
        return fail(5, "banned")
    if user["status"] == "temp_banned":
        return fail(7, "temp banned")
    if user["role"] == "管理员" and not user["is_admin"]:
        return fail(8, "no subscription")
    if not user["expired_at"]:
        return fail(8, "no subscription")
    try:
        expiry = db.datetime.datetime.strptime(user["expired_at"], "%Y-%m-%dT%H:%M:%S")
    except (ValueError, TypeError):
        return fail(8, "no subscription")
    if expiry < db.now():
        return fail(8, "subscription expired")

    # DH: parse client values, derive server exponent and session key
    q = dh.parse_bigint(base64.b64decode(_form(form, "q")))
    m = dh.parse_bigint(base64.b64decode(_form(form, "m")))
    p = dh.parse_bigint(base64.b64decode(_form(form, "p")))
    if q <= 1 or m <= q or p <= 0:
        return fail(4, "bad dh params")
    b = dh.server_exponent()
    p_resp = pow(q, b, m)
    shared = pow(p, b, m)
    key = dh.derive_key(shared)

    nonce = secrets.token_bytes(12)
    jwt = secrets.token_urlsafe(32)

    data = collections.OrderedDict()
    data["uid"] = user["id"]
    data["jwt"] = jwt
    data["n"] = _b64(nonce)
    data["p"] = _b64(dh.java_bigint_bytes(p_resp))
    data["roles"] = [collections.OrderedDict(
        [("rank_name", user["role"] or "会员"),
         ("expired_date", user["expired_at"])])]

    payload = _compact(data)
    entity = collections.OrderedDict()
    entity["signature"] = _sign(payload)
    entity["data"] = json.loads(payload)

    db.save_session(jwt, user["id"], key, nonce, counter=0, ip=ip)
    db.execute("UPDATE users SET last_login=? WHERE id=?", (db.now_iso(), user["id"]))
    db.add_log("login", username, ip, f"uid={user['id']} ok")
    return _ok(entity)


# ------------------------------------------------------------ heartbeat ----

def handle_heartbeat(form: dict, headers, ip: str) -> str:
    token = headers.get("verify-token") or ""
    sess = db.get_session(token)
    if sess is None:
        db.add_log("error", "?", ip, f"heartbeat: unknown token {token[:8]}...")
        return _err(2)
    user = db.get_user_by_id(sess["uid"])
    if user is None:
        db.delete_session(token)
        db.add_log("error", "?", ip, "heartbeat: user gone")
        return _err(2)

    lock = _lock_for(token)
    with lock:
        ch = ChaCha20(bytes.fromhex(sess["key_hex"]), bytes.fromhex(sess["nonce_hex"]),
                      int(sess["counter"]))
        try:
            cipher = base64.b64decode(_form(form, "data"))
            plain = ch.crypt(cipher)
            obj = json.loads(plain.decode("utf-8"))
        except Exception as exc:
            db.update_stream(token, ch.counter)
            db.add_log("error", "?", ip, f"heartbeat: decrypt/parse failed: {exc}")
            return _err(-1)

        try:
            if "+" in obj:
                resp = _first_info(sess, user, obj, ch, ip)
            elif "_" in obj:
                resp = _heartbeat(sess, user, ch)
            elif "-" in obj:
                db.add_log("risk", user["username"], ip,
                           str(obj.get("r", "主动风控")))
                resp = _err(0)
            else:
                resp = _err(0)
        finally:
            db.update_stream(token, ch.counter)
        return resp


def _expired(user) -> bool:
    if not user["expired_at"]:
        return True
    try:
        return db.datetime.datetime.strptime(user["expired_at"], "%Y-%m-%dT%H:%M:%S") < db.now()
    except ValueError:
        return True


def _first_info(sess, user, obj: dict, ch: ChaCha20, ip: str) -> str:
    hwid_hex = str(obj.get("h", ""))
    version = str(obj.get("v", ""))
    qq = json.dumps([str(x) for x in obj.get("q", [])], ensure_ascii=False)

    if db.get_setting("service_stopped") == "1":
        return _err(1)
    if user["status"] in ("banned", "temp_banned"):
        return _err(1)
    if _expired(user):
        return _err(1)

    min_version = db.get_setting("min_version", "")
    if min_version and version != min_version:
        db.add_log("login-fail", user["username"], ip, f"version mismatch: {version!r}")
        return _err(4)

    info = hwid_mod.parse(hwid_hex)
    if info is None:
        db.add_log("login-fail", user["username"], ip, "hwid malformed")
        return _err(3)
    stored = {"host": user["hwid_host"], "userdir": user["hwid_userdir"],
              "uuid": user["hwid_uuid"]}
    if stored["host"] or stored["userdir"] or stored["uuid"]:
        if not hwid_mod.matches(stored, info):
            db.add_log("login-fail", user["username"], ip,
                       f"hwid mismatch {info.get('host')!r}/{info.get('userdir')!r}")
            return _err(3)
    else:
        db.execute("UPDATE users SET hwid_host=?,hwid_userdir=?,hwid_uuid=? WHERE id=?",
                   (info["host"], info["userdir"], info["uuid"], user["id"]))
        db.add_log("hwid-bind", user["username"], ip,
                   f"host={info['host']!r} uuid={info['uuid']}")

    magic = secrets.token_bytes(16)
    mk = magic_key(magic)
    kstream = ChaCha20(bytes.fromhex(sess["key_hex"]), bytes.fromhex(sess["nonce_hex"]), mk)

    c_entries = []
    for row in db.queryall("SELECT * FROM cloud_constants"):
        strings = json.loads(row["strings"])
        blob = b"".join(len(s.encode("utf-8")).to_bytes(2, "little") + s.encode("utf-8")
                        for s in strings)
        c_entries.append(collections.OrderedDict(
            [("h", str(row["hash"])), ("e", _b64(kstream.crypt(blob)))]))

    k_entries = []
    try:
        class_keys = json.loads(db.get_setting("class_keys", "{}"))
    except json.JSONDecodeError:
        class_keys = {}
    for hash_str, key_hex in class_keys.items():
        k_entries.append(collections.OrderedDict(
            [("h", str(hash_str)), ("e", _b64(kstream.crypt(bytes.fromhex(key_hex))))]))

    plain = collections.OrderedDict()
    plain["t"] = int(time.time() * 1000)
    plain["h"] = hwid_hex  # echo back verbatim: the client re-checks it locally
    plain["m"] = _b64(magic)
    plain["c"] = c_entries
    plain["k"] = k_entries

    payload = _compact(plain)
    cipher = ch.crypt(payload)
    entity = collections.OrderedDict()
    entity["signature"] = _sign(payload)
    entity["data"] = _b64(cipher)

    db.update_stream(sess["jwt"], ch.counter, magic=magic, hwid_hex=hwid_hex,
                     version=version, qq=qq)
    db.add_log("first-info", user["username"], ip,
               f"v={version!r} qq={qq} host={info['host']!r}")
    return _ok(entity)


def _heartbeat(sess, user, ch: ChaCha20) -> str:
    plain = collections.OrderedDict()
    plain["t"] = int(time.time() * 1000)
    if db.get_setting("service_stopped") == "1" or _expired(user) \
            or user["status"] in ("banned", "temp_banned"):
        plain["b"] = None  # client exits when the "b" key is present
    if sess["kicked"]:
        plain = collections.OrderedDict()
        plain["t"] = int(time.time() * 1000)
        plain["b"] = None

    payload = _compact(plain)
    cipher = ch.crypt(payload)
    entity = collections.OrderedDict()
    entity["signature"] = _sign(payload)  # client does not verify here; harmless
    entity["data"] = _b64(cipher)
    return _ok(entity)
