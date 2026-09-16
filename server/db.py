"""SQLite storage layer. One shared connection guarded by a lock (the HTTP
server is thread-per-request; traffic here is tiny)."""

import datetime
import json
import secrets
import sqlite3
import threading
from pathlib import Path

_PATH = Path(__file__).resolve().parent.parent / "data.db"
_LOCK = threading.RLock()
_CONN: sqlite3.Connection = None


def now() -> datetime.datetime:
    return datetime.datetime.now()


def iso(dt: datetime.datetime) -> str:
    return dt.strftime("%Y-%m-%dT%H:%M:%S")


def now_iso() -> str:
    return iso(now())


def init(path: Path = None):
    global _CONN, _PATH
    if path is not None:
        _PATH = path
    _CONN = sqlite3.connect(str(_PATH), check_same_thread=False)
    _CONN.row_factory = sqlite3.Row
    with _LOCK, _CONN:
        _CONN.executescript(
            """
            CREATE TABLE IF NOT EXISTS users(
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password_md5 TEXT NOT NULL,
                qq TEXT DEFAULT '',
                role TEXT DEFAULT '会员',
                expired_at TEXT DEFAULT '',
                status TEXT DEFAULT 'active',
                suspected INTEGER DEFAULT 0,
                hwid_host TEXT, hwid_userdir TEXT, hwid_uuid TEXT,
                api_token TEXT DEFAULT '',
                is_admin INTEGER DEFAULT 0,
                created_at TEXT, last_login TEXT
            );
            CREATE TABLE IF NOT EXISTS cards(
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                card_key TEXT UNIQUE NOT NULL,
                days INTEGER NOT NULL,
                used_by TEXT DEFAULT '',
                used_at TEXT DEFAULT '',
                created_at TEXT
            );
            CREATE TABLE IF NOT EXISTS sessions(
                jwt TEXT PRIMARY KEY,
                uid INTEGER NOT NULL,
                key_hex TEXT NOT NULL,
                nonce_hex TEXT NOT NULL,
                counter INTEGER NOT NULL DEFAULT 0,
                magic_hex TEXT DEFAULT '',
                ip TEXT DEFAULT '',
                version TEXT DEFAULT '',
                qq TEXT DEFAULT '',
                hwid_hex TEXT DEFAULT '',
                kicked INTEGER DEFAULT 0,
                created_at TEXT, last_seen TEXT
            );
            CREATE TABLE IF NOT EXISTS settings(
                key TEXT PRIMARY KEY,
                value TEXT
            );
            CREATE TABLE IF NOT EXISTS cloud_constants(
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                hash TEXT UNIQUE NOT NULL,
                source TEXT DEFAULT '',
                strings TEXT DEFAULT '[]'
            );
            CREATE TABLE IF NOT EXISTS logs(
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ts TEXT, type TEXT, username TEXT, ip TEXT, detail TEXT
            );
            CREATE TABLE IF NOT EXISTS orders(
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                order_id TEXT UNIQUE,
                username TEXT DEFAULT '',
                detail TEXT DEFAULT '',
                created_at TEXT
            );
            CREATE TABLE IF NOT EXISTS web_sessions(
                token TEXT PRIMARY KEY,
                username TEXT NOT NULL,
                is_admin INTEGER DEFAULT 0,
                expires_at TEXT
            );
            """
        )


def bootstrap_admin(username: str = "admin", password: str = "admin123"):
    row = query1("SELECT id FROM users WHERE is_admin=1")
    created = False
    if row is None:
        import hashlib
        execute(
            "INSERT INTO users(username,password_md5,is_admin,api_token,created_at,role,expired_at)"
            " VALUES(?,?,?,?,?,?,?)",
            (username, hashlib.md5(password.encode()).hexdigest(), 1,
             secrets.token_hex(16), now_iso(), "管理员", ""),
        )
        created = True
    return created


DEFAULT_SETTINGS = {
    "maintenance": "0",          # 1 -> login returns 9
    "service_stopped": "0",      # 1 -> login returns 6 / heartbeat returns 1
    "min_version": "",           # empty -> version check disabled (dev client sends "")
    "announcement": "欢迎使用 Phantom Shield 验证服务。",
    "roles": json.dumps({"1": "会员"}, ensure_ascii=False),
    "class_keys": "{}",          # {role_hash: hex32} for protected-jar k entries
}


def get_setting(key: str, default: str = "") -> str:
    row = query1("SELECT value FROM settings WHERE key=?", (key,))
    if row is not None:
        return row["value"]
    if key in DEFAULT_SETTINGS:
        return DEFAULT_SETTINGS[key]
    return default


def set_setting(key: str, value: str):
    execute("INSERT INTO settings(key,value) VALUES(?,?)"
            " ON CONFLICT(key) DO UPDATE SET value=excluded.value", (key, value))


def execute(sql: str, params=()):
    with _LOCK, _CONN:
        return _CONN.execute(sql, params)


def query1(sql: str, params=()):
    with _LOCK:
        return _CONN.execute(sql, params).fetchone()


def queryall(sql: str, params=()):
    with _LOCK:
        return _CONN.execute(sql, params).fetchall()


def add_log(log_type: str, username: str, ip: str, detail: str):
    try:
        execute("INSERT INTO logs(ts,type,username,ip,detail) VALUES(?,?,?,?,?)",
                (now_iso(), log_type, username or "", ip or "", detail or ""))
    except Exception:
        pass


def get_user_by_name(username: str):
    return query1("SELECT * FROM users WHERE username=?", (username,))


def get_user_by_id(uid: int):
    return query1("SELECT * FROM users WHERE id=?", (uid,))


# ---- verify sessions (jwt -> crypto stream state) ----

def save_session(jwt: str, uid: int, key: bytes, nonce: bytes, counter: int = 0,
                 magic: bytes = b"", ip: str = "", hwid_hex: str = "",
                 version: str = "", qq: str = ""):
    execute(
        "INSERT INTO sessions(jwt,uid,key_hex,nonce_hex,counter,magic_hex,ip,version,qq,hwid_hex,created_at,last_seen)"
        " VALUES(?,?,?,?,?,?,?,?,?,?,?,?)"
        " ON CONFLICT(jwt) DO UPDATE SET counter=excluded.counter,"
        " magic_hex=excluded.magic_hex, ip=excluded.ip, version=excluded.version,"
        " qq=excluded.qq, hwid_hex=excluded.hwid_hex, last_seen=excluded.last_seen",
        (jwt, uid, key.hex(), nonce.hex(), counter, magic.hex(), ip, version,
         qq, hwid_hex, now_iso(), now_iso()),
    )


def get_session(jwt: str):
    return query1("SELECT * FROM sessions WHERE jwt=?", (jwt,))


def update_stream(jwt: str, counter: int, magic: bytes = None, hwid_hex: str = None,
                  version: str = None, qq: str = None, kicked: bool = None):
    sets, params = ["counter=?"], [counter]
    if magic is not None:
        sets.append("magic_hex=?")
        params.append(magic.hex())
    if hwid_hex is not None:
        sets.append("hwid_hex=?")
        params.append(hwid_hex)
    if version is not None:
        sets.append("version=?")
        params.append(version)
    if qq is not None:
        sets.append("qq=?")
        params.append(qq)
    if kicked is not None:
        sets.append("kicked=?")
        params.append(1 if kicked else 0)
    sets.append("last_seen=?")
    params.append(now_iso())
    params.append(jwt)
    execute("UPDATE sessions SET " + ",".join(sets) + " WHERE jwt=?", params)


def delete_session(jwt: str):
    execute("DELETE FROM sessions WHERE jwt=?", (jwt,))


def online_sessions():
    return queryall("SELECT * FROM sessions ORDER BY last_seen DESC")


# ---- web sessions (cookie token) ----

def create_web_session(username: str, is_admin: bool) -> str:
    token = secrets.token_urlsafe(32)
    expires = iso(now() + datetime.timedelta(days=7))
    execute("INSERT INTO web_sessions(token,username,is_admin,expires_at) VALUES(?,?,?,?)",
            (token, username, 1 if is_admin else 0, expires))
    return token


def get_web_session(token: str):
    if not token:
        return None
    row = query1("SELECT * FROM web_sessions WHERE token=?", (token,))
    if row is None:
        return None
    try:
        if datetime.datetime.strptime(row["expires_at"], "%Y-%m-%dT%H:%M:%S") < now():
            delete_web_session(token)
            return None
    except ValueError:
        return None
    return row


def delete_web_session(token: str):
    execute("DELETE FROM web_sessions WHERE token=?", (token,))
