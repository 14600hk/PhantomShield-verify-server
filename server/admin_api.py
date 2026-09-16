"""Admin API for the Phantom-Shield obfuscator GUI.

POST /api/admin/<action>, form-encoded, authenticated with the headers
    phantom-shield-x-uid: <uid>
    phantom-shield-x-api-token: <api token>
Response contract (HttpUtilsTest.java:86): {"code":0,"message":"成功","entity":{"data":...}}
"""

import datetime
import json
import secrets

from . import db, util


def _fail(message: str, code: int = 1) -> str:
    return util.dump({"code": code, "message": message})


def _ok(data, message: str = "成功") -> str:
    return util.dump({"code": 0, "message": message, "entity": {"data": data}})


def _auth(headers):
    try:
        uid = int(headers.get("phantom-shield-x-uid") or "0")
    except ValueError:
        return None
    token = headers.get("phantom-shield-x-api-token") or ""
    user = db.get_user_by_id(uid)
    if user is None or not user["is_admin"] or not token or user["api_token"] != token:
        return None
    return user


def _user_info(user) -> dict:
    hwid = " / ".join(x for x in
                      (user["hwid_host"], user["hwid_userdir"],
                       (user["hwid_uuid"] or "")[:16]) if x)
    return {
        "uid": user["id"],
        "username": user["username"],
        "qq": user["qq"],
        "role": user["role"],
        "expired_date": user["expired_at"],
        "status": user["status"],
        "suspected": bool(user["suspected"]),
        "hwid": hwid,
        "created_at": user["created_at"],
        "last_login": user["last_login"],
    }


def _parse_expired(raw: str):
    raw = (raw or "").strip()
    for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S", "%Y/%m/%d %H:%M:%S"):
        try:
            return datetime.datetime.strptime(raw, fmt).strftime("%Y-%m-%dT%H:%M:%S")
        except ValueError:
            continue
    return None


def dispatch(action: str, form: dict, headers) -> str:
    admin = _auth(headers)
    if admin is None:
        return _fail("身份验证失败", 401)

    def get(key: str, default: str = "") -> str:
        vals = form.get(key)
        return vals[0] if vals else default

    if action == "software-information":
        total = db.query1("SELECT COUNT(*) c FROM users WHERE is_admin=0")["c"]
        online = db.query1("SELECT COUNT(*) c FROM sessions")["c"]
        cards = db.query1("SELECT COUNT(*) c FROM cards WHERE used_by=''")["c"]
        return _ok({
            "software_id": get("software_id"),
            "name": "Phantom Shield",
            "total_users": total,
            "online_users": online,
            "unused_cards": cards,
        })

    if action in ("whois", "user-information"):
        user = db.get_user_by_name(get("username"))
        if user is None:
            return _fail("用户不存在")
        return _ok(_user_info(user))

    if action == "query-order":
        order = db.query1("SELECT * FROM orders WHERE order_id=?", (get("order_id"),))
        if order is None:
            return _fail("订单不存在")
        return _ok({"order_id": order["order_id"], "username": order["username"],
                    "detail": order["detail"], "created_at": order["created_at"]})

    if action == "set-as-suspected":
        user = db.get_user_by_name(get("username"))
        if user is None:
            return _fail("用户不存在")
        db.execute("UPDATE users SET suspected=1 WHERE id=?", (user["id"],))
        db.add_log("risk", user["username"], "-", "admin set-as-suspected: " + get("reason"))
        return _ok({"username": user["username"], "suspected": True})

    if action == "remove-suspected":
        user = db.get_user_by_name(get("username"))
        if user is None:
            return _fail("用户不存在")
        db.execute("UPDATE users SET suspected=0 WHERE id=?", (user["id"],))
        return _ok({"username": user["username"], "suspected": False})

    if action == "generate-card":
        prefix = get("card_id", "PS").strip() or "PS"
        try:
            amount = max(1, min(500, int(get("amount", "1"))))
        except ValueError:
            return _fail("amount 必须是数字")
        keys = []
        for _ in range(amount):
            key = f"{prefix}-{secrets.token_hex(10).upper()}"
            db.execute("INSERT INTO cards(card_key,days,created_at) VALUES(?,?,?)",
                       (key, 30, db.now_iso()))
            keys.append(key)
        db.add_log("card", admin["username"], "-", f"generate {amount} card(s) prefix={prefix}")
        return _ok({"cards": keys, "amount": amount})

    if action == "user-online":
        sess = db.get_session(get("token"))
        if sess is None:
            return _fail("会话不存在或已离线")
        user = db.get_user_by_id(sess["uid"])
        return _ok({
            "jwt": sess["jwt"][:8] + "...",
            "username": user["username"] if user else f"uid={sess['uid']}",
            "ip": sess["ip"],
            "version": sess["version"],
            "last_seen": sess["last_seen"],
        })

    if action == "set-user-expired-date":
        user = db.get_user_by_name(get("username"))
        if user is None:
            return _fail("用户不存在")
        expired = _parse_expired(get("expired_date"))
        if expired is None:
            return _fail("日期格式必须为 2077-01-01 00:00:00")
        role_id = get("role_id", "")
        role = user["role"]
        try:
            roles = json.loads(db.get_setting("roles", "{}"))
        except json.JSONDecodeError:
            roles = {}
        if role_id and role_id in roles:
            role = roles[role_id]
        db.execute("UPDATE users SET expired_at=?, role=? WHERE id=?",
                   (expired, role, user["id"]))
        db.add_log("user", admin["username"], "-",
                   f"set-expired {user['username']} -> {expired} role={role}")
        return _ok({"username": user["username"], "expired_date": expired, "role": role})

    return _fail(f"未知操作: {action}")
