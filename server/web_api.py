"""Web panel API (cookie-authenticated JSON). Requests come from the bundled
dashboard / panel pages as JSON POST bodies; responses are {"success":bool,...}.

Passwords are MD5-hashed in the browser before they ever reach the server, so
the stored value is byte-identical to what the Java client sends on login.
"""

import base64
import datetime
import hashlib
import json
import re
import secrets

from . import db, util

COOKIE = "ps_session"
_USERNAME_RE = re.compile(r"^[A-Za-z0-9_\u4e00-\u9fa5]{3,20}$")


def _fail(message: str, code: int = 401) -> tuple:
    return util.dump({"success": False, "message": message}), None, code


def _ok(data=None, message: str = "ok") -> tuple:
    body = {"success": True, "message": message}
    if data is not None:
        body["data"] = data
    return util.dump(body), None, 200


def dispatch(action: str, body: dict, headers, cookies) -> tuple:
    """Returns (json_text, set_cookie_or_None, http_status)."""
    try:
        return _dispatch(action, body, headers, cookies)
    except Exception as exc:
        db.add_log("error", "?", "-", f"web api {action}: {exc}")
        return _fail("服务器内部错误", 500)


def _dispatch(action: str, body: dict, headers, cookies) -> tuple:
    token = cookies.get(COOKIE, "")
    sess = db.get_web_session(token)

    if action == "login":
        return _login(body)
    if action == "register":
        return _register(body)
    if action == "logout":
        if sess is not None:
            db.delete_web_session(token)
        return _ok(message="已退出")

    if sess is None:
        return _fail("未登录")
    user = db.get_user_by_name(sess["username"])
    if user is None:
        return _fail("账号不存在")

    if action == "me":
        return _ok({"username": user["username"], "is_admin": bool(user["is_admin"])})

    if action == "user/info":
        hwid_bound = bool(user["hwid_host"] or user["hwid_userdir"] or user["hwid_uuid"])
        return _ok({
            "username": user["username"],
            "qq": user["qq"],
            "role": user["role"],
            "expired_at": user["expired_at"],
            "status": user["status"],
            "suspected": bool(user["suspected"]),
            "hwid_bound": hwid_bound,
            "hwid_host": user["hwid_host"] or "",
            "created_at": user["created_at"],
            "last_login": user["last_login"],
            "announcement": db.get_setting("announcement", ""),
        })

    if action == "user/redeem":
        return _redeem(user, str(body.get("card", "")).strip())

    if action == "user/change-password":
        old = str(body.get("old", "")).lower()
        new = str(body.get("new", "")).lower()
        if not re.fullmatch(r"[0-9a-f]{32}", new):
            return _fail("密码哈希格式错误")
        if user["password_md5"].lower() != old:
            return _fail("旧密码错误")
        db.execute("UPDATE users SET password_md5=? WHERE id=?", (new, user["id"]))
        db.add_log("user", user["username"], "-", "password changed via web")
        return _ok(message="密码已修改")

    # ---- everything below is admin-only ----
    if not user["is_admin"]:
        return _fail("需要管理员权限", 403)

    if action == "admin/stats":
        total = db.query1("SELECT COUNT(*) c FROM users WHERE is_admin=0")["c"]
        online = db.query1("SELECT COUNT(*) c FROM sessions")["c"]
        unused = db.query1("SELECT COUNT(*) c FROM cards WHERE used_by=''")["c"]
        banned = db.query1(
            "SELECT COUNT(*) c FROM users WHERE status!='active' AND is_admin=0")["c"]
        return _ok({"total_users": total, "online_users": online,
                    "unused_cards": unused, "banned_users": banned})

    if action == "admin/users":
        q = str(body.get("q", "")).strip()
        if q:
            rows = db.queryall(
                "SELECT * FROM users WHERE is_admin=0 AND username LIKE ? ORDER BY id",
                (f"%{q}%",))
        else:
            rows = db.queryall("SELECT * FROM users WHERE is_admin=0 ORDER BY id")
        users = [{
            "uid": r["id"], "username": r["username"], "qq": r["qq"],
            "role": r["role"], "expired_at": r["expired_at"], "status": r["status"],
            "suspected": bool(r["suspected"]),
            "hwid_host": r["hwid_host"] or "", "hwid_uuid": (r["hwid_uuid"] or "")[:16],
            "created_at": r["created_at"], "last_login": r["last_login"] or "",
        } for r in rows]
        return _ok({"users": users})

    if action == "admin/user/create":
        return _admin_create_user(body)

    if action == "admin/user/delete":
        target = db.get_user_by_name(str(body.get("username", "")))
        if target is None or target["is_admin"]:
            return _fail("用户不存在")
        db.execute("DELETE FROM users WHERE id=?", (target["id"],))
        db.execute("DELETE FROM sessions WHERE uid=?", (target["id"],))
        db.add_log("user", target["username"], "-", "deleted by admin")
        return _ok(message="已删除")

    if action == "admin/user/ban":
        target = db.get_user_by_name(str(body.get("username", "")))
        if target is None or target["is_admin"]:
            return _fail("用户不存在")
        banned = bool(body.get("banned"))
        db.execute("UPDATE users SET status=? WHERE id=?",
                   ("banned" if banned else "active", target["id"]))
        if banned:
            db.execute("UPDATE sessions SET kicked=1 WHERE uid=?", (target["id"],))
        db.add_log("user", target["username"], "-",
                   "banned" if banned else "unbanned")
        return _ok(message="已封禁" if banned else "已解封")

    if action == "admin/user/reset-hwid":
        target = db.get_user_by_name(str(body.get("username", "")))
        if target is None:
            return _fail("用户不存在")
        db.execute("UPDATE users SET hwid_host=NULL,hwid_userdir=NULL,hwid_uuid=NULL WHERE id=?",
                   (target["id"],))
        db.execute("UPDATE sessions SET kicked=1 WHERE uid=?", (target["id"],))
        db.add_log("user", target["username"], "-", "hwid reset")
        return _ok(message="HWID 已重置")

    if action == "admin/user/set-expiry":
        target = db.get_user_by_name(str(body.get("username", "")))
        if target is None:
            return _fail("用户不存在")
        expired = str(body.get("expired_at", "")).strip()
        try:
            days = int(expired)
            base = db.now()
            if target["expired_at"]:
                try:
                    cur = datetime.datetime.strptime(target["expired_at"], "%Y-%m-%dT%H:%M:%S")
                    if cur > base:
                        base = cur
                except ValueError:
                    pass
            new_expiry = (base + datetime.timedelta(days=days)).strftime("%Y-%m-%dT%H:%M:%S")
        except ValueError:
            for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S"):
                try:
                    new_expiry = datetime.datetime.strptime(expired, fmt).strftime("%Y-%m-%dT%H:%M:%S")
                    break
                except ValueError:
                    continue
            else:
                return _fail("日期格式错误")
        db.execute("UPDATE users SET expired_at=? WHERE id=?", (new_expiry, target["id"]))
        db.add_log("user", target["username"], "-", f"expiry -> {new_expiry}")
        return _ok(message=f"到期时间已设为 {new_expiry}")

    if action == "admin/user/reset-password":
        target = db.get_user_by_name(str(body.get("username", "")))
        if target is None:
            return _fail("用户不存在")
        new = str(body.get("password", "")).lower()
        if not re.fullmatch(r"[0-9a-f]{32}", new):
            return _fail("密码哈希格式错误")
        db.execute("UPDATE users SET password_md5=? WHERE id=?", (new, target["id"]))
        db.execute("UPDATE sessions SET kicked=1 WHERE uid=?", (target["id"],))
        db.add_log("user", target["username"], "-", "password reset by admin")
        return _ok(message="密码已重置")

    if action == "admin/cards":
        rows = db.queryall("SELECT * FROM cards ORDER BY id DESC LIMIT 500")
        cards = [{"id": r["id"], "card_key": r["card_key"], "days": r["days"],
                  "used_by": r["used_by"], "used_at": r["used_at"],
                  "created_at": r["created_at"]} for r in rows]
        return _ok({"cards": cards})

    if action == "admin/cards/generate":
        prefix = str(body.get("prefix", "PS")).strip() or "PS"
        try:
            amount = max(1, min(500, int(body.get("amount", 1))))
            days = max(1, min(3650, int(body.get("days", 30))))
        except (TypeError, ValueError):
            return _fail("数量/天数必须是数字")
        keys = []
        for _ in range(amount):
            key = f"{prefix}-{secrets.token_hex(10).upper()}"
            db.execute("INSERT INTO cards(card_key,days,created_at) VALUES(?,?,?)",
                       (key, days, db.now_iso()))
            keys.append(key)
        db.add_log("card", user["username"], "-", f"generate {amount}x{days}d prefix={prefix}")
        return _ok({"cards": keys}, f"已生成 {amount} 张 {days} 天卡密")

    if action == "admin/cards/delete":
        cid = body.get("id")
        db.execute("DELETE FROM cards WHERE id=? AND used_by=''", (cid,))
        return _ok(message="已删除")

    if action == "admin/sessions":
        rows = db.online_sessions()
        sessions = []
        for r in rows:
            u = db.get_user_by_id(r["uid"])
            sessions.append({
                "jwt": r["jwt"], "username": u["username"] if u else f"uid={r['uid']}",
                "ip": r["ip"], "version": r["version"], "qq": r["qq"],
                "hwid": (r["hwid_hex"] or "")[:32] + "...",
                "created_at": r["created_at"], "last_seen": r["last_seen"],
                "kicked": bool(r["kicked"]),
            })
        return _ok({"sessions": sessions})

    if action == "admin/sessions/kick":
        jwt = str(body.get("jwt", ""))
        if db.get_session(jwt) is None:
            return _fail("会话不存在")
        db.update_stream(jwt, _current_counter(jwt), kicked=True)
        db.add_log("user", "?", "-", f"kicked session {jwt[:8]}")
        return _ok(message="已踢下线（下次心跳生效）")

    if action == "admin/settings":
        return _ok({
            "maintenance": db.get_setting("maintenance") == "1",
            "service_stopped": db.get_setting("service_stopped") == "1",
            "min_version": db.get_setting("min_version", ""),
            "announcement": db.get_setting("announcement", ""),
        })

    if action == "admin/settings/save":
        if "maintenance" in body:
            db.set_setting("maintenance", "1" if body["maintenance"] else "0")
        if "service_stopped" in body:
            db.set_setting("service_stopped", "1" if body["service_stopped"] else "0")
        if "min_version" in body:
            db.set_setting("min_version", str(body["min_version"]).strip())
        if "announcement" in body:
            db.set_setting("announcement", str(body["announcement"]))
        db.add_log("admin", user["username"], "-", "settings updated")
        return _ok(message="设置已保存")

    if action == "admin/cloud":
        rows = db.queryall("SELECT * FROM cloud_constants ORDER BY id")
        from .util import java_string_hash
        items = [{"id": r["id"], "hash": r["hash"], "source": r["source"],
                  "strings": json.loads(r["strings"])} for r in rows]
        return _ok({"constants": items})

    if action == "admin/cloud/add":
        from .util import java_string_hash
        source = str(body.get("source", "")).strip()
        strings = [str(s) for s in body.get("strings", []) if str(s).strip()]
        if source:
            hash_str = str(java_string_hash(source))
        else:
            hash_str = str(body.get("hash", "")).strip()
        if not hash_str or not strings:
            return _fail("需要角色名（自动计算 hash）或 hash，且至少一条常量")
        try:
            int(hash_str)
        except ValueError:
            return _fail("hash 必须是整数")
        db.execute(
            "INSERT INTO cloud_constants(hash,source,strings) VALUES(?,?,?)"
            " ON CONFLICT(hash) DO UPDATE SET strings=excluded.strings, source=excluded.source",
            (hash_str, source, util.dump(strings)))
        db.add_log("admin", user["username"], "-", f"cloud constant {hash_str} updated")
        return _ok(message="云常量已保存")

    if action == "admin/cloud/delete":
        db.execute("DELETE FROM cloud_constants WHERE id=?", (body.get("id"),))
        return _ok(message="已删除")

    if action == "admin/logs":
        rows = db.queryall("SELECT * FROM logs ORDER BY id DESC LIMIT 300")
        logs = [{"id": r["id"], "ts": r["ts"], "type": r["type"],
                 "username": r["username"], "ip": r["ip"], "detail": r["detail"]}
                for r in rows]
        return _ok({"logs": logs})

    return _fail(f"未知操作: {action}", 404)


def _current_counter(jwt: str) -> int:
    sess = db.get_session(jwt)
    return int(sess["counter"]) if sess else 0


def _login(body: dict) -> tuple:
    username = str(body.get("username", "")).strip()
    password = str(body.get("password", "")).lower()
    user = db.get_user_by_name(username)
    if user is None or user["password_md5"].lower() != password:
        db.add_log("web-login-fail", username, "-", "wrong credentials")
        return _fail("用户名或密码错误", 200)
    web_token = db.create_web_session(username, bool(user["is_admin"]))
    db.add_log("web-login", username, "-", "ok")
    cookie = f"{COOKIE}={web_token}; Path=/; HttpOnly; SameSite=Lax; Max-Age=604800"
    return util.dump({"success": True, "is_admin": bool(user["is_admin"])}), cookie, 200


def _register(body: dict) -> tuple:
    username = str(body.get("username", "")).strip()
    password = str(body.get("password", "")).lower()
    qq = str(body.get("qq", "")).strip()
    card = str(body.get("card", "")).strip()
    if not _USERNAME_RE.fullmatch(username):
        return _fail("用户名需 3-20 位字母/数字/下划线/中文", 200)
    if not re.fullmatch(r"[0-9a-f]{32}", password):
        return _fail("密码格式错误", 200)
    if qq and not re.fullmatch(r"\d{5,11}", qq):
        return _fail("QQ 号格式不正确", 200)
    if db.get_user_by_name(username) is not None:
        return _fail("用户名已存在", 200)
    expired = ""
    if card:
        row = db.query1("SELECT * FROM cards WHERE card_key=? AND used_by=''", (card,))
        if row is None:
            return _fail("卡密无效或已被使用", 200)
        expired = (db.now() + datetime.timedelta(days=row["days"])).strftime("%Y-%m-%dT%H:%M:%S")
        db.execute("UPDATE cards SET used_by=?, used_at=? WHERE id=?",
                   (username, db.now_iso(), row["id"]))
    db.execute(
        "INSERT INTO users(username,password_md5,qq,expired_at,created_at) VALUES(?,?,?,?,?)",
        (username, password, qq, expired, db.now_iso()))
    if card:
        db.add_log("register", username, "-", f"registered with card {card[:10]}...")
    else:
        db.add_log("register", username, "-", "registered (no subscription)")
    return _ok(message="注册成功，请登录")


def _redeem(user, card: str) -> tuple:
    if not card:
        return _fail("请输入卡密", 200)
    row = db.query1("SELECT * FROM cards WHERE card_key=? AND used_by=''", (card,))
    if row is None:
        return _fail("卡密无效或已被使用", 200)
    base = db.now()
    if user["expired_at"]:
        try:
            cur = datetime.datetime.strptime(user["expired_at"], "%Y-%m-%dT%H:%M:%S")
            if cur > base:
                base = cur
        except ValueError:
            pass
    new_expiry = (base + datetime.timedelta(days=row["days"])).strftime("%Y-%m-%dT%H:%M:%S")
    db.execute("UPDATE users SET expired_at=? WHERE id=?", (new_expiry, user["id"]))
    db.execute("UPDATE cards SET used_by=?, used_at=? WHERE id=?",
               (user["username"], db.now_iso(), row["id"]))
    db.add_log("card", user["username"], "-", f"redeemed {row['days']}d -> {new_expiry}")
    return _ok({"expired_at": new_expiry}, f"充值成功，到期时间 {new_expiry}")
