"""Phantom Shield verification server — entry point.

Zero third-party dependencies: pure Python 3.8+ standard library.

    python run.py            # serve on 0.0.0.0:8694 (config.json)

The dev client hardcodes http://localhost:8694/ (Internals.java), so keep the
port at 8694 unless you re-build the client.
"""

import json
import socket
import sys
from pathlib import Path

BASE = Path(__file__).resolve().parent
sys.path.insert(0, str(BASE))

from server import app, db, verify_api  # noqa: E402

CONFIG_FILE = BASE / "config.json"

DEFAULT_CONFIG = {
    "host": "0.0.0.0",
    "port": 8694,
    "software_id": 1,
    "admin_username": "admin",
    "admin_password": "admin123",
}


def load_config() -> dict:
    if CONFIG_FILE.exists():
        cfg = json.loads(CONFIG_FILE.read_text("utf-8"))
    else:
        cfg = dict(DEFAULT_CONFIG)
        CONFIG_FILE.write_text(json.dumps(cfg, indent=2, ensure_ascii=False), "utf-8")
    return {**DEFAULT_CONFIG, **cfg}


def main():
    cfg = load_config()
    db.init(BASE / "data.db")
    verify_api.load_keys(BASE / "keys")
    created = db.bootstrap_admin(cfg["admin_username"], cfg["admin_password"])

    print("=" * 56)
    print("  Phantom Shield verification server")
    print(f"  listening : http://{local_ip()}:{cfg['port']}  (client expects http://localhost:{cfg['port']}/)")
    print(f"  endpoints : /api/verify/login  /api/verify/heartbeat")
    print(f"              /api/admin/*       (uid + api-token headers)")
    print(f"  web panel : http://localhost:{cfg['port']}/            (login)")
    print(f"              http://localhost:{cfg['port']}/#/register (user register)")
    print(f"              http://localhost:{cfg['port']}/dashboard   (admin)")
    if created:
        print(f"  bootstrap : admin account created -> "
              f"{cfg['admin_username']} / {cfg['admin_password']}  (CHANGE IT!)")
    print("=" * 56)

    try:
        app.serve(cfg["host"], int(cfg["port"]))
    except KeyboardInterrupt:
        print("\nbye")


def local_ip() -> str:
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except OSError:
        return "127.0.0.1"


if __name__ == "__main__":
    main()
