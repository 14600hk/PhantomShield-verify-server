"""HTTP layer: routing, form/JSON parsing, static file serving.

Rules that keep the Java client happy:
- /api/verify/* MUST always answer HTTP 200 with a JSON body; any 4xx/5xx or
  empty body is treated by the client as "no internet" (code -1).
- Requests are application/x-www-form-urlencoded (JDK URLEncoder: space -> '+',
  which urllib.parse.parse_qs decodes correctly).
"""

import json
import mimetypes
import traceback
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, unquote, urlparse

from . import admin_api, verify_api, web_api

WEB_DIR = Path(__file__).resolve().parent.parent / "web"

VERIFY_ROUTES = {
    "/api/verify/login": verify_api.handle_login,
    "/api/verify/heartbeat": verify_api.handle_heartbeat,
}


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "PhantomShield/0.1"

    # ------------------------------------------------------------ plumbing

    def log_message(self, fmt, *args):
        pass  # keep the console clean; business events go to the logs table

    def _send(self, status: int, body: bytes, content_type: str = "application/json; charset=utf-8",
              set_cookie: str = None):
        try:
            self.send_response(status)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            if set_cookie:
                self.send_header("Set-Cookie", set_cookie)
            self.end_headers()
            self.wfile.write(body)
        except (ConnectionResetError, BrokenPipeError):
            pass

    def _send_json(self, text: str, set_cookie: str = None, status: int = 200):
        self._send(status, text.encode("utf-8"), "application/json; charset=utf-8", set_cookie)

    def _cookies(self) -> dict:
        out = {}
        raw = self.headers.get("Cookie") or ""
        for part in raw.split(";"):
            if "=" in part:
                k, v = part.split("=", 1)
                out[k.strip()] = v.strip()
        return out

    # ------------------------------------------------------------- GET

    def do_GET(self):
        path = unquote(urlparse(self.path).path)
        if path in ("/", "/index.html", "/login", "/register"):
            return self._static("index.html")
        if path == "/dashboard":
            return self._static("dashboard.html")
        if path == "/panel":
            return self._static("panel.html")
        if path.startswith(("/css/", "/js/", "/font/", "/image/")):
            return self._static(path.lstrip("/"))
        if path == "/favicon.ico":
            return self._send(404, b"", "image/x-icon")
        self._send(404, b"not found", "text/plain; charset=utf-8")

    def _static(self, rel: str):
        file_path = (WEB_DIR / rel).resolve()
        try:
            file_path.relative_to(WEB_DIR.resolve())
        except ValueError:
            return self._send(404, b"not found", "text/plain; charset=utf-8")
        if not file_path.is_file():
            return self._send(404, b"not found", "text/plain; charset=utf-8")
        ctype = mimetypes.guess_type(str(file_path))[0] or "application/octet-stream"
        if file_path.suffix == ".js":
            ctype = "application/javascript"
        elif file_path.suffix == ".css":
            ctype = "text/css"
        self._send(200, file_path.read_bytes(),
                   f"{ctype}; charset=utf-8" if file_path.suffix in (".html", ".css", ".js") else ctype)

    # ------------------------------------------------------------ POST

    def do_POST(self):
        try:
            length = int(self.headers.get("Content-Length") or 0)
        except ValueError:
            length = 0
        raw = self.rfile.read(length) if length > 0 else b""
        body = raw.decode("utf-8", "replace")
        path = urlparse(self.path).path

        if path in VERIFY_ROUTES:
            # the Java client must always receive 200 + JSON
            print(f"[req] POST {path} from {self.client_address[0]} body={length}B", flush=True)
            form = parse_qs(body, keep_blank_values=True)
            try:
                text = VERIFY_ROUTES[path](form, self.headers,
                                           self.client_address[0])
            except Exception:
                traceback.print_exc()
                text = json.dumps({"code": -1}, separators=(",", ":"))
            return self._send_json(text)

        if path.startswith("/api/admin/"):
            action = path[len("/api/admin/"):]
            form = parse_qs(body, keep_blank_values=True)
            try:
                text = admin_api.dispatch(action, form, self.headers)
            except Exception:
                traceback.print_exc()
                text = json.dumps({"code": -1, "message": "内部错误"}, ensure_ascii=False)
            return self._send_json(text)

        if path.startswith("/api/web/"):
            action = path[len("/api/web/"):]
            try:
                data = json.loads(body) if body else {}
            except json.JSONDecodeError:
                data = {}
            if not isinstance(data, dict):
                data = {}
            text, cookie, status = web_api.dispatch(action, data, self.headers, self._cookies())
            return self._send_json(text, set_cookie=cookie, status=status)

        self._send(404, b"not found", "text/plain; charset=utf-8")


def serve(host: str, port: int):
    httpd = ThreadingHTTPServer((host, port), Handler)
    httpd.daemon_threads = True
    httpd.serve_forever()
