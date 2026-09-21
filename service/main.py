"""项目服务入口。

运行方式：
    RELAY_DB=relay.db RELAY_VAULT_KEY=<64位十六进制> python3 -m service.main

未提供 RELAY_VAULT_KEY 时使用内置开发密钥（仅限本地调试，生产必须配置）。
身份与角色通过请求头 X-Actor / X-Role 传入；正式部署应置于真实认证之后。
"""
from __future__ import annotations

import hashlib
import json
import os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

from .api import Api
from .clock import SystemClock
from .relay import Conflict, Forbidden, NotFound, RelayService, Validation
from .store import Store

DEV_VAULT_KEY = hashlib.sha256(b"relay-dev-only-insecure-key").digest()

ERROR_STATUS = (
    (Validation, 400),
    (Forbidden, 403),
    (NotFound, 404),
    (Conflict, 409),
)


class Handler(BaseHTTPRequestHandler):
    """健康检查与业务 API 入口。api 由 run() 注入；健康检查不依赖业务服务。"""

    api: Api | None = None

    def do_GET(self):
        self._dispatch("GET")

    def do_POST(self):
        self._dispatch("POST")

    def _dispatch(self, method):
        parsed = urlparse(self.path)
        if parsed.path == "/health":
            self._json(200, {"status": "ok"})
            return
        if Handler.api is None:
            self._json(503, {"error": {"code": "unavailable", "message": "业务服务未注入"}})
            return
        length = int(self.headers.get("Content-Length") or 0)
        payload = {}
        if length:
            try:
                payload = json.loads(self.rfile.read(length))
            except json.JSONDecodeError:
                self._json(400, {"error": {"code": "validation", "message": "请求体不是合法 JSON"}})
                return
        query = {k: v[0] for k, v in parse_qs(parsed.query).items()}
        actor = self.headers.get("X-Actor", "anonymous")
        role = self.headers.get("X-Role", "")
        try:
            result = Handler.api.handle(method, parsed.path, query, actor, role, payload)
        except (Validation, Forbidden, NotFound, Conflict) as exc:
            self._json(self._status_for(exc),
                       {"error": {"code": exc.code, "message": str(exc)}})
            return
        except Exception as exc:  # 兜底：未预期异常返回 500 而不是断开连接
            self._json(500, {"error": {"code": "internal", "message": f"内部错误: {exc}"}})
            return
        self._json(200, result)

    @staticmethod
    def _status_for(exc):
        for cls, status in ERROR_STATUS:
            if isinstance(exc, cls):
                return status
        return 500

    def _json(self, status, obj):
        body = json.dumps(obj, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format, *args):
        return


def build_service(db_path: str, vault_key: bytes) -> RelayService:
    """构建业务服务；启动时自动恢复未完成的封存。"""
    return RelayService(Store(db_path), SystemClock(), vault_key)


def run():
    """启动本地服务。"""
    db_path = os.environ.get("RELAY_DB", "relay.db")
    key_hex = os.environ.get("RELAY_VAULT_KEY")
    vault_key = bytes.fromhex(key_hex) if key_hex else DEV_VAULT_KEY
    Handler.api = Api(build_service(db_path, vault_key))
    ThreadingHTTPServer(("127.0.0.1", 8000), Handler).serve_forever()


if __name__ == "__main__":
    run()
