"""家书接力站服务入口。

HTTP 仅为领域服务的薄适配层：鉴权信息由调用方在 JSON 的 "actor" 中提供
（{id, roles}，生产环境应替换为网关注入的已验证身份）。

数据目录由环境变量 LETTER_RELAY_HOME 指定，默认为 ./data。
独立运行：python3 -m service.main
"""
from __future__ import annotations

import json
import os
import re
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit

from .events import DomainError, EventStore
from .relay import LetterRelay
from .vault import Vault

_HOME = os.environ.get("LETTER_RELAY_HOME", os.path.join(os.getcwd(), "data"))


def build_service(home: str | None = None) -> LetterRelay:
    """根据数据目录构建服务（崩溃恢复 = 重放哈希链事件日志）。"""
    home = home or _HOME
    os.makedirs(home, exist_ok=True)
    key_path = os.path.join(home, "master.key")
    if os.path.exists(key_path):
        with open(key_path, encoding="utf-8") as f:
            key = bytes.fromhex(f.read().strip())
    else:
        from .crypto import new_master_key
        key = new_master_key()
        with open(key_path, "w", encoding="utf-8") as f:
            f.write(key.hex())
    store = EventStore(os.path.join(home, "events.log"))
    return LetterRelay(store, Vault(key))


def build_default_service() -> LetterRelay:
    return build_service(_HOME)


class Handler(BaseHTTPRequestHandler):
    service: LetterRelay | None = None  # 由 run()/测试注入

    def _json(self, status: int, payload: dict) -> None:
        body = json.dumps(payload, ensure_ascii=False, default=str).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _read_body(self) -> dict:
        length = int(self.headers.get("Content-Length") or 0)
        if not length:
            return {}
        raw = self.rfile.read(length)
        try:
            data = json.loads(raw)
        except json.JSONDecodeError:
            raise DomainError("bad_json", "请求体不是合法 JSON")
        if not isinstance(data, dict):
            raise DomainError("bad_request", "请求体必须是 JSON 对象")
        return data

    def _service(self) -> LetterRelay:
        if Handler.service is None:
            # 惰性初始化，避免导入模块即写盘
            Handler.service = build_default_service()
        return Handler.service

    def do_GET(self):
        self._dispatch("GET")

    def do_POST(self):
        self._dispatch("POST")

    # 路由：(method, pattern) -> handler(payload, groups)
    ROUTES = None  # 类创建后填充

    def _dispatch(self, method: str) -> None:
        try:
            parsed = urlsplit(self.path)
            path = parsed.path.rstrip("/") or "/"
            payload = self._read_body() if method == "POST" else {}
            for m, pattern in _ROUTES:
                if m != method:
                    continue
                match = re.fullmatch(pattern, path)
                if match:
                    # 健康检查不触发服务构建，保持无副作用
                    svc = None if path == "/health" else self._service()
                    result, status = _ROUTES[(m, pattern)](
                        svc, payload, match.groupdict())
                    self._json(status, result)
                    return
            self._json(404, {"error": "not_found", "message": path})
        except DomainError as exc:
            self._json(exc.status, {"error": exc.code, "message": str(exc)})
        except Exception as exc:  # noqa: BLE001 - 适配层兜底
            self._json(500, {"error": "internal", "message": str(exc)})

    def log_message(self, format, *args):
        return


def _ok(result: dict | None = None, status: int = 200):
    return result or {}, status


def _make_routes() -> dict:
    routes = {}

    def route(method: str, pattern: str):
        def register(fn):
            routes[(method, pattern)] = fn
            return fn
        return register

    @route("GET", r"/health")
    def health(svc, p, g):
        return {"status": "ok"}, 200

    @route("POST", r"/letters/import")
    def import_letter(svc, p, g):
        return _ok(svc.import_letter(
            p.get("actor"), p["school_code"], p["source_key"],
            p["request_id"], p["body"], p.get("pii", {}),
            event_time=p.get("event_time")), 201)

    @route("POST", r"/letters/(?P<lid>L-[0-9a-f]+)/consent/grant")
    def grant(svc, p, g):
        return _ok(svc.grant_consent(
            p["actor"], g["lid"], p["scopes"],
            p.get("valid_from"), p.get("valid_until")))

    @route("POST", r"/letters/(?P<lid>L-[0-9a-f]+)/consent/revoke")
    def revoke(svc, p, g):
        return _ok(svc.revoke_consent(p["actor"], g["lid"],
                                      p.get("reason", "")))

    @route("GET", r"/letters/(?P<lid>L-[0-9a-f]+)")
    def letter(svc, p, g):
        return _ok(svc.letter_view(g["lid"]))

    @route("GET", r"/letters/(?P<lid>L-[0-9a-f]+)/propagation")
    def propagation(svc, p, g):
        return _ok(svc.propagation_report(g["lid"]))

    @route("POST", r"/letters/(?P<lid>L-[0-9a-f]+)/review")
    def review(svc, p, g):
        return _ok(svc.decide_review(p["actor"], g["lid"],
                                     p["result"], p.get("note", "")))

    @route("POST", r"/letters/(?P<lid>L-[0-9a-f]+)/access")
    def access(svc, p, g):
        result = svc.request_access(
            p["actor"], g["lid"], p["scope"], p.get("purpose", ""),
            int(p.get("ttl_seconds", 300)))
        return _ok(result, 201)

    @route("POST", r"/batches")
    def create_batch(svc, p, g):
        return _ok(svc.create_batch(p["actor"], p["name"]), 201)

    @route("POST", r"/batches/(?P<bid>B-[0-9a-f]+)/items")
    def add_item(svc, p, g):
        return _ok(svc.add_batch_item(p["actor"], g["bid"], p["letter_id"]))

    @route("POST", r"/batches/(?P<bid>B-[0-9a-f]+)/(?P<action>freeze|verify|manifest|seal)")
    def stage(svc, p, g):
        fn = {
            "freeze": svc.freeze_batch, "verify": svc.verify_batch,
            "manifest": svc.prepare_manifest, "seal": svc.seal_batch,
        }[g["action"]]
        return _ok(fn(p["actor"], g["bid"]))

    @route("GET", r"/batches/(?P<bid>B-[0-9a-f]+)")
    def batch(svc, p, g):
        return _ok(svc.batch_view(g["bid"]))

    @route("POST", r"/batches/(?P<bid>B-[0-9a-f]+)/corrections")
    def correction(svc, p, g):
        result = svc.propose_correction(
            p["actor"], g["bid"], p["action"], p["letter_id"],
            p.get("reason", ""), p.get("replacement_id"))
        return _ok(result, 201)

    @route("POST", r"/batches/(?P<bid>B-[0-9a-f]+)/receipts")
    def receipt(svc, p, g):
        result = svc.record_receipt(
            p["actor"], g["bid"], p["letter_id"], p["status"],
            p["carrier_ref"], p["receipt_key"], p.get("manifest_version"))
        return _ok(result, 201)

    @route("GET", r"/batches/(?P<bid>B-[0-9a-f]+)/reconcile")
    def reconcile(svc, p, g):
        return _ok(svc.reconcile(g["bid"]))

    @route("POST", r"/batches/(?P<bid>B-[0-9a-f]+)/displays")
    def display(svc, p, g):
        result = svc.publish_display(p["actor"], g["bid"],
                                     p.get("letter_ids"))
        return _ok(result, 201)

    @route("GET", r"/displays/(?P<did>D-[0-9a-f]+)")
    def display_view(svc, p, g):
        return _ok(svc.display_view(g["did"]))

    @route("GET", r"/displays/(?P<did>D-[0-9a-f]+)/proof/(?P<lid>L-[0-9a-f]+)")
    def proof(svc, p, g):
        return _ok(svc.display_authorization_proof(g["did"], g["lid"]))

    @route("POST", r"/access/(?P<gid>G-[0-9a-f]+)/reveal")
    def reveal(svc, p, g):
        return _ok(svc.reveal(p["actor"], g["gid"]))

    @route("GET", r"/grants")
    def grants(svc, p, g):
        return _ok({"grants": svc.list_grants()})

    return routes


_ROUTES = _make_routes()
Handler.ROUTES = _ROUTES


def run(host: str = "127.0.0.1", port: int = 8000):
    """启动本地服务。"""
    Handler.service = build_default_service()
    print(f"家书接力站数据目录: {_HOME}")
    ThreadingHTTPServer((host, port), Handler).serve_forever()


if __name__ == "__main__":
    run()
