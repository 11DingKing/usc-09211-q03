"""HTTP 接口层：把 JSON 请求映射到 RelayService。

路由表驱动：required/optional 描述请求体字段，query 描述 GET 参数；
actor/role 来自请求头 X-Actor / X-Role。
"""
from __future__ import annotations

from .relay import NotFound, RelayService, Validation

# (method, path) -> (service 方法, 必填字段, 可选字段, 参数来源)
ROUTES = {
    ("POST", "/letters/import"): ("import_letter",
        ["idempotency_key", "child_name", "school", "guardian_ref", "content",
         "event_time", "source_org"], [], "body"),
    ("POST", "/consents/grant"): ("grant_consent",
        ["idempotency_key", "pseudonym", "scope", "valid_from", "valid_until",
         "event_time"], [], "body"),
    ("POST", "/consents/revoke"): ("revoke_consent",
        ["idempotency_key", "consent_id", "reason", "event_time"], [], "body"),
    ("POST", "/reviews"): ("review",
        ["idempotency_key", "letter_id", "decision", "event_time"], ["note"], "body"),
    ("POST", "/batches"): ("create_batch",
        ["idempotency_key", "title"], [], "body"),
    ("POST", "/batches/stage"): ("stage_letter",
        ["idempotency_key", "batch_id", "letter_id"], [], "body"),
    ("POST", "/batches/seal"): ("seal_batch",
        ["batch_id"], ["chunk_size"], "body"),
    ("POST", "/batches/amend"): ("add_amendment",
        ["idempotency_key", "batch_id", "letter_id", "action", "reason"], [], "body"),
    ("POST", "/receipts"): ("record_receipt",
        ["idempotency_key", "batch_id", "letter_id", "status", "event_time"], [], "body"),
    ("POST", "/displays"): ("record_display",
        ["idempotency_key", "letter_id", "channel", "event_time"], [], "body"),
    ("POST", "/access/grants"): ("request_content_access",
        ["idempotency_key", "letter_id", "ttl_seconds"], [], "body"),
    ("POST", "/content/read"): ("read_content",
        ["grant_id"], [], "body"),
    ("GET", "/letters/locations"): ("letter_locations",
        ["letter_id"], [], "query"),
    ("GET", "/batches/reconcile"): ("reconcile",
        ["batch_id"], [], "query"),
    ("GET", "/displays/proof"): ("display_proof",
        ["display_id"], [], "query"),
    ("GET", "/identities"): ("read_identity",
        ["pseudonym"], [], "query"),
    ("GET", "/audit/verify"): ("verify_audit",
        [], [], "query"),
}


class Api:
    def __init__(self, service: RelayService):
        self.service = service

    def handle(self, method: str, path: str, query: dict, actor: str, role: str, payload: dict):
        route = ROUTES.get((method, path))
        if not route:
            raise NotFound(f"未知路由 {method} {path}")
        name, required, optional, source = route
        data = query if source == "query" else (payload or {})
        missing = [f for f in required if data.get(f) in (None, "")]
        if missing:
            raise Validation(f"缺少字段: {', '.join(missing)}")
        kwargs = {k: data[k] for k in required + optional if k in data}
        return getattr(self.service, name)(actor=actor, role=role, **kwargs)
