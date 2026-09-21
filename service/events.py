"""仅追加的哈希链事件日志。

领域约定：
- 事件时间（event_time，业务发生时间，调用方提供）与接收时间
  （recorded_time，服务端落盘时间）分离记录；
- 业务身份由调用方提供的稳定标识表示；
- 审计记录只能追加，不能覆盖——每条记录包含上一条记录的哈希，
  形成哈希链，可随时整体校验。
"""
from __future__ import annotations

import hashlib
import json
import os
import threading
from datetime import datetime, timezone
from typing import Any, Callable

# 受保护的授权范围
SCOPE_REVIEW = "REVIEW"     # 允许编辑团队阅读原文并复核
SCOPE_UPLINK = "UPLINK"     # 允许进入上行批次
SCOPE_DISPLAY = "DISPLAY"   # 允许公开展示
ALL_SCOPES = (SCOPE_REVIEW, SCOPE_UPLINK, SCOPE_DISPLAY)


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def canonical(obj: Any) -> str:
    """确定性 JSON 序列化，用于哈希与签名。"""
    return json.dumps(
        obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False, default=str
    )


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


class DomainError(Exception):
    """业务规则冲突，code 供调用方程序化处理，status 为建议 HTTP 状态码。"""

    def __init__(self, code: str, message: str, status: int = 400):
        super().__init__(message)
        self.code = code
        self.status = status


def require_actor(actor: dict | None, *roles: str) -> dict:
    """校验调用方身份及其角色；roles 为空时只要求有稳定身份。"""
    if not actor or not actor.get("id"):
        raise DomainError("actor_required", "请求必须携带调用方稳定身份", 401)
    if roles:
        held = set(actor.get("roles") or [])
        if not held.intersection(roles):
            raise DomainError(
                "forbidden",
                f"身份 {actor['id']} 缺少所需角色之一: {', '.join(roles)}",
                403,
            )
    return actor


class EventStore:
    """JSONL 哈希链事件存储，每条追加都 fsync。"""

    def __init__(self, path: str, clock: Callable[[], str] = now_iso):
        self.path = path
        self.clock = clock
        os.makedirs(os.path.dirname(path), exist_ok=True)
        self._lock = threading.Lock()
        self.records: list[dict] = []
        if os.path.exists(path):
            with open(path, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if line:
                        self.records.append(json.loads(line))
            # 加载即校验，截断/篡改的日志不允许启动
            self.verify()

    def append(
        self,
        event_type: str,
        data: dict,
        event_time: str | None = None,
        actor: dict | None = None,
    ) -> dict:
        event_time = event_time or self.clock()
        with self._lock:
            seq = len(self.records) + 1
            prev_hash = self.records[-1]["hash"] if self.records else ""
            body = canonical(
                {
                    "type": event_type,
                    "data": data,
                    "event_time": event_time,
                    "actor": actor,
                }
            )
            digest = sha256_hex((prev_hash + body).encode("utf-8"))
            record = {
                "seq": seq,
                "type": event_type,
                "event_time": event_time,
                "recorded_time": self.clock(),
                "actor": actor,
                "data": data,
                "prev_hash": prev_hash,
                "hash": digest,
            }
            line = json.dumps(record, ensure_ascii=False, default=str)
            with open(self.path, "a", encoding="utf-8") as f:
                f.write(line + "\n")
                f.flush()
                os.fsync(f.fileno())
            self.records.append(record)
            return record

    def verify(self) -> None:
        """重算整条哈希链，发现任何覆盖/篡改即抛错。"""
        prev_hash = ""
        for idx, rec in enumerate(self.records, start=1):
            body = canonical(
                {
                    "type": rec["type"],
                    "data": rec["data"],
                    "event_time": rec["event_time"],
                    "actor": rec["actor"],
                }
            )
            expected = sha256_hex((prev_hash + body).encode("utf-8"))
            if not (
                rec.get("prev_hash") == prev_hash
                and rec.get("hash") == expected
                and rec.get("seq") == idx
            ):
                raise DomainError(
                    "log_tampered",
                    f"事件日志在第 {idx} 条处哈希校验失败",
                    500,
                )
            prev_hash = rec["hash"]
