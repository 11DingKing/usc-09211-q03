"""SQLite 存储层：表结构、连接管理与哈希链审计。

设计约定：
- 业务身份均使用调用方提供的稳定标识或系统生成的随机标识；
- 审计日志只追加、不覆盖，逐条哈希链可校验；
- 直接身份标识（姓名/学校/监护人）只存于 identities 保险库，
  业务表一律使用匿名标识 pseudonym。
"""
from __future__ import annotations

import hashlib
import json
import sqlite3
import threading

GENESIS_HASH = "0" * 64

SCHEMA = """
CREATE TABLE IF NOT EXISTS identities (
  pseudonym   TEXT PRIMARY KEY,
  lookup_key  TEXT NOT NULL UNIQUE,
  pii_enc     TEXT NOT NULL,
  created_at  TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS letters (
  letter_id    TEXT PRIMARY KEY,
  pseudonym    TEXT NOT NULL REFERENCES identities(pseudonym),
  content_enc  TEXT NOT NULL,
  content_hash TEXT NOT NULL,
  status       TEXT NOT NULL,            -- received / approved / rejected / withdrawn
  source_org   TEXT NOT NULL,
  uploaded_by  TEXT NOT NULL,
  event_time   TEXT NOT NULL,            -- 事件时间（调用方）
  received_at  TEXT NOT NULL,            -- 接收时间（服务端）
  UNIQUE (pseudonym, content_hash)       -- 同一孩子同一正文只保留一份
);

CREATE TABLE IF NOT EXISTS letter_refs (
  idempotency_key TEXT PRIMARY KEY,      -- 调用方稳定标识（网络重试去重）
  letter_id       TEXT NOT NULL REFERENCES letters(letter_id)
);

CREATE TABLE IF NOT EXISTS consents (
  consent_id         TEXT PRIMARY KEY,
  pseudonym          TEXT NOT NULL,
  scope              TEXT NOT NULL,      -- uplink / display
  valid_from         TEXT NOT NULL,
  valid_until        TEXT NOT NULL,
  revoked_at         TEXT,
  revocation_reason  TEXT,
  revoke_key         TEXT UNIQUE,        -- 撤回操作幂等键
  propagation_report TEXT,               -- 撤回传播结果（供重试返回一致结果）
  idempotency_key    TEXT UNIQUE,
  event_time         TEXT NOT NULL,
  received_at        TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS reviews (
  review_id       TEXT PRIMARY KEY,
  letter_id       TEXT NOT NULL REFERENCES letters(letter_id),
  reviewer        TEXT NOT NULL,
  decision        TEXT NOT NULL,         -- approve / reject
  note            TEXT,
  idempotency_key TEXT UNIQUE,
  event_time      TEXT NOT NULL,
  received_at     TEXT NOT NULL,
  UNIQUE (letter_id, reviewer)           -- 同一复核人对同一封信只能复核一次
);

CREATE TABLE IF NOT EXISTS batches (
  batch_id        TEXT PRIMARY KEY,
  title           TEXT NOT NULL,
  status          TEXT NOT NULL,         -- open / sealing / sealed
  idempotency_key TEXT UNIQUE,
  created_at      TEXT NOT NULL,
  sealed_at       TEXT,
  manifest_hash   TEXT
);

CREATE TABLE IF NOT EXISTS batch_staging (
  batch_id        TEXT NOT NULL REFERENCES batches(batch_id),
  letter_id       TEXT NOT NULL REFERENCES letters(letter_id),
  staged_seq      INTEGER NOT NULL,
  staged_at       TEXT NOT NULL,
  idempotency_key TEXT UNIQUE,
  PRIMARY KEY (batch_id, letter_id)
);

CREATE TABLE IF NOT EXISTS batch_members (
  batch_id    TEXT NOT NULL REFERENCES batches(batch_id),
  letter_id   TEXT NOT NULL REFERENCES letters(letter_id),
  snapshot_id TEXT NOT NULL,             -- 封存时刻的上行授权快照
  member_seq  INTEGER NOT NULL,
  PRIMARY KEY (batch_id, letter_id)
);

CREATE TABLE IF NOT EXISTS seal_journal (
  batch_id        TEXT PRIMARY KEY,
  state           TEXT NOT NULL,         -- started / committed
  planned_count   INTEGER NOT NULL,
  done_count      INTEGER NOT NULL,
  planned_ids     TEXT NOT NULL,         -- 封存计划快照（JSON），崩溃后按计划续跑
  seal_started_at TEXT NOT NULL,         -- 封存评估时点，保证恢复后结果一致
  updated_at      TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS amendments (
  amendment_id    TEXT PRIMARY KEY,
  batch_id        TEXT NOT NULL REFERENCES batches(batch_id),
  letter_id       TEXT NOT NULL,
  action          TEXT NOT NULL,         -- remove / redact
  reason          TEXT NOT NULL,
  idempotency_key TEXT UNIQUE,
  actor           TEXT NOT NULL,
  event_time      TEXT NOT NULL,
  received_at     TEXT NOT NULL,
  UNIQUE (batch_id, letter_id, action)   -- 同类更正天然去重
);

CREATE TABLE IF NOT EXISTS receipts (
  batch_id        TEXT NOT NULL,
  letter_id       TEXT NOT NULL,
  status          TEXT NOT NULL,         -- delivered / failed
  idempotency_key TEXT UNIQUE,
  event_time      TEXT NOT NULL,
  received_at     TEXT NOT NULL,
  PRIMARY KEY (batch_id, letter_id)
);

CREATE TABLE IF NOT EXISTS consent_snapshots (
  snapshot_id  TEXT PRIMARY KEY,         -- 快照内容的哈希，可重算校验
  pseudonym    TEXT NOT NULL,
  scope        TEXT NOT NULL,
  state        TEXT NOT NULL,            -- active / inactive
  valid_from   TEXT,
  valid_until  TEXT,
  revoked_at   TEXT,
  evaluated_at TEXT NOT NULL,            -- 授权有效性评估时点（事件时间）
  captured_at  TEXT NOT NULL             -- 快照采集时间（服务端）
);

CREATE TABLE IF NOT EXISTS displays (
  display_id      TEXT PRIMARY KEY,
  letter_id       TEXT NOT NULL REFERENCES letters(letter_id),
  snapshot_id     TEXT NOT NULL REFERENCES consent_snapshots(snapshot_id),
  channel         TEXT NOT NULL,
  idempotency_key TEXT UNIQUE,
  event_time      TEXT NOT NULL,         -- 展示发生时间
  received_at     TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS access_grants (
  grant_id        TEXT PRIMARY KEY,
  actor           TEXT NOT NULL,
  letter_id       TEXT NOT NULL REFERENCES letters(letter_id),
  expires_at      TEXT NOT NULL,
  idempotency_key TEXT UNIQUE,
  created_at      TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS audit_log (
  seq       INTEGER PRIMARY KEY AUTOINCREMENT,
  actor     TEXT NOT NULL,
  action    TEXT NOT NULL,
  entity    TEXT NOT NULL,
  entity_id TEXT NOT NULL,
  detail    TEXT NOT NULL,               -- JSON，不含 PII 与正文
  at        TEXT NOT NULL,
  prev_hash TEXT NOT NULL,
  hash      TEXT NOT NULL
);
"""


def _canonical(entry: dict) -> str:
    return json.dumps(entry, ensure_ascii=False, sort_keys=True)


def _audit_body(actor: str, action: str, entity: str, entity_id: str,
                detail_json: str, at: str, prev_hash: str) -> str:
    return _canonical({
        "actor": actor,
        "action": action,
        "entity": entity,
        "entity_id": entity_id,
        "detail": detail_json,
        "at": at,
        "prev_hash": prev_hash,
    })


class Store:
    """单连接存储；所有访问经同一把可重入锁串行化。"""

    def __init__(self, path: str = ":memory:"):
        self.path = path
        self.conn = sqlite3.connect(path, check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        self.conn.execute("PRAGMA foreign_keys = ON")
        self.conn.executescript(SCHEMA)
        self.lock = threading.RLock()

    def append_audit(self, *, actor: str, action: str, entity: str,
                     entity_id: str, detail: dict, at: str) -> None:
        """追加一条审计记录。须在业务事务内调用，与业务变更同生共死。"""
        row = self.conn.execute(
            "SELECT hash FROM audit_log ORDER BY seq DESC LIMIT 1").fetchone()
        prev_hash = row["hash"] if row else GENESIS_HASH
        detail_json = _canonical(detail)
        digest = hashlib.sha256(
            _audit_body(actor, action, entity, entity_id, detail_json, at, prev_hash)
            .encode("utf-8")
        ).hexdigest()
        self.conn.execute(
            "INSERT INTO audit_log (actor, action, entity, entity_id, detail, at, prev_hash, hash)"
            " VALUES (?,?,?,?,?,?,?,?)",
            (actor, action, entity, entity_id, detail_json, at, prev_hash, digest),
        )

    def verify_audit_chain(self) -> dict:
        """重放哈希链，任何覆盖式修改都会使校验失败。"""
        rows = self.conn.execute("SELECT * FROM audit_log ORDER BY seq").fetchall()
        prev = GENESIS_HASH
        for row in rows:
            body = _audit_body(row["actor"], row["action"], row["entity"],
                               row["entity_id"], row["detail"], row["at"], row["prev_hash"])
            digest = hashlib.sha256(body.encode("utf-8")).hexdigest()
            if row["prev_hash"] != prev or digest != row["hash"]:
                return {"ok": False, "length": len(rows), "first_bad_seq": row["seq"]}
            prev = row["hash"]
        return {"ok": True, "length": len(rows)}

    def close(self) -> None:
        self.conn.close()
