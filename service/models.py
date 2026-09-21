"""领域模型与状态投影。

所有状态都由事件日志重放得到，本模块只保存推导结果，不自行持久化。
"""
from __future__ import annotations

import hashlib
import unicodedata
from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional

from .events import ALL_SCOPES


def parse_ts(value: str | datetime | None) -> Optional[datetime]:
    if value is None:
        return None
    if isinstance(value, datetime):
        dt = value
    else:
        dt = datetime.fromisoformat(value)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=datetime.timezone.utc)
    return dt


def content_fingerprint(body: str) -> str:
    """对正文做 NFKC 归一化与空白压缩后取 SHA-256。

    不同学校导入同一封信件（仅空白/全半角差异）得到相同指纹。
    """
    normalized = unicodedata.normalize("NFKC", body)
    compact = "".join(normalized.split())
    return hashlib.sha256(compact.encode("utf-8")).hexdigest()


# 角色
ROLE_SCHOOL = "SCHOOL_COORDINATOR"   # 学校收件协调人
ROLE_GUARDIAN = "GUARDIAN"           # 监护人
ROLE_REVIEWER = "REVIEWER"           # 复核编辑（一审/二审）
ROLE_EDITOR = "EDITOR"               # 编辑团队（批次、展示）
ROLE_CARRIER = "CARRIER"             # 上行承运人/回执方
ROLE_AUDITOR = "AUDITOR"             # 只读审计


@dataclass
class ConsentVersion:
    letter_id: str
    version: int
    guardian_id: str
    scopes: tuple[str, ...]
    valid_from: datetime
    valid_until: Optional[datetime]
    granted_at: datetime
    revoked_at: Optional[datetime] = None
    revoke_reason: Optional[str] = None

    def valid_at(self, moment: datetime) -> bool:
        if moment < self.valid_from:
            return False
        if self.valid_until is not None and moment >= self.valid_until:
            return False
        if self.revoked_at is not None and moment >= self.revoked_at:
            return False
        return True

    def has_scope(self, scope: str, moment: datetime) -> bool:
        return scope in self.scopes and self.valid_at(moment)


@dataclass
class ReviewDecision:
    letter_id: str
    state: str = "PENDING_FIRST"  # PENDING_FIRST / PENDING_SECOND / APPROVED / REJECTED
    first_reviewer: Optional[str] = None
    first_at: Optional[datetime] = None
    first_result: Optional[str] = None
    first_note: Optional[str] = None
    second_reviewer: Optional[str] = None
    second_at: Optional[datetime] = None
    second_result: Optional[str] = None
    second_note: Optional[str] = None


@dataclass
class LetterState:
    letter_id: str
    school_code: str
    source_key: str
    content_hash: str
    body_secret_ref: str
    pii_secret_ref: str
    received_at: datetime
    imported_by: Optional[str]
    status: str = "ACTIVE"  # ACTIVE / CONSENT_REVOKED
    consent: Optional[ConsentVersion] = None
    decision: Optional[ReviewDecision] = None


@dataclass
class Correction:
    seq: int
    action: str               # REMOVE / REPLACE
    letter_id: str
    reason: str
    actor: str
    at: datetime
    replacement: Optional[dict] = None
    manifest_hash: str = ""


@dataclass
class BatchState:
    batch_id: str
    name: str
    created_by: str
    created_at: datetime
    # OPEN：可增减候选；FROZEN/VERIFIED/MANIFEST_READY：封存工序中；SEALED：已封存
    stage: str = "OPEN"
    open_items: dict[str, dict] = field(default_factory=dict)  # letter_id -> 条目
    removed_items: list[dict] = field(default_factory=list)    # 开放期被移除的候选
    sealed_entries: list[dict] = field(default_factory=list)
    manifest_hash: Optional[str] = None
    sealed_at: Optional[datetime] = None
    corrections: list[Correction] = field(default_factory=list)
    stage_history: list[dict] = field(default_factory=list)


@dataclass
class DisplayState:
    display_id: str
    published_at: datetime
    manifest_hash: str
    items: list[dict] = field(default_factory=list)
    # letter_id -> 下架时间/原因
    takedowns: dict[str, dict] = field(default_factory=dict)


@dataclass
class Receipt:
    batch_id: str
    letter_id: str
    status: str                 # SUCCESS / FAILED
    carrier_ref: str
    receipt_key: str
    manifest_version: int
    at: datetime
    actor: str


@dataclass
class AccessGrant:
    """短时原文访问凭据（进程内有效，重放后自然过期即失效）。"""
    jti: str
    letter_id: str
    actor_id: str
    scope: str
    expires_at: datetime
    purpose: str
    revealed: bool = False
