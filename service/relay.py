"""家书接力核心业务。

能力覆盖：
- 匿名化收件：直接身份入保险库，业务流转只用匿名标识；
- 监护授权：有效期 + 撤回传播（候选池、开放批次即时移除，已封存批次增量更正）；
- 内容复核：双人分离（导入人不得复核、两人不得为同一人）；
- 批次封存：日志化分块推进，崩溃后按计划续跑；封存后只能增量更正；
- 发送回执对账：应发/已发/缺失/异常一目了然；
- 公开展示：每次展示锚定当时有效的授权快照，可独立验证；
- 敏感原文：限定角色凭短时授权访问，每次读取留痕；
- 幂等：所有写操作接受幂等键，重试与多校重复导入不产生双份记录。
"""
from __future__ import annotations

import hashlib
import json
from datetime import timedelta

from . import security
from .clock import format_iso, parse_iso
from .store import Store

CONTENT_ROLES = frozenset({"reviewer", "privacy_officer"})
CONSENT_SCOPES = frozenset({"uplink", "display"})
REVIEW_DECISIONS = frozenset({"approve", "reject"})
AMENDMENT_ACTIONS = frozenset({"remove", "redact"})
RECEIPT_STATUSES = frozenset({"delivered", "failed"})
APPROVALS_REQUIRED = 2
MAX_CONTENT_TTL_SECONDS = 300


class RelayError(Exception):
    """业务异常基类，code 供 HTTP 层映射状态码。"""

    code = "error"


class Validation(RelayError):
    code = "validation"


class Forbidden(RelayError):
    code = "forbidden"


class NotFound(RelayError):
    code = "not_found"


class Conflict(RelayError):
    code = "conflict"


class SimulatedCrash(Exception):
    """测试注入的崩溃，用于验证封存恢复。"""


def _parse_time(value, field: str):
    try:
        return parse_iso(value)
    except (TypeError, ValueError):
        raise Validation(f"{field} 不是合法的 ISO 时间") from None


def _snapshot_id(fields: dict) -> str:
    canonical = json.dumps(fields, ensure_ascii=False, sort_keys=True)
    return "snap_" + hashlib.sha256(canonical.encode("utf-8")).hexdigest()[:40]


class RelayService:
    def __init__(self, store: Store, clock, vault_key: bytes, auto_recover: bool = True):
        self.store = store
        self.clock = clock
        self._vault_key = vault_key
        self._conn = store.conn
        self._lock = store.lock
        if auto_recover:
            self.recover_sealing()

    # ------------------------------------------------------------------
    # 基础工具
    # ------------------------------------------------------------------
    @staticmethod
    def _require(role: str, allowed) -> None:
        if role not in allowed:
            raise Forbidden(f"角色 {role or '(未提供)'} 无权执行此操作，需要 {'/'.join(sorted(allowed))}")

    def _audit(self, actor: str, action: str, entity: str, entity_id: str, detail: dict, at: str) -> None:
        self.store.append_audit(actor=actor, action=action, entity=entity,
                                entity_id=entity_id, detail=detail, at=at)

    def _now(self) -> str:
        return format_iso(self.clock.now())

    def _get_letter(self, letter_id: str):
        row = self._conn.execute("SELECT * FROM letters WHERE letter_id = ?", (letter_id,)).fetchone()
        if not row:
            raise NotFound(f"信件 {letter_id} 不存在")
        return row

    def _get_batch(self, batch_id: str):
        row = self._conn.execute("SELECT * FROM batches WHERE batch_id = ?", (batch_id,)).fetchone()
        if not row:
            raise NotFound(f"批次 {batch_id} 不存在")
        return row

    def _active_consent(self, pseudonym: str, scope: str, at_dt):
        """at_dt 时刻有效的授权：在有效期内且尚未撤回（按撤回接收时间判定）。"""
        rows = self._conn.execute(
            "SELECT * FROM consents WHERE pseudonym = ? AND scope = ?", (pseudonym, scope)).fetchall()
        for row in rows:
            if _parse_time(row["valid_from"], "valid_from") <= at_dt < _parse_time(row["valid_until"], "valid_until"):
                if row["revoked_at"] is None or at_dt < _parse_time(row["revoked_at"], "revoked_at"):
                    return row
        return None

    def _ensure_snapshot(self, pseudonym: str, scope: str, evaluated_at, captured_at: str) -> str:
        """生成（或复用）授权快照，快照 ID 即内容哈希，可独立重算校验。"""
        consent = self._active_consent(pseudonym, scope, evaluated_at)
        fields = {
            "pseudonym": pseudonym,
            "scope": scope,
            "state": "active" if consent else "inactive",
            "valid_from": consent["valid_from"] if consent else None,
            "valid_until": consent["valid_until"] if consent else None,
            "revoked_at": consent["revoked_at"] if consent else None,
            "evaluated_at": format_iso(evaluated_at),
            "captured_at": captured_at,
        }
        snap_id = _snapshot_id(fields)
        self._conn.execute(
            "INSERT OR IGNORE INTO consent_snapshots"
            " (snapshot_id, pseudonym, scope, state, valid_from, valid_until, revoked_at, evaluated_at, captured_at)"
            " VALUES (?,?,?,?,?,?,?,?,?)",
            (snap_id, fields["pseudonym"], fields["scope"], fields["state"],
             fields["valid_from"], fields["valid_until"], fields["revoked_at"],
             fields["evaluated_at"], fields["captured_at"]),
        )
        return snap_id

    # ------------------------------------------------------------------
    # 收件（匿名化 + 幂等）
    # ------------------------------------------------------------------
    def import_letter(self, *, actor, role, idempotency_key, child_name, school,
                      guardian_ref, content, event_time, source_org):
        self._require(role, {"intake_officer", "privacy_officer"})
        if not all([idempotency_key, child_name, school, guardian_ref, content, source_org]):
            raise Validation("缺少必填字段")
        event_at = format_iso(_parse_time(event_time, "event_time"))
        now = self._now()
        with self._lock, self._conn:
            # 1) 网络重试：同一幂等键直接返回首次结果
            ref = self._conn.execute(
                "SELECT letter_id FROM letter_refs WHERE idempotency_key = ?",
                (idempotency_key,)).fetchone()
            if ref:
                return self._letter_view(ref["letter_id"], deduplicated=True, note="idempotency_key")

            # 2) 身份入保险库，业务侧只拿匿名标识
            lookup = security.identity_lookup_key(self._vault_key, child_name, school, guardian_ref)
            ident = self._conn.execute(
                "SELECT pseudonym FROM identities WHERE lookup_key = ?", (lookup,)).fetchone()
            if ident:
                pseudonym = ident["pseudonym"]
            else:
                pseudonym = security.new_token("ps")
                pii = json.dumps(
                    {"child_name": child_name, "school": school, "guardian_ref": guardian_ref},
                    ensure_ascii=False)
                self._conn.execute(
                    "INSERT INTO identities (pseudonym, lookup_key, pii_enc, created_at) VALUES (?,?,?,?)",
                    (pseudonym, lookup, security.encrypt_text(self._vault_key, pii), now))
                self._audit(actor, "identity.created", "identity", pseudonym,
                            {"source_org": source_org}, now)

            # 3) 多校重复导入：同一孩子同一正文只保留一份，新键登记为别名
            digest = security.content_hash(content)
            dup = self._conn.execute(
                "SELECT letter_id FROM letters WHERE pseudonym = ? AND content_hash = ?",
                (pseudonym, digest)).fetchone()
            if dup:
                self._conn.execute(
                    "INSERT INTO letter_refs (idempotency_key, letter_id) VALUES (?,?)",
                    (idempotency_key, dup["letter_id"]))
                self._audit(actor, "letter.deduplicated", "letter", dup["letter_id"],
                            {"idempotency_key": idempotency_key, "content_hash": digest,
                             "source_org": source_org}, now)
                return self._letter_view(dup["letter_id"], deduplicated=True, note="content_match")

            letter_id = security.new_token("L")
            self._conn.execute(
                "INSERT INTO letters (letter_id, pseudonym, content_enc, content_hash, status,"
                " source_org, uploaded_by, event_time, received_at) VALUES (?,?,?,?,?,?,?,?,?)",
                (letter_id, pseudonym, security.encrypt_text(self._vault_key, content), digest,
                 "received", source_org, actor, event_at, now))
            self._conn.execute(
                "INSERT INTO letter_refs (idempotency_key, letter_id) VALUES (?,?)",
                (idempotency_key, letter_id))
            self._audit(actor, "letter.imported", "letter", letter_id,
                        {"pseudonym": pseudonym, "content_hash": digest,
                         "source_org": source_org, "event_time": event_at}, now)
            return self._letter_view(letter_id, deduplicated=False)

    def _letter_view(self, letter_id: str, *, deduplicated: bool, note: str | None = None) -> dict:
        row = self._conn.execute(
            "SELECT letter_id, pseudonym, status, source_org, uploaded_by, event_time, received_at, content_hash"
            " FROM letters WHERE letter_id = ?", (letter_id,)).fetchone()
        view = {
            "letter_id": row["letter_id"],
            "pseudonym": row["pseudonym"],
            "status": row["status"],
            "source_org": row["source_org"],
            "event_time": row["event_time"],
            "received_at": row["received_at"],
            "content_hash": row["content_hash"],
            "deduplicated": deduplicated,
        }
        if note:
            view["dedup_note"] = note
        return view

    # ------------------------------------------------------------------
    # 监护授权：授予、撤回与传播
    # ------------------------------------------------------------------
    def grant_consent(self, *, actor, role, idempotency_key, pseudonym, scope,
                      valid_from, valid_until, event_time):
        self._require(role, {"guardian", "privacy_officer"})
        if scope not in CONSENT_SCOPES:
            raise Validation(f"scope 必须是 {sorted(CONSENT_SCOPES)} 之一")
        valid_from_dt = _parse_time(valid_from, "valid_from")
        valid_until_dt = _parse_time(valid_until, "valid_until")
        if not valid_from_dt < valid_until_dt:
            raise Validation("valid_from 必须早于 valid_until")
        event_at = format_iso(_parse_time(event_time, "event_time"))
        now = self._now()
        with self._lock, self._conn:
            dup = self._conn.execute(
                "SELECT consent_id FROM consents WHERE idempotency_key = ?",
                (idempotency_key,)).fetchone()
            if dup:
                return self._consent_view(dup["consent_id"], deduplicated=True)
            if not self._conn.execute(
                    "SELECT 1 FROM identities WHERE pseudonym = ?", (pseudonym,)).fetchone():
                raise NotFound(f"匿名身份 {pseudonym} 不存在")
            consent_id = security.new_token("C")
            self._conn.execute(
                "INSERT INTO consents (consent_id, pseudonym, scope, valid_from, valid_until,"
                " idempotency_key, event_time, received_at) VALUES (?,?,?,?,?,?,?,?)",
                (consent_id, pseudonym, scope, format_iso(valid_from_dt),
                 format_iso(valid_until_dt), idempotency_key, event_at, now))
            self._audit(actor, "consent.granted", "consent", consent_id,
                        {"pseudonym": pseudonym, "scope": scope,
                         "valid_from": format_iso(valid_from_dt),
                         "valid_until": format_iso(valid_until_dt)}, now)
            return self._consent_view(consent_id, deduplicated=False)

    def _consent_view(self, consent_id: str, *, deduplicated: bool) -> dict:
        row = self._conn.execute(
            "SELECT * FROM consents WHERE consent_id = ?", (consent_id,)).fetchone()
        return {
            "consent_id": row["consent_id"],
            "pseudonym": row["pseudonym"],
            "scope": row["scope"],
            "valid_from": row["valid_from"],
            "valid_until": row["valid_until"],
            "revoked_at": row["revoked_at"],
            "deduplicated": deduplicated,
        }

    def revoke_consent(self, *, actor, role, idempotency_key, consent_id, reason, event_time):
        """撤回授权并同步传播：候选池/开放批次即时移除，已封存批次登记增量更正。

        撤回按接收时间生效；早于撤回时刻的历史展示快照仍然有效（当时有效）。
        """
        self._require(role, {"guardian", "privacy_officer"})
        event_at = format_iso(_parse_time(event_time, "event_time"))
        now = self._now()
        with self._lock, self._conn:
            clash = self._conn.execute(
                "SELECT consent_id FROM consents WHERE revoke_key = ?", (idempotency_key,)).fetchone()
            if clash and clash["consent_id"] != consent_id:
                raise Conflict("该幂等键已用于其他撤回操作")
            row = self._conn.execute(
                "SELECT * FROM consents WHERE consent_id = ?", (consent_id,)).fetchone()
            if not row:
                raise NotFound(f"授权 {consent_id} 不存在")
            if row["revoked_at"]:
                # 重试：返回首次撤回时固化的传播结果
                return {
                    "consent_id": consent_id,
                    "revoked": True,
                    "revoked_at": row["revoked_at"],
                    "deduplicated": True,
                    "propagation": json.loads(row["propagation_report"] or "{}"),
                }

            scope, pseudonym = row["scope"], row["pseudonym"]
            self._conn.execute(
                "UPDATE consents SET revoked_at = ?, revocation_reason = ?, revoke_key = ?"
                " WHERE consent_id = ?",
                (now, reason, idempotency_key, consent_id))
            self._audit(actor, "consent.revoked", "consent", consent_id,
                        {"pseudonym": pseudonym, "scope": scope, "reason": reason,
                         "event_time": event_at}, now)
            if scope == "uplink":
                propagation = self._propagate_uplink_revocation(actor, pseudonym, consent_id, reason, now)
            else:
                # 展示授权撤回：未来展示在校验时被拒，历史展示快照仍证明当时有效
                propagation = {"future_displays_blocked": True}
            self._conn.execute(
                "UPDATE consents SET propagation_report = ? WHERE consent_id = ?",
                (json.dumps(propagation, ensure_ascii=False), consent_id))
            return {"consent_id": consent_id, "revoked": True, "revoked_at": now,
                    "deduplicated": False, "propagation": propagation}

    def _propagate_uplink_revocation(self, actor, pseudonym, consent_id, reason, now) -> dict:
        letters = self._conn.execute(
            "SELECT letter_id, status FROM letters WHERE pseudonym = ?", (pseudonym,)).fetchall()
        withdrawn, staging_removed, amendments = [], [], []
        for letter in letters:
            lid = letter["letter_id"]
            if letter["status"] in ("received", "approved"):
                self._conn.execute(
                    "UPDATE letters SET status = 'withdrawn' WHERE letter_id = ?", (lid,))
                withdrawn.append(lid)
                self._audit(actor, "letter.withdrawn", "letter", lid,
                            {"cause": "consent_revoked", "consent_id": consent_id}, now)
            staged = self._conn.execute(
                "SELECT bs.batch_id FROM batch_staging bs JOIN batches b ON b.batch_id = bs.batch_id"
                " WHERE bs.letter_id = ? AND b.status IN ('open','sealing')", (lid,)).fetchall()
            for s in staged:
                self._conn.execute(
                    "DELETE FROM batch_staging WHERE batch_id = ? AND letter_id = ?",
                    (s["batch_id"], lid))
                staging_removed.append({"batch_id": s["batch_id"], "letter_id": lid})
                self._audit(actor, "staging.removed", "batch", s["batch_id"],
                            {"letter_id": lid, "cause": "consent_revoked"}, now)
            sealed = self._conn.execute(
                "SELECT bm.batch_id FROM batch_members bm JOIN batches b ON b.batch_id = bm.batch_id"
                " WHERE bm.letter_id = ? AND b.status = 'sealed'", (lid,)).fetchall()
            for s in sealed:
                exists = self._conn.execute(
                    "SELECT 1 FROM amendments WHERE batch_id = ? AND letter_id = ? AND action = 'remove'",
                    (s["batch_id"], lid)).fetchone()
                if not exists:
                    amendment_id = security.new_token("A")
                    self._conn.execute(
                        "INSERT INTO amendments (amendment_id, batch_id, letter_id, action, reason,"
                        " idempotency_key, actor, event_time, received_at) VALUES (?,?,?,?,?,?,?,?,?)",
                        (amendment_id, s["batch_id"], lid, "remove",
                         f"consent_revoked: {reason}",
                         f"auto-revoke:{consent_id}:{s['batch_id']}:{lid}",
                         actor, now, now))
                    amendments.append({"batch_id": s["batch_id"], "letter_id": lid,
                                       "amendment_id": amendment_id})
                    self._audit(actor, "batch.amended", "batch", s["batch_id"],
                                {"amendment_id": amendment_id, "letter_id": lid,
                                 "action": "remove", "cause": "consent_revoked"}, now)
        return {"letters_withdrawn": withdrawn, "staging_removed": staging_removed,
                "amendments_created": amendments}

    # ------------------------------------------------------------------
    # 内容复核：双人分离
    # ------------------------------------------------------------------
    def review(self, *, actor, role, idempotency_key, letter_id, decision, event_time, note=""):
        self._require(role, {"reviewer"})
        if decision not in REVIEW_DECISIONS:
            raise Validation(f"decision 必须是 {sorted(REVIEW_DECISIONS)} 之一")
        event_at = format_iso(_parse_time(event_time, "event_time"))
        now = self._now()
        with self._lock, self._conn:
            dup = self._conn.execute(
                "SELECT review_id FROM reviews WHERE idempotency_key = ?",
                (idempotency_key,)).fetchone()
            if dup:
                return self._review_result(dup["review_id"], deduplicated=True)
            letter = self._get_letter(letter_id)
            if letter["status"] != "received":
                raise Conflict(f"信件当前状态为 {letter['status']}，不可复核")
            if letter["uploaded_by"] == actor:
                raise Forbidden("导入人不得复核自己导入的信件（职责分离）")
            if self._conn.execute(
                    "SELECT 1 FROM reviews WHERE letter_id = ? AND reviewer = ?",
                    (letter_id, actor)).fetchone():
                raise Conflict("同一复核人不得重复复核同一封信")
            review_id = security.new_token("R")
            self._conn.execute(
                "INSERT INTO reviews (review_id, letter_id, reviewer, decision, note,"
                " idempotency_key, event_time, received_at) VALUES (?,?,?,?,?,?,?,?)",
                (review_id, letter_id, actor, decision, note, idempotency_key, event_at, now))
            if decision == "reject":
                # 涉及未成年人内容，一票否决（保守策略）
                self._conn.execute(
                    "UPDATE letters SET status = 'rejected' WHERE letter_id = ?", (letter_id,))
            else:
                approvals = self._conn.execute(
                    "SELECT COUNT(DISTINCT reviewer) AS c FROM reviews"
                    " WHERE letter_id = ? AND decision = 'approve'", (letter_id,)).fetchone()["c"]
                if approvals >= APPROVALS_REQUIRED:
                    self._conn.execute(
                        "UPDATE letters SET status = 'approved' WHERE letter_id = ?", (letter_id,))
            action = "review.approved" if decision == "approve" else "review.rejected"
            self._audit(actor, action, "letter", letter_id,
                        {"review_id": review_id, "note": note or ""}, now)
            return self._review_result(review_id, deduplicated=False)

    def _review_result(self, review_id: str, *, deduplicated: bool) -> dict:
        row = self._conn.execute(
            "SELECT * FROM reviews WHERE review_id = ?", (review_id,)).fetchone()
        status = self._conn.execute(
            "SELECT status FROM letters WHERE letter_id = ?", (row["letter_id"],)).fetchone()["status"]
        approvals = self._conn.execute(
            "SELECT COUNT(DISTINCT reviewer) AS c FROM reviews"
            " WHERE letter_id = ? AND decision = 'approve'", (row["letter_id"],)).fetchone()["c"]
        return {"review_id": review_id, "letter_id": row["letter_id"],
                "decision": row["decision"], "letter_status": status,
                "approvals": approvals, "deduplicated": deduplicated}

    # ------------------------------------------------------------------
    # 批次：建批、候选、封存（可恢复）、增量更正
    # ------------------------------------------------------------------
    def create_batch(self, *, actor, role, idempotency_key, title):
        self._require(role, {"batch_operator"})
        if not title:
            raise Validation("title 不能为空")
        now = self._now()
        with self._lock, self._conn:
            dup = self._conn.execute(
                "SELECT batch_id FROM batches WHERE idempotency_key = ?",
                (idempotency_key,)).fetchone()
            if dup:
                row = self._get_batch(dup["batch_id"])
                return {"batch_id": row["batch_id"], "title": row["title"],
                        "status": row["status"], "deduplicated": True}
            batch_id = security.new_token("B")
            self._conn.execute(
                "INSERT INTO batches (batch_id, title, status, idempotency_key, created_at)"
                " VALUES (?,?,?,?,?)",
                (batch_id, title, "open", idempotency_key, now))
            self._audit(actor, "batch.created", "batch", batch_id, {"title": title}, now)
            return {"batch_id": batch_id, "title": title, "status": "open", "deduplicated": False}

    def stage_letter(self, *, actor, role, idempotency_key, batch_id, letter_id):
        """把通过复核且授权有效的信件放入开放批次的候选。"""
        self._require(role, {"batch_operator"})
        now_dt = self.clock.now()
        now = format_iso(now_dt)
        with self._lock, self._conn:
            dup = self._conn.execute(
                "SELECT batch_id, letter_id FROM batch_staging WHERE idempotency_key = ?",
                (idempotency_key,)).fetchone()
            if dup:
                return {"batch_id": dup["batch_id"], "letter_id": dup["letter_id"],
                        "deduplicated": True}
            batch = self._get_batch(batch_id)
            if batch["status"] != "open":
                raise Conflict(f"批次状态为 {batch['status']}，不能加入候选")
            letter = self._get_letter(letter_id)
            if self._conn.execute(
                    "SELECT 1 FROM batch_staging WHERE batch_id = ? AND letter_id = ?",
                    (batch_id, letter_id)).fetchone():
                return {"batch_id": batch_id, "letter_id": letter_id, "deduplicated": True}
            if letter["status"] != "approved":
                raise Conflict(f"信件状态为 {letter['status']}，未通过复核或已撤回")
            if not self._active_consent(letter["pseudonym"], "uplink", now_dt):
                raise Conflict("没有覆盖当前时刻的上行授权")
            if self._conn.execute(
                    "SELECT 1 FROM batch_members bm JOIN batches b ON b.batch_id = bm.batch_id"
                    " WHERE bm.letter_id = ? AND b.status = 'sealed'", (letter_id,)).fetchone():
                raise Conflict("信件已在其他封存批次中，不得重复上行")
            seq = self._conn.execute(
                "SELECT COALESCE(MAX(staged_seq), 0) + 1 AS s FROM batch_staging WHERE batch_id = ?",
                (batch_id,)).fetchone()["s"]
            self._conn.execute(
                "INSERT INTO batch_staging (batch_id, letter_id, staged_seq, staged_at, idempotency_key)"
                " VALUES (?,?,?,?,?)",
                (batch_id, letter_id, seq, now, idempotency_key))
            self._audit(actor, "staging.added", "batch", batch_id,
                        {"letter_id": letter_id, "staged_seq": seq}, now)
            return {"batch_id": batch_id, "letter_id": letter_id,
                    "staged_seq": seq, "deduplicated": False}

    def seal_batch(self, *, actor, role, batch_id, chunk_size: int = 100, crash_after=None):
        """封存批次：分块推进并记录日志，崩溃后可续跑。crash_after 仅供测试注入。"""
        self._require(role, {"batch_operator"})
        return self._seal(batch_id, actor=actor, chunk_size=chunk_size, crash_after=crash_after)

    def _seal(self, batch_id: str, *, actor: str, chunk_size: int, crash_after) -> dict:
        try:
            chunk_size = max(1, int(chunk_size))
        except (TypeError, ValueError):
            raise Validation("chunk_size 必须是正整数") from None
        with self._lock:
            batch = self._get_batch(batch_id)
            journal = self._conn.execute(
                "SELECT * FROM seal_journal WHERE batch_id = ?", (batch_id,)).fetchone()
            if journal and journal["state"] == "committed":
                return {"batch_id": batch_id, "status": "sealed",
                        "manifest_hash": batch["manifest_hash"], "deduplicated": True}
            if batch["status"] == "sealed":
                return {"batch_id": batch_id, "status": "sealed",
                        "manifest_hash": batch["manifest_hash"], "deduplicated": True}
            if batch["status"] not in ("open", "sealing"):
                raise Conflict(f"批次状态为 {batch['status']}，不可封存")

            if not journal:
                planned = [r["letter_id"] for r in self._conn.execute(
                    "SELECT letter_id FROM batch_staging WHERE batch_id = ? ORDER BY staged_seq",
                    (batch_id,)).fetchall()]
                if not planned:
                    raise Conflict("批次为空，没有可封存的信件")
                with self._conn:
                    started = self._now()
                    self._conn.execute(
                        "INSERT INTO seal_journal (batch_id, state, planned_count, done_count,"
                        " planned_ids, seal_started_at, updated_at) VALUES (?,?,?,?,?,?,?)",
                        (batch_id, "started", len(planned), 0,
                         json.dumps(planned), started, started))
                    self._conn.execute(
                        "UPDATE batches SET status = 'sealing' WHERE batch_id = ?", (batch_id,))
                    self._audit(actor, "seal.started", "batch", batch_id,
                                {"planned_count": len(planned)}, started)
                journal = self._conn.execute(
                    "SELECT * FROM seal_journal WHERE batch_id = ?", (batch_id,)).fetchone()

            planned = json.loads(journal["planned_ids"])
            seal_started_at = journal["seal_started_at"]
            done = journal["done_count"]
            while done < len(planned):
                chunk = planned[done:done + chunk_size]
                now = self._now()
                with self._conn:
                    for offset, letter_id in enumerate(chunk):
                        self._seal_one(batch_id, letter_id, done + offset,
                                       seal_started_at, actor, now)
                    self._conn.execute(
                        "UPDATE seal_journal SET done_count = ?, updated_at = ? WHERE batch_id = ?",
                        (done + len(chunk), now, batch_id))
                done += len(chunk)
                if crash_after is not None and done >= crash_after and done < len(planned):
                    raise SimulatedCrash(f"注入崩溃：封存进度 {done}/{len(planned)}")

            with self._conn:
                members = self._conn.execute(
                    "SELECT letter_id, snapshot_id, member_seq FROM batch_members"
                    " WHERE batch_id = ? ORDER BY member_seq", (batch_id,)).fetchall()
                manifest = hashlib.sha256(json.dumps(
                    [dict(m) for m in members], ensure_ascii=False, sort_keys=True
                ).encode("utf-8")).hexdigest()
                finished = self._now()
                self._conn.execute(
                    "UPDATE batches SET status = 'sealed', sealed_at = ?, manifest_hash = ?"
                    " WHERE batch_id = ?", (finished, manifest, batch_id))
                self._conn.execute(
                    "UPDATE seal_journal SET state = 'committed', updated_at = ? WHERE batch_id = ?",
                    (finished, batch_id))
                self._conn.execute(
                    "DELETE FROM batch_staging WHERE batch_id = ?", (batch_id,))
                self._audit(actor, "seal.committed", "batch", batch_id,
                            {"manifest_hash": manifest, "member_count": len(members)}, finished)
            return {"batch_id": batch_id, "status": "sealed", "manifest_hash": manifest,
                    "member_count": len(members), "deduplicated": False}

    def _seal_one(self, batch_id, letter_id, member_seq, seal_started_at, actor, now) -> None:
        letter = self._conn.execute(
            "SELECT * FROM letters WHERE letter_id = ?", (letter_id,)).fetchone()
        eval_at = _parse_time(seal_started_at, "seal_started_at")
        eligible = (
            letter is not None
            and letter["status"] == "approved"
            and self._active_consent(letter["pseudonym"], "uplink", eval_at) is not None
        )
        if not eligible:
            # 封存时点不再满足条件（如授权刚被撤回）：移出候选并留痕
            self._conn.execute(
                "DELETE FROM batch_staging WHERE batch_id = ? AND letter_id = ?",
                (batch_id, letter_id))
            self._audit(actor, "seal.skipped", "letter", letter_id,
                        {"batch_id": batch_id, "reason": "ineligible_at_seal"}, now)
            return
        snapshot_id = self._ensure_snapshot(
            letter["pseudonym"], "uplink", eval_at, captured_at=seal_started_at)
        self._conn.execute(
            "INSERT OR IGNORE INTO batch_members (batch_id, letter_id, snapshot_id, member_seq)"
            " VALUES (?,?,?,?)",
            (batch_id, letter_id, snapshot_id, member_seq))
        self._conn.execute(
            "DELETE FROM batch_staging WHERE batch_id = ? AND letter_id = ?",
            (batch_id, letter_id))

    def recover_sealing(self) -> dict:
        """启动时恢复未完成的封存：按日志中的计划从断点续跑。"""
        with self._lock:
            pending = self._conn.execute(
                "SELECT batch_id, done_count, planned_count FROM seal_journal"
                " WHERE state != 'committed'").fetchall()
            recovered = []
            for row in pending:
                with self._conn:
                    self._audit("system", "seal.recovered", "batch", row["batch_id"],
                                {"resume_from": row["done_count"],
                                 "planned_count": row["planned_count"]}, self._now())
                recovered.append(self._seal(row["batch_id"], actor="system",
                                            chunk_size=100, crash_after=None))
            return {"recovered": recovered}

    def add_amendment(self, *, actor, role, idempotency_key, batch_id, letter_id, action, reason):
        """封存后的增量更正：只追加更正记录，不改封存清单。"""
        self._require(role, {"batch_operator"})
        if action not in AMENDMENT_ACTIONS:
            raise Validation(f"action 必须是 {sorted(AMENDMENT_ACTIONS)} 之一")
        if not reason:
            raise Validation("reason 不能为空")
        now = self._now()
        with self._lock, self._conn:
            dup = self._conn.execute(
                "SELECT amendment_id FROM amendments WHERE idempotency_key = ?",
                (idempotency_key,)).fetchone()
            if dup:
                return self._amendment_view(dup["amendment_id"], deduplicated=True)
            batch = self._get_batch(batch_id)
            if batch["status"] != "sealed":
                raise Conflict("只有已封存批次才能登记增量更正")
            if not self._conn.execute(
                    "SELECT 1 FROM batch_members WHERE batch_id = ? AND letter_id = ?",
                    (batch_id, letter_id)).fetchone():
                raise NotFound("该信件不在批次封存清单中")
            natural = self._conn.execute(
                "SELECT amendment_id FROM amendments WHERE batch_id = ? AND letter_id = ? AND action = ?",
                (batch_id, letter_id, action)).fetchone()
            if natural:
                return self._amendment_view(natural["amendment_id"], deduplicated=True)
            amendment_id = security.new_token("A")
            self._conn.execute(
                "INSERT INTO amendments (amendment_id, batch_id, letter_id, action, reason,"
                " idempotency_key, actor, event_time, received_at) VALUES (?,?,?,?,?,?,?,?,?)",
                (amendment_id, batch_id, letter_id, action, reason,
                 idempotency_key, actor, now, now))
            self._audit(actor, "batch.amended", "batch", batch_id,
                        {"amendment_id": amendment_id, "letter_id": letter_id,
                         "action": action, "reason": reason}, now)
            return self._amendment_view(amendment_id, deduplicated=False)

    def _amendment_view(self, amendment_id: str, *, deduplicated: bool) -> dict:
        row = self._conn.execute(
            "SELECT * FROM amendments WHERE amendment_id = ?", (amendment_id,)).fetchone()
        return {"amendment_id": row["amendment_id"], "batch_id": row["batch_id"],
                "letter_id": row["letter_id"], "action": row["action"],
                "reason": row["reason"], "deduplicated": deduplicated}

    # ------------------------------------------------------------------
    # 发送回执与对账
    # ------------------------------------------------------------------
    def record_receipt(self, *, actor, role, idempotency_key, batch_id, letter_id,
                       status, event_time):
        self._require(role, {"batch_operator"})
        if status not in RECEIPT_STATUSES:
            raise Validation(f"status 必须是 {sorted(RECEIPT_STATUSES)} 之一")
        event_at = format_iso(_parse_time(event_time, "event_time"))
        now = self._now()
        with self._lock, self._conn:
            dup = self._conn.execute(
                "SELECT * FROM receipts WHERE idempotency_key = ?", (idempotency_key,)).fetchone()
            if dup:
                return {"batch_id": dup["batch_id"], "letter_id": dup["letter_id"],
                        "status": dup["status"], "deduplicated": True}
            batch = self._get_batch(batch_id)
            if batch["status"] != "sealed":
                raise Conflict("批次未封存，不能登记回执")
            existing = self._conn.execute(
                "SELECT * FROM receipts WHERE batch_id = ? AND letter_id = ?",
                (batch_id, letter_id)).fetchone()
            if existing:
                if existing["status"] == status:
                    return {"batch_id": batch_id, "letter_id": letter_id,
                            "status": status, "deduplicated": True}
                # 上行重试后的最新结果以新回执为准，旧记录留痕于审计
                self._conn.execute(
                    "UPDATE receipts SET status = ?, idempotency_key = ?, event_time = ?,"
                    " received_at = ? WHERE batch_id = ? AND letter_id = ?",
                    (status, idempotency_key, event_at, now, batch_id, letter_id))
                self._audit(actor, "receipt.updated", "receipt", f"{batch_id}/{letter_id}",
                            {"status": status, "previous": existing["status"]}, now)
                return {"batch_id": batch_id, "letter_id": letter_id,
                        "status": status, "updated": True, "deduplicated": False}
            self._conn.execute(
                "INSERT INTO receipts (batch_id, letter_id, status, idempotency_key,"
                " event_time, received_at) VALUES (?,?,?,?,?,?)",
                (batch_id, letter_id, status, idempotency_key, event_at, now))
            self._audit(actor, "receipt.recorded", "receipt", f"{batch_id}/{letter_id}",
                        {"status": status, "event_time": event_at}, now)
            return {"batch_id": batch_id, "letter_id": letter_id,
                    "status": status, "deduplicated": False}

    def reconcile(self, *, actor, role, batch_id):
        """对账：以封存清单 + 增量更正为应发口径，对照回执找出差异。"""
        self._require(role, {"batch_operator", "editor", "auditor", "privacy_officer"})
        with self._lock:
            batch = self._get_batch(batch_id)
            members = [r["letter_id"] for r in self._conn.execute(
                "SELECT letter_id FROM batch_members WHERE batch_id = ?", (batch_id,)).fetchall()]
            removed = {r["letter_id"] for r in self._conn.execute(
                "SELECT letter_id FROM amendments WHERE batch_id = ? AND action = 'remove'",
                (batch_id,)).fetchall()}
            expected = [m for m in members if m not in removed]
            receipts = self._conn.execute(
                "SELECT letter_id, status FROM receipts WHERE batch_id = ?",
                (batch_id,)).fetchall()
            receipt_map = {r["letter_id"]: r["status"] for r in receipts}
            delivered = sorted(l for l in expected if receipt_map.get(l) == "delivered")
            failed = sorted(l for l in expected if receipt_map.get(l) == "failed")
            missing = sorted(l for l in expected if l not in receipt_map)
            unexpected = sorted(l for l in receipt_map if l not in members)
            superseded = sorted(l for l in receipt_map if l in removed)
            balanced = not missing and not failed and not unexpected
            return {
                "batch_id": batch_id,
                "sealed": batch["status"] == "sealed",
                "manifest_hash": batch["manifest_hash"],
                "expected": sorted(expected),
                "delivered": delivered,
                "failed": failed,
                "missing": missing,
                "unexpected": unexpected,
                "superseded": superseded,
                "balanced": balanced,
                "generated_at": self._now(),
            }

    # ------------------------------------------------------------------
    # 公开展示与授权快照证明
    # ------------------------------------------------------------------
    def record_display(self, *, actor, role, idempotency_key, letter_id, channel, event_time):
        """登记一次公开展示，并锚定展示时刻有效的授权快照。"""
        self._require(role, {"editor"})
        if not channel:
            raise Validation("channel 不能为空")
        event_dt = _parse_time(event_time, "event_time")
        event_at = format_iso(event_dt)
        now = self._now()
        with self._lock, self._conn:
            dup = self._conn.execute(
                "SELECT display_id, snapshot_id FROM displays WHERE idempotency_key = ?",
                (idempotency_key,)).fetchone()
            if dup:
                return {"display_id": dup["display_id"], "letter_id": letter_id,
                        "snapshot_id": dup["snapshot_id"], "deduplicated": True}
            letter = self._get_letter(letter_id)
            if letter["status"] != "approved":
                raise Conflict(f"信件状态为 {letter['status']}，未通过复核或已撤回，不得展示")
            if not self._active_consent(letter["pseudonym"], "display", event_dt):
                raise Conflict("展示时刻没有有效的展示授权")
            snapshot_id = self._ensure_snapshot(
                letter["pseudonym"], "display", event_dt, captured_at=now)
            display_id = security.new_token("D")
            self._conn.execute(
                "INSERT INTO displays (display_id, letter_id, snapshot_id, channel,"
                " idempotency_key, event_time, received_at) VALUES (?,?,?,?,?,?,?)",
                (display_id, letter_id, snapshot_id, channel, idempotency_key, event_at, now))
            self._audit(actor, "display.recorded", "display", display_id,
                        {"letter_id": letter_id, "snapshot_id": snapshot_id,
                         "channel": channel, "event_time": event_at}, now)
            return {"display_id": display_id, "letter_id": letter_id,
                    "snapshot_id": snapshot_id, "deduplicated": False}

    def display_proof(self, *, actor, role, display_id):
        """验证展示证明：快照完整、展示时刻授权有效、且已锚定进审计链。"""
        with self._lock:
            display = self._conn.execute(
                "SELECT * FROM displays WHERE display_id = ?", (display_id,)).fetchone()
            if not display:
                raise NotFound(f"展示记录 {display_id} 不存在")
            snap = self._conn.execute(
                "SELECT * FROM consent_snapshots WHERE snapshot_id = ?",
                (display["snapshot_id"],)).fetchone()
            snap_fields = {
                "pseudonym": snap["pseudonym"], "scope": snap["scope"], "state": snap["state"],
                "valid_from": snap["valid_from"], "valid_until": snap["valid_until"],
                "revoked_at": snap["revoked_at"], "evaluated_at": snap["evaluated_at"],
                "captured_at": snap["captured_at"],
            }
            displayed_at = _parse_time(display["event_time"], "event_time")
            anchored = self._conn.execute(
                "SELECT 1 FROM audit_log WHERE action = 'display.recorded' AND entity_id = ?"
                " AND instr(detail, ?) > 0",
                (display_id, display["snapshot_id"])).fetchone()
            checks = {
                "snapshot_intact": _snapshot_id(snap_fields) == display["snapshot_id"],
                "state_active": snap["state"] == "active",
                "within_validity": bool(snap["valid_from"]) and
                    _parse_time(snap["valid_from"], "valid_from") <= displayed_at
                    < _parse_time(snap["valid_until"], "valid_until"),
                "not_revoked_at_display": snap["revoked_at"] is None or
                    displayed_at < _parse_time(snap["revoked_at"], "revoked_at"),
                "audit_anchored": bool(anchored),
            }
            return {
                "display_id": display_id,
                "letter_id": display["letter_id"],
                "channel": display["channel"],
                "displayed_at": display["event_time"],
                "snapshot": {"snapshot_id": display["snapshot_id"], **snap_fields},
                "checks": checks,
                "verified": all(checks.values()),
            }

    # ------------------------------------------------------------------
    # 敏感原文与身份：限定角色 + 短时授权
    # ------------------------------------------------------------------
    def request_content_access(self, *, actor, role, idempotency_key, letter_id, ttl_seconds):
        self._require(role, CONTENT_ROLES)
        try:
            ttl = int(ttl_seconds)
        except (TypeError, ValueError):
            raise Validation("ttl_seconds 必须是整数") from None
        if not 1 <= ttl <= MAX_CONTENT_TTL_SECONDS:
            raise Validation(f"ttl_seconds 须在 1..{MAX_CONTENT_TTL_SECONDS} 秒之间")
        now_dt = self.clock.now()
        now = format_iso(now_dt)
        with self._lock, self._conn:
            dup = self._conn.execute(
                "SELECT grant_id, expires_at FROM access_grants WHERE idempotency_key = ?",
                (idempotency_key,)).fetchone()
            if dup:
                return {"grant_id": dup["grant_id"], "letter_id": letter_id,
                        "expires_at": dup["expires_at"], "deduplicated": True}
            self._get_letter(letter_id)
            grant_id = security.new_token("G")
            expires_at = format_iso(now_dt + timedelta(seconds=ttl))
            self._conn.execute(
                "INSERT INTO access_grants (grant_id, actor, letter_id, expires_at,"
                " idempotency_key, created_at) VALUES (?,?,?,?,?,?)",
                (grant_id, actor, letter_id, expires_at, idempotency_key, now))
            self._audit(actor, "content.granted", "letter", letter_id,
                        {"grant_id": grant_id, "ttl_seconds": ttl}, now)
            return {"grant_id": grant_id, "letter_id": letter_id,
                    "expires_at": expires_at, "deduplicated": False}

    def read_content(self, *, actor, grant_id, role=None):
        """凭短时授权读取原文；每次读取都写入审计。授权本身即凭证，不再查角色。"""
        now_dt = self.clock.now()
        now = format_iso(now_dt)
        with self._lock, self._conn:
            grant = self._conn.execute(
                "SELECT * FROM access_grants WHERE grant_id = ?", (grant_id,)).fetchone()
            if not grant:
                raise NotFound("访问授权不存在")
            if grant["actor"] != actor:
                raise Forbidden("访问授权仅限申请人本人使用")
            if now_dt >= _parse_time(grant["expires_at"], "expires_at"):
                raise Forbidden("访问授权已过期")
            row = self._conn.execute(
                "SELECT content_enc FROM letters WHERE letter_id = ?",
                (grant["letter_id"],)).fetchone()
            content = security.decrypt_text(self._vault_key, row["content_enc"])
            self._audit(actor, "content.read", "letter", grant["letter_id"],
                        {"grant_id": grant_id}, now)
            return {"letter_id": grant["letter_id"], "content": content}

    def read_identity(self, *, actor, role, pseudonym):
        """读取保险库中的直接身份标识，仅限隐私官并留痕。"""
        self._require(role, {"privacy_officer"})
        now = self._now()
        with self._lock, self._conn:
            row = self._conn.execute(
                "SELECT pii_enc FROM identities WHERE pseudonym = ?", (pseudonym,)).fetchone()
            if not row:
                raise NotFound(f"匿名身份 {pseudonym} 不存在")
            pii = json.loads(security.decrypt_text(self._vault_key, row["pii_enc"]))
            self._audit(actor, "identity.read", "identity", pseudonym, {}, now)
            return {"pseudonym": pseudonym, "identity": pii}

    # ------------------------------------------------------------------
    # 位置查询与审计校验
    # ------------------------------------------------------------------
    def letter_locations(self, *, actor, role, letter_id):
        """回答“这封信的副本现在都在哪”：候选池、批次、展示、授权状态。"""
        self._require(role, {"guardian", "privacy_officer", "editor",
                             "batch_operator", "auditor"})
        with self._lock:
            letter = self._get_letter(letter_id)
            open_batches = [r["batch_id"] for r in self._conn.execute(
                "SELECT bs.batch_id FROM batch_staging bs JOIN batches b ON b.batch_id = bs.batch_id"
                " WHERE bs.letter_id = ? AND b.status IN ('open','sealing')",
                (letter_id,)).fetchall()]
            sealed_batches = []
            for row in self._conn.execute(
                    "SELECT bm.batch_id, b.sealed_at, b.manifest_hash FROM batch_members bm"
                    " JOIN batches b ON b.batch_id = bm.batch_id WHERE bm.letter_id = ?",
                    (letter_id,)).fetchall():
                removed = self._conn.execute(
                    "SELECT 1 FROM amendments WHERE batch_id = ? AND letter_id = ?"
                    " AND action = 'remove'",
                    (row["batch_id"], letter_id)).fetchone()
                sealed_batches.append({
                    "batch_id": row["batch_id"],
                    "sealed_at": row["sealed_at"],
                    "manifest_hash": row["manifest_hash"],
                    "removed_by_amendment": bool(removed),
                })
            displays = [dict(r) for r in self._conn.execute(
                "SELECT display_id, channel, event_time FROM displays WHERE letter_id = ?",
                (letter_id,)).fetchall()]
            consents = [dict(r) for r in self._conn.execute(
                "SELECT consent_id, scope, valid_from, valid_until, revoked_at"
                " FROM consents WHERE pseudonym = ?", (letter["pseudonym"],)).fetchall()]
            candidate = (
                letter["status"] in ("received", "approved")
                and not sealed_batches
                and self._active_consent(letter["pseudonym"], "uplink", self.clock.now())
                is not None
            )
            return {
                "letter_id": letter_id,
                "status": letter["status"],
                "candidate": candidate,
                "open_batches": open_batches,
                "sealed_batches": sealed_batches,
                "displays": displays,
                "consents": consents,
                "generated_at": self._now(),
            }

    def verify_audit(self, *, actor, role):
        self._require(role, {"auditor", "privacy_officer"})
        with self._lock:
            return self.store.verify_audit_chain()
