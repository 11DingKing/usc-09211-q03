"""家书接力核心领域服务。

所有写操作都是：校验投影状态 -> 追加事件 -> 事件折叠更新投影。
崩溃恢复时只需重放事件日志；封存工序按阶段检查点续跑。
"""
from __future__ import annotations

import os
import threading
from datetime import timedelta
from typing import Optional

from .events import (
    ALL_SCOPES,
    DomainError,
    EventStore,
    canonical,
    now_iso,
    require_actor,
    sha256_hex,
)
from .models import (
    AccessGrant,
    BatchState,
    ConsentVersion,
    Correction,
    DisplayState,
    LetterState,
    Receipt,
    ReviewDecision,
    content_fingerprint,
    parse_ts,
)
from .vault import Vault

ROLE_SCHOOL = "SCHOOL_COORDINATOR"
ROLE_GUARDIAN = "GUARDIAN"
ROLE_REVIEWER = "REVIEWER"
ROLE_EDITOR = "EDITOR"
ROLE_CARRIER = "CARRIER"

# 封存工序阶段
ST_OPEN, ST_FROZEN, ST_VERIFIED, ST_MANIFEST, ST_SEALED = (
    "OPEN",
    "FROZEN",
    "VERIFIED",
    "MANIFEST_READY",
    "SEALED",
)


def _letter_id(school_code: str, source_key: str) -> str:
    digest = sha256_hex(f"{school_code}|{source_key}".encode("utf-8"))[:16]
    return f"L-{digest}"


def _batch_id(name: str) -> str:
    return f"B-{sha256_hex(name.encode('utf-8'))[:12]}"


class LetterRelay:
    def __init__(self, store: EventStore, vault: Optional[Vault] = None):
        self.store = store
        self.vault = vault or Vault()
        self._lock = threading.RLock()
        # 投影
        self.letters: dict[str, LetterState] = {}
        self.by_request: dict[tuple[str, str], str] = {}
        self.by_source: dict[tuple[str, str], str] = {}
        self.by_content: dict[str, str] = {}
        self.batches: dict[str, BatchState] = {}
        self.displays: dict[str, DisplayState] = {}
        self.grants: dict[str, AccessGrant] = {}
        self.receipts: list[Receipt] = []
        self._receipt_by_key: dict[str, Receipt] = {}
        self.duplicate_suppressions: list[dict] = []
        self._replay()

    # ------------------------------------------------------------------ 重放

    def _replay(self) -> None:
        for rec in self.store.records:
            self._apply(rec["type"], rec["data"], rec["event_time"])

    def _emit(self, event_type: str, data: dict, actor: Optional[dict],
              event_time: Optional[str] = None) -> dict:
        rec = self.store.append(event_type, data, event_time=event_time,
                                actor=actor and {"id": actor["id"],
                                                 "roles": actor.get("roles", [])})
        self._apply(rec["type"], rec["data"], rec["event_time"])
        return rec

    def _apply(self, etype: str, d: dict, event_time: str) -> None:
        ts = parse_ts(event_time)
        if etype == "LetterReceived":
            self.vault.register(d["body_secret_ref"], d["body_blob"])
            self.vault.register(d["pii_secret_ref"], d["pii_blob"])
            letter = LetterState(
                letter_id=d["letter_id"],
                school_code=d["school_code"],
                source_key=d["source_key"],
                content_hash=d["content_hash"],
                body_secret_ref=d["body_secret_ref"],
                pii_secret_ref=d["pii_secret_ref"],
                received_at=parse_ts(d["received_at"]),
                imported_by=d.get("imported_by"),
            )
            self.letters[d["letter_id"]] = letter
            self.by_request[(d["school_code"], d["request_id"])] = d["letter_id"]
            self.by_source[(d["school_code"], d["source_key"])] = d["letter_id"]
            self.by_content.setdefault(d["content_hash"], d["letter_id"])
        elif etype == "DuplicateImportSuppressed":
            self.duplicate_suppressions.append(d)
        elif etype == "ConsentGranted":
            letter = self.letters[d["letter_id"]]
            letter.consent = ConsentVersion(
                letter_id=d["letter_id"],
                version=d["version"],
                guardian_id=d["guardian_id"],
                scopes=tuple(d["scopes"]),
                valid_from=parse_ts(d["valid_from"]),
                valid_until=parse_ts(d.get("valid_until")),
                granted_at=parse_ts(d["granted_at"]),
            )
            letter.status = "ACTIVE"
        elif etype == "ConsentRevoked":
            letter = self.letters[d["letter_id"]]
            if letter.consent:
                letter.consent.revoked_at = parse_ts(d["revoked_at"])
                letter.consent.revoke_reason = d.get("reason")
            letter.status = "CONSENT_REVOKED"
        elif etype == "ReviewDecided":
            letter = self.letters[d["letter_id"]]
            dec = letter.decision or ReviewDecision(letter_id=d["letter_id"])
            at = parse_ts(d["at"])
            if d["round"] == 1:
                dec.first_reviewer, dec.first_at = d["reviewer"], at
                dec.first_result, dec.first_note = d["result"], d.get("note")
                dec.state = "PENDING_SECOND" if d["result"] == "APPROVE" else "REJECTED"
            else:
                dec.second_reviewer, dec.second_at = d["reviewer"], at
                dec.second_result, dec.second_note = d["result"], d.get("note")
                dec.state = "APPROVED" if d["result"] == "APPROVE" else "REJECTED"
            letter.decision = dec
        elif etype == "BatchCreated":
            self.batches[d["batch_id"]] = BatchState(
                batch_id=d["batch_id"], name=d["name"],
                created_by=d["created_by"], created_at=ts,
                stage_history=[{"to": ST_OPEN, "at": event_time}],
            )
        elif etype == "BatchItemAdded":
            self.batches[d["batch_id"]].open_items[d["letter_id"]] = {
                "added_at": d["at"], "added_by": d["actor_id"],
            }
        elif etype == "BatchItemRemoved":
            batch = self.batches[d["batch_id"]]
            if d["letter_id"] in batch.open_items:
                batch.open_items.pop(d["letter_id"], None)
                batch.removed_items.append(
                    {"letter_id": d["letter_id"], "at": d["at"],
                     "reason": d.get("reason", ""),
                     "actor_id": d.get("actor_id")})
        elif etype == "BatchStageChanged":
            batch = self.batches[d["batch_id"]]
            batch.stage = d["to_stage"]
            batch.stage_history.append(
                {"from": d.get("from_stage"), "to": d["to_stage"],
                 "at": d["at"], "actor_id": d.get("actor_id")})
        elif etype == "BatchSealed":
            batch = self.batches[d["batch_id"]]
            batch.sealed_entries = d["entries"]
            batch.manifest_hash = d["manifest_hash"]
            batch.sealed_at = parse_ts(d["at"])
            batch.manifest_versions = [{
                "version": 1,
                "manifest_hash": d["manifest_hash"],
                "prev_hash": "",
                "entries": d["entries"],
                "at": d["at"],
                "corrections": [],
            }]
        elif etype == "BatchCorrectionProposed":
            batch = self.batches[d["batch_id"]]
            batch.corrections.append(Correction(
                seq=d["seq"], action=d["action"], letter_id=d["letter_id"],
                reason=d["reason"], actor=d["actor_id"], at=parse_ts(d["at"]),
                replacement=d.get("replacement"),
                manifest_hash=d.get("manifest_hash", ""),
            ))
        elif etype == "BatchManifestRevised":
            batch = self.batches[d["batch_id"]]
            batch.manifest_versions.append({
                "version": d["version"],
                "manifest_hash": d["manifest_hash"],
                "prev_hash": d["prev_hash"],
                "entries": d["entries"],
                "at": d["at"],
                "corrections": d["corrections"],
            })
            batch.manifest_hash = d["manifest_hash"]
        elif etype == "DisplayPublished":
            self.displays[d["display_id"]] = DisplayState(
                display_id=d["display_id"], published_at=ts,
                manifest_hash=d["manifest_hash"], items=d["items"])
        elif etype == "DisplayItemRemoved":
            disp = self.displays[d["display_id"]]
            disp.takedowns[d["letter_id"]] = {"at": d["at"], "reason": d["reason"]}
        elif etype == "AccessGranted":
            self.grants[d["jti"]] = AccessGrant(
                jti=d["jti"], letter_id=d["letter_id"], actor_id=d["actor_id"],
                scope=d["scope"], expires_at=parse_ts(d["expires_at"]),
                purpose=d["purpose"])
        elif etype == "AccessRevealed":
            grant = self.grants[d["jti"]]
            grant.revealed = True
        elif etype == "ReceiptRecorded":
            receipt = Receipt(
                batch_id=d["batch_id"], letter_id=d["letter_id"],
                status=d["status"], carrier_ref=d["carrier_ref"],
                receipt_key=d["receipt_key"], manifest_version=d["manifest_version"],
                at=parse_ts(d["at"]), actor=d["actor_id"])
            self.receipts.append(receipt)
            self._receipt_by_key[d["receipt_key"]] = receipt

    # ---------------------------------------------------------- 匿名化收件

    def import_letter(self, actor: dict, school_code: str, source_key: str,
                      request_id: str, body: str, pii: dict,
                      event_time: Optional[str] = None) -> dict:
        with self._lock:
            require_actor(actor, ROLE_SCHOOL)
            if not school_code or not source_key or not request_id:
                raise DomainError("bad_request", "school_code/source_key/request_id 均必填")
            if not body or not body.strip():
                raise DomainError("empty_body", "家书正文不能为空")

            # 网络重试：同一所学校的同一 request_id / source_key -> 原记录
            existing = self.by_request.get((school_code, request_id))
            if existing:
                return {"letter_id": existing, "duplicate": True,
                        "reason": "request_id"}
            existing = self.by_source.get((school_code, source_key))
            if existing:
                return {"letter_id": existing, "duplicate": True,
                        "reason": "source_key"}

            fingerprint = content_fingerprint(body)
            # 多校重复导入：同一内容指纹 -> 不产生第二份记录
            original = self.by_content.get(fingerprint)
            if original:
                self._emit("DuplicateImportSuppressed", {
                    "school_code": school_code, "source_key": source_key,
                    "request_id": request_id, "content_hash": fingerprint,
                    "duplicate_of": original, "imported_by": actor["id"],
                }, actor)
                return {"letter_id": original, "duplicate": True,
                        "reason": "content_fingerprint"}

            letter_id = _letter_id(school_code, source_key)
            body_ref, body_blob = self.vault.seal(body)
            pii_ref, pii_blob = self.vault.seal(canonical(pii))
            self._emit("LetterReceived", {
                "letter_id": letter_id,
                "school_code": school_code,
                "source_key": source_key,
                "request_id": request_id,
                "content_hash": fingerprint,
                "body_secret_ref": body_ref,
                "body_blob": body_blob,
                "pii_secret_ref": pii_ref,
                "pii_blob": pii_blob,
                "imported_by": actor["id"],
                "received_at": event_time or now_iso(),
            }, actor, event_time=event_time)
            return {"letter_id": letter_id, "duplicate": False}

    # ---------------------------------------------------------- 监护授权

    def grant_consent(self, actor: dict, letter_id: str, scopes: list[str],
                      valid_from: Optional[str] = None,
                      valid_until: Optional[str] = None) -> dict:
        with self._lock:
            require_actor(actor, ROLE_GUARDIAN)
            letter = self._require_letter(letter_id)
            scopes = tuple(sorted(set(scopes or [])))
            if not scopes or any(s not in ALL_SCOPES for s in scopes):
                raise DomainError("bad_scopes",
                                  f"scopes 必须是 {ALL_SCOPES} 的非空子集")
            start = parse_ts(valid_from) or parse_ts(now_iso())
            end = parse_ts(valid_until)
            if end and end <= start:
                raise DomainError("bad_window", "valid_until 必须晚于 valid_from")
            if letter.consent and letter.consent.guardian_id != actor["id"]:
                raise DomainError("guardian_mismatch",
                                  "该信件授权已绑定其他监护人身份")
            version = (letter.consent.version + 1) if letter.consent else 1
            self._emit("ConsentGranted", {
                "letter_id": letter_id, "version": version,
                "guardian_id": actor["id"], "scopes": list(scopes),
                "valid_from": start.isoformat(),
                "valid_until": end.isoformat() if end else None,
                "granted_at": now_iso(),
            }, actor)
            return {"letter_id": letter_id, "version": version,
                    "scopes": list(scopes),
                    "valid_until": end.isoformat() if end else None}

    def revoke_consent(self, actor: dict, letter_id: str,
                       reason: str = "") -> dict:
        with self._lock:
            require_actor(actor, ROLE_GUARDIAN)
            letter = self._require_letter(letter_id)
            if not letter.consent:
                raise DomainError("no_consent", "该信件尚无授权记录")
            if letter.consent.guardian_id != actor["id"]:
                raise DomainError("guardian_mismatch",
                                  "只有授权监护人本人可以撤回")
            if letter.consent.revoked_at is not None:
                return {"letter_id": letter_id, "already_revoked": True,
                        "propagation": self.propagation_report(letter_id)}
            revoked_at = now_iso()
            self._emit("ConsentRevoked", {
                "letter_id": letter_id, "revoked_at": revoked_at,
                "reason": reason,
            }, actor)
            # 撤回传播：候选包移除、已封存批次增量更正、展示下架
            self._propagate_revocation(letter_id, revoked_at, actor)
            return {"letter_id": letter_id, "revoked_at": revoked_at,
                    "propagation": self.propagation_report(letter_id)}

    def _propagate_revocation(self, letter_id: str, at: str,
                              guardian: dict) -> None:
        for batch in self.batches.values():
            if letter_id not in batch.open_items:
                continue
            if batch.stage == ST_SEALED:
                continue
            self._emit("BatchItemRemoved", {
                "batch_id": batch.batch_id, "letter_id": letter_id,
                "at": at, "actor_id": guardian["id"], "reason": "consent_withdrawn",
            }, guardian)
        for batch in self.batches.values():
            if batch.stage != ST_SEALED:
                continue
            if not any(e["letter_id"] == letter_id
                       for e in self._current_entries(batch)):
                continue
            self._propose_correction(
                guardian, batch.batch_id, "REMOVE", letter_id,
                "监护人撤回授权，封存后增量移除", None, at=at,
                system_note="withdrawal_propagation")
        for display in self.displays.values():
            if letter_id in display.takedowns:
                continue
            if not any(i["letter_id"] == letter_id for i in display.items):
                continue
            self._emit("DisplayItemRemoved", {
                "display_id": display.display_id, "letter_id": letter_id,
                "at": at, "reason": "consent_withdrawn",
            }, guardian)

    def propagation_report(self, letter_id: str) -> dict:
        """逐处列明副本的当前处置状态——撤回后可确认每一处副本的去向。"""
        self._require_letter(letter_id)
        locations = []
        for batch in sorted(self.batches.values(), key=lambda b: b.created_at):
            if batch.stage == ST_SEALED:
                # 封存后的副本以清单版本为准，不在候选包中重复报告
                pass
            elif letter_id in batch.open_items:
                locations.append({"kind": "CANDIDATE_BATCH",
                                  "batch_id": batch.batch_id,
                                  "stage": batch.stage, "state": "PRESENT"})
            elif any(r["letter_id"] == letter_id for r in batch.removed_items):
                removed = next(r for r in batch.removed_items
                               if r["letter_id"] == letter_id)
                locations.append({"kind": "CANDIDATE_BATCH",
                                  "batch_id": batch.batch_id,
                                  "stage": batch.stage, "state": "REMOVED",
                                  "at": removed["at"],
                                  "reason": removed["reason"]})
            for mv in getattr(batch, "manifest_versions", []):
                if any(e["letter_id"] == letter_id for e in mv["entries"]):
                    current = mv["version"] == len(batch.manifest_versions)
                    locations.append({
                        "kind": "SEALED_MANIFEST",
                        "batch_id": batch.batch_id,
                        "manifest_version": mv["version"],
                        "state": "PRESENT" if current else "REMOVED_IN_LATER_REVISION",
                    })
        for display in sorted(self.displays.values(), key=lambda d: d.published_at):
            if any(i["letter_id"] == letter_id for i in display.items):
                td = display.takedowns.get(letter_id)
                locations.append({
                    "kind": "PUBLIC_DISPLAY",
                    "display_id": display.display_id,
                    "state": "TAKEN_DOWN" if td else "PRESENT",
                    "at": td["at"] if td else None,
                })
        return {"letter_id": letter_id, "locations": locations}

    # ---------------------------------------------------------- 双人复核

    def decide_review(self, actor: dict, letter_id: str, result: str,
                      note: str = "") -> dict:
        with self._lock:
            require_actor(actor, ROLE_REVIEWER)
            letter = self._require_letter(letter_id)
            if result not in ("APPROVE", "REJECT"):
                raise DomainError("bad_result", "result 必须为 APPROVE/REJECT")
            if not letter.consent or not letter.consent.has_scope(
                    "REVIEW", parse_ts(now_iso())):
                raise DomainError("consent_required",
                                  "复核要求该信件当前持有有效的 REVIEW 授权")
            dec = letter.decision
            if dec is None:
                round_no, state = 1, "PENDING_FIRST"
            elif dec.state == "PENDING_FIRST":
                round_no, state = 1, "PENDING_FIRST"
            elif dec.state == "PENDING_SECOND":
                round_no, state = 2, "PENDING_SECOND"
            else:
                raise DomainError("review_closed",
                                  f"复核已结束，结论为 {dec.state}")
            if round_no == 2 and dec.first_reviewer == actor["id"]:
                raise DomainError(
                    "separation_of_duties",
                    "双人复核强制分离：二审人不得与一审人为同一自然人")
            self._emit("ReviewDecided", {
                "letter_id": letter_id, "round": round_no,
                "reviewer": actor["id"], "result": result,
                "note": note, "at": now_iso(),
            }, actor)
            return {"letter_id": letter_id, "round": round_no,
                    "result": result,
                    "state": self.letters[letter_id].decision.state}

    # ---------------------------------------------------------- 批次封存

    def create_batch(self, actor: dict, name: str) -> dict:
        with self._lock:
            require_actor(actor, ROLE_EDITOR)
            batch_id = _batch_id(name)
            if batch_id in self.batches:
                return {"batch_id": batch_id, "already_exists": True}
            self._emit("BatchCreated", {
                "batch_id": batch_id, "name": name,
                "created_by": actor["id"],
            }, actor)
            return {"batch_id": batch_id}

    def add_batch_item(self, actor: dict, batch_id: str, letter_id: str) -> dict:
        with self._lock:
            require_actor(actor, ROLE_EDITOR)
            batch = self._require_batch(batch_id)
            letter = self._require_letter(letter_id)
            if batch.stage != ST_OPEN:
                raise DomainError("batch_not_open",
                                  f"批次处于 {batch.stage}，不能增减候选")
            if letter_id in batch.open_items:
                return {"batch_id": batch_id, "letter_id": letter_id,
                        "already_present": True}
            if not letter.decision or letter.decision.state != "APPROVED":
                raise DomainError("not_approved", "候选信件必须已通过双人复核")
            if not letter.consent or not letter.consent.has_scope(
                    "UPLINK", parse_ts(now_iso())):
                raise DomainError("consent_required",
                                  "候选信件必须当前持有有效的 UPLINK 授权")
            self._emit("BatchItemAdded", {
                "batch_id": batch_id, "letter_id": letter_id,
                "at": now_iso(), "actor_id": actor["id"],
            }, actor)
            return {"batch_id": batch_id, "letter_id": letter_id}

    def freeze_batch(self, actor: dict, batch_id: str) -> dict:
        with self._lock:
            require_actor(actor, ROLE_EDITOR)
            batch = self._require_batch(batch_id)
            if not batch.open_items:
                raise DomainError("empty_batch", "空批次不能封存")
            if batch.stage == ST_OPEN:
                self._change_stage(batch, ST_FROZEN, actor)
            return self.batch_view(batch_id)

    def verify_batch(self, actor: dict, batch_id: str) -> dict:
        with self._lock:
            require_actor(actor, ROLE_EDITOR)
            batch = self._require_batch(batch_id)
            if batch.stage == ST_FROZEN:
                failures = self._verify_entries(batch)
                if failures:
                    raise DomainError(
                        "verification_failed",
                        f"封存前核验发现不合格候选: {failures}", 422)
                self._change_stage(batch, ST_VERIFIED, actor)
            elif batch.stage == ST_OPEN:
                raise DomainError("not_frozen", "批次尚未冻结")
            return self.batch_view(batch_id)

    def _verify_entries(self, batch: BatchState) -> list[dict]:
        failures = []
        for letter_id in sorted(batch.open_items):
            letter = self.letters[letter_id]
            problems = []
            if not letter.decision or letter.decision.state != "APPROVED":
                problems.append("NOT_DOUBLE_APPROVED")
            if not letter.consent or not letter.consent.has_scope(
                    "UPLINK", parse_ts(now_iso())):
                problems.append("UPLINK_CONSENT_INVALID")
            if problems:
                failures.append({"letter_id": letter_id, "problems": problems})
        return failures

    def prepare_manifest(self, actor: dict, batch_id: str) -> dict:
        with self._lock:
            require_actor(actor, ROLE_EDITOR)
            batch = self._require_batch(batch_id)
            if batch.stage == ST_VERIFIED:
                entries = self._build_entries(batch, sorted(batch.open_items))
                manifest_hash = self._manifest_hash(batch_id, 1, "", entries)
                self._emit("BatchStageChanged", {
                    "batch_id": batch_id, "from_stage": ST_VERIFIED,
                    "to_stage": ST_MANIFEST, "at": now_iso(),
                    "actor_id": actor["id"], "manifest_hash": manifest_hash,
                }, actor)
            elif batch.stage == ST_FROZEN:
                raise DomainError("not_verified", "批次尚未通过核验")
            return self.batch_view(batch_id)

    def seal_batch(self, actor: dict, batch_id: str) -> dict:
        with self._lock:
            require_actor(actor, ROLE_EDITOR)
            batch = self._require_batch(batch_id)
            if batch.stage == ST_SEALED:
                return self.batch_view(batch_id)
            if batch.stage not in (ST_OPEN, ST_FROZEN, ST_VERIFIED, ST_MANIFEST):
                raise DomainError("not_ready", "批次尚未进入封存工序")
            if not batch.open_items:
                raise DomainError("empty_batch", "空批次不能封存")
            # 崩溃恢复续跑：从当前检查点补齐缺失阶段，每步都由事件幂等记录
            if batch.stage == ST_OPEN:
                self._change_stage(batch, ST_FROZEN, actor)
            if batch.stage == ST_FROZEN:
                failures = self._verify_entries(batch)
                if failures:
                    raise DomainError("verification_failed",
                                      "封存前核验发现不合格候选", 422)
                self._change_stage(batch, ST_VERIFIED, actor)
            if batch.stage == ST_VERIFIED:
                self.prepare_manifest(actor, batch_id)
            entries = self._build_entries(batch, sorted(batch.open_items))
            manifest_hash = self._manifest_hash(batch_id, 1, "", entries)
            at = now_iso()
            self._emit("BatchSealed", {
                "batch_id": batch_id, "entries": entries,
                "manifest_hash": manifest_hash, "at": at,
            }, actor)
            self._change_stage(batch, ST_SEALED, actor)
            return self.batch_view(batch_id)

    def _change_stage(self, batch: BatchState, to_stage: str,
                      actor: dict) -> None:
        self._emit("BatchStageChanged", {
            "batch_id": batch.batch_id, "from_stage": batch.stage,
            "to_stage": to_stage, "at": now_iso(), "actor_id": actor["id"],
        }, actor)

    def _consent_snapshot(self, letter: LetterState) -> dict:
        c = letter.consent
        return {
            "version": c.version, "guardian_id": c.guardian_id,
            "scopes": list(c.scopes), "valid_from": c.valid_from.isoformat(),
            "valid_until": c.valid_until.isoformat() if c.valid_until else None,
            "granted_at": c.granted_at.isoformat(),
            "revoked_at": c.revoked_at.isoformat() if c.revoked_at else None,
        }

    def _build_entries(self, batch: BatchState, letter_ids: list[str]) -> list[dict]:
        entries = []
        for letter_id in letter_ids:
            letter = self.letters[letter_id]
            entries.append({
                "letter_id": letter_id,
                "content_hash": letter.content_hash,
                "body_secret_ref": letter.body_secret_ref,
                "pii_secret_ref": letter.pii_secret_ref,
                "consent_snapshot": self._consent_snapshot(letter),
            })
        return entries

    @staticmethod
    def _manifest_hash(batch_id: str, version: int, prev_hash: str,
                       entries: list[dict]) -> str:
        return sha256_hex(canonical({
            "batch_id": batch_id, "version": version,
            "prev_hash": prev_hash, "entries": entries,
        }).encode("utf-8"))

    # ---------------------------------------------------------- 增量更正

    def propose_correction(self, actor: dict, batch_id: str, action: str,
                           letter_id: str, reason: str,
                           replacement_id: Optional[str] = None) -> dict:
        with self._lock:
            require_actor(actor, ROLE_EDITOR)
            return self._propose_correction(
                actor, batch_id, action, letter_id, reason, replacement_id)

    def _propose_correction(self, actor: dict, batch_id: str, action: str,
                            letter_id: str, reason: str,
                            replacement_id: Optional[str],
                            at: Optional[str] = None,
                            system_note: str = "") -> dict:
        # 注意：本方法也被撤回传播流程调用，actor 可能是监护人；
        # 角色校验只放在公开入口 propose_correction 中。
        batch = self._require_batch(batch_id)
        if batch.stage != ST_SEALED:
            raise DomainError("not_sealed", "只有已封存批次适用增量更正")
        current = self._current_entries(batch)
        if not any(e["letter_id"] == letter_id for e in current):
            raise DomainError("not_in_manifest", "目标信件不在当前生效清单中")
        if action not in ("REMOVE", "REPLACE"):
            raise DomainError("bad_action", "action 必须为 REMOVE/REPLACE")
        replacement = None
        new_entries = [e for e in current if e["letter_id"] != letter_id]
        if action == "REPLACE":
            if not replacement_id:
                raise DomainError("replacement_required", "REPLACE 需要替换信件")
            rep_letter = self._require_letter(replacement_id)
            if not rep_letter.decision or rep_letter.decision.state != "APPROVED":
                raise DomainError("replacement_not_approved",
                                  "替换信件必须已通过双人复核")
            if not rep_letter.consent or not rep_letter.consent.has_scope(
                    "UPLINK", parse_ts(now_iso())):
                raise DomainError("replacement_consent_invalid",
                                  "替换信件必须持有有效 UPLINK 授权")
            if any(e["letter_id"] == replacement_id for e in current):
                raise DomainError("already_present", "替换信件已在清单中")
            rep_entry = self._build_entries(batch, [replacement_id])[0]
            new_entries.append(rep_entry)
            replacement = {"letter_id": replacement_id,
                           "content_hash": rep_letter.content_hash}
        at = at or now_iso()
        new_version = len(batch.manifest_versions) + 1
        seq = len(batch.corrections) + 1
        prev_hash = batch.manifest_hash
        new_entries.sort(key=lambda e: e["letter_id"])
        new_hash = self._manifest_hash(batch_id, new_version, prev_hash,
                                       new_entries)
        correction_record = {
            "seq": seq, "action": action, "letter_id": letter_id,
            "replacement": replacement, "reason": reason,
            "actor_id": actor["id"], "at": at,
            "system_note": system_note,
        }
        self._emit("BatchCorrectionProposed", {
            "batch_id": batch_id, **correction_record,
            "manifest_hash": new_hash,
        }, actor, event_time=at)
        self._emit("BatchManifestRevised", {
            "batch_id": batch_id, "version": new_version,
            "prev_hash": prev_hash, "entries": new_entries,
            "manifest_hash": new_hash, "at": at,
            "corrections": [correction_record],
        }, actor, event_time=at)
        return {"batch_id": batch_id, "version": new_version,
                "manifest_hash": new_hash, "seq": seq}

    @staticmethod
    def _current_entries(batch: BatchState) -> list[dict]:
        versions = getattr(batch, "manifest_versions", None)
        if not versions:
            return []
        return versions[-1]["entries"]

    # ---------------------------------------------------------- 公开展示

    def publish_display(self, actor: dict, batch_id: str,
                        letter_ids: Optional[list[str]] = None) -> dict:
        with self._lock:
            require_actor(actor, ROLE_EDITOR)
            batch = self._require_batch(batch_id)
            if batch.stage != ST_SEALED:
                raise DomainError("not_sealed", "只能展示已封存批次的清单")
            manifest_entries = self._current_entries(batch)
            available = {e["letter_id"]: e for e in manifest_entries}
            selected = letter_ids if letter_ids is not None else sorted(available)
            unknown = [x for x in selected if x not in available]
            if unknown:
                raise DomainError("not_in_manifest",
                                  f"信件不在当前生效清单: {unknown}")
            if not selected:
                raise DomainError(
                    "display_consent_required",
                    "没有可公开展示的信件：清单为空或授权均已失效", 422)
            at = parse_ts(now_iso())
            items = []
            for letter_id in selected:
                letter = self.letters[letter_id]
                if not letter.consent or not letter.consent.has_scope(
                        "DISPLAY", at):
                    raise DomainError(
                        "display_consent_required",
                        f"信件 {letter_id} 在发布时点无有效 DISPLAY 授权", 422)
                entry = available[letter_id]
                items.append({
                    "letter_id": letter_id,
                    "content_hash": letter.content_hash,
                    "manifest_version": len(batch.manifest_versions),
                    "batch_manifest_hash": batch.manifest_hash,
                    "consent_snapshot": self._consent_snapshot(letter),
                })
            display_id = "D-" + sha256_hex(
                canonical({"batch": batch_id, "at": at.isoformat(),
                           "items": items}).encode("utf-8"))[:12]
            manifest_hash = sha256_hex(
                canonical({"display_id": display_id,
                           "items": items}).encode("utf-8"))
            self._emit("DisplayPublished", {
                "display_id": display_id, "batch_id": batch_id,
                "manifest_version": len(batch.manifest_versions),
                "items": items, "manifest_hash": manifest_hash,
                "published_at": at.isoformat(),
            }, actor)
            return {"display_id": display_id,
                    "manifest_hash": manifest_hash, "count": len(items)}

    def display_authorization_proof(self, display_id: str,
                                    letter_id: str) -> dict:
        """举证：某次公开展示在发布时点对应一份当时有效的授权快照。"""
        display = self.displays.get(display_id)
        if not display:
            raise DomainError("not_found", "展示不存在", 404)
        item = next((i for i in display.items if i["letter_id"] == letter_id),
                    None)
        if not item:
            raise DomainError("not_in_display", "该信件不在此次展示中", 404)
        snap = item["consent_snapshot"]
        published_at = parse_ts(display.published_at)
        consent = ConsentVersion(
            letter_id=letter_id, version=snap["version"],
            guardian_id=snap["guardian_id"], scopes=tuple(snap["scopes"]),
            valid_from=parse_ts(snap["valid_from"]),
            valid_until=parse_ts(snap.get("valid_until")),
            granted_at=parse_ts(snap["granted_at"]),
            revoked_at=parse_ts(snap.get("revoked_at")))
        valid_then = consent.has_scope("DISPLAY", published_at)
        batch = next((b for b in self.batches.values()
                      if any(m["manifest_hash"] == item["batch_manifest_hash"]
                             for m in getattr(b, "manifest_versions", []))),
                     None)
        in_manifest_then = bool(batch) and any(
            e["letter_id"] == letter_id
            for mv in batch.manifest_versions
            if mv["manifest_hash"] == item["batch_manifest_hash"]
            for e in mv["entries"])
        return {
            "display_id": display_id, "letter_id": letter_id,
            "published_at": display.published_at.isoformat(),
            "display_manifest_hash": display.manifest_hash,
            "batch_manifest_hash": item["batch_manifest_hash"],
            "manifest_version": item["manifest_version"],
            "consent_snapshot": snap,
            "consent_valid_at_publish": valid_then,
            "present_in_batch_manifest_at_publish": in_manifest_then,
            "proof_valid": valid_then and in_manifest_then,
            # 授权事后被撤回不影响历史举证：valid_at 只看发布时点
            "later_revoked": bool(
                self.letters[letter_id].consent
                and self.letters[letter_id].consent.revoked_at),
        }

    # ---------------------------------------------------------- 发送回执对账

    def record_receipt(self, actor: dict, batch_id: str, letter_id: str,
                       status: str, carrier_ref: str, receipt_key: str,
                       manifest_version: Optional[int] = None) -> dict:
        with self._lock:
            require_actor(actor, ROLE_CARRIER)
            if receipt_key in self._receipt_by_key:
                existing = self._receipt_by_key[receipt_key]
                return {"duplicate": True, "receipt_key": receipt_key,
                        "status": existing.status}
            batch = self._require_batch(batch_id)
            if batch.stage != ST_SEALED:
                raise DomainError("not_sealed", "未封存批次没有回执")
            if status not in ("SUCCESS", "FAILED"):
                raise DomainError("bad_status", "status 必须为 SUCCESS/FAILED")
            version = manifest_version or len(batch.manifest_versions)
            mv = next((m for m in batch.manifest_versions
                       if m["version"] == version), None)
            if mv is None or not any(e["letter_id"] == letter_id
                                     for e in mv["entries"]):
                raise DomainError("not_in_manifest_version",
                                  f"该信件不在批次 v{version} 清单中")
            self._emit("ReceiptRecorded", {
                "batch_id": batch_id, "letter_id": letter_id,
                "status": status, "carrier_ref": carrier_ref,
                "receipt_key": receipt_key, "manifest_version": version,
                "at": now_iso(), "actor_id": actor["id"],
            }, actor)
            return {"duplicate": False, "receipt_key": receipt_key,
                    "status": status}

    def reconcile(self, batch_id: str) -> dict:
        batch = self._require_batch(batch_id)
        if batch.stage != ST_SEALED:
            raise DomainError("not_sealed", "未封存批次无法对账")
        versions = batch.manifest_versions
        current_version = versions[-1]
        current_ids = {e["letter_id"] for e in current_version["entries"]}
        ever_ids = {e["letter_id"] for mv in versions for e in mv["entries"]}

        last_receipt: dict[str, Receipt] = {}
        for r in self.receipts:
            if r.batch_id != batch_id:
                continue
            prev = last_receipt.get(r.letter_id)
            if prev is None or r.at >= prev.at:
                last_receipt[r.letter_id] = r

        items = []
        missing = failed = sent = 0
        for letter_id in sorted(current_ids):
            r = last_receipt.get(letter_id)
            if r is None:
                state, missing = "MISSING", missing + 1
            elif r.status == "SUCCESS":
                state, sent = "SENT", sent + 1
            else:
                state, failed = "FAILED", failed + 1
            items.append({
                "letter_id": letter_id, "state": state,
                "carrier_ref": r.carrier_ref if r else None,
                "manifest_version_of_receipt":
                    r.manifest_version if r else None,
            })

        # 已发后又被更正移除（撤回传播）——必须向监护人交代
        sent_then_removed = []
        for letter_id in sorted(ever_ids - current_ids):
            r = last_receipt.get(letter_id)
            if r and r.status == "SUCCESS":
                sent_then_removed.append({
                    "letter_id": letter_id,
                    "carrier_ref": r.carrier_ref,
                    "sent_at_manifest_version": r.manifest_version,
                })

        known_keys = {
            (r.letter_id, r.manifest_version)
            for r in self.receipts if r.batch_id == batch_id
        }
        valid_pairs = {(e["letter_id"], mv["version"])
                       for mv in versions for e in mv["entries"]}
        unexpected = sorted(
            {r.receipt_key for r in self.receipts
             if r.batch_id == batch_id
             and (r.letter_id, r.manifest_version) not in valid_pairs})

        return {
            "batch_id": batch_id,
            "current_manifest_version": current_version["version"],
            "manifest_hash": current_version["manifest_hash"],
            "expected": len(current_ids), "sent": sent,
            "failed": failed, "missing": missing,
            "items": items,
            "sent_then_removed": sent_then_removed,
            "unexpected_receipts": unexpected,
            "balanced": sent == len(current_ids) and not failed
                        and not missing and not sent_then_removed
                        and not unexpected,
        }

    # ---------------------------------------------------------- 短时访问

    def request_access(self, actor: dict, letter_id: str, scope: str,
                       purpose: str, ttl_seconds: int = 300) -> dict:
        with self._lock:
            allowed = {ROLE_REVIEWER: "REVIEW", ROLE_EDITOR: "DISPLAY"}
            require_actor(actor, *allowed)
            held = [r for r in (actor.get("roles") or []) if r in allowed]
            expected = allowed[held[0]]
            if scope != expected:
                raise DomainError("scope_forbidden",
                                  f"该角色只能申请 {expected} 范围的原文访问")
            letter = self._require_letter(letter_id)
            if not letter.consent or not letter.consent.has_scope(
                    scope, parse_ts(now_iso())):
                raise DomainError("consent_invalid",
                                  "授权已失效（撤回或过期），不得访问原文")
            if ttl_seconds > 900:
                raise DomainError("ttl_too_long", "单次访问凭据不得超过 15 分钟")
            jti = "G-" + sha256_hex(os.urandom(16).hex().encode())[:16]
            expires = (parse_ts(now_iso()) + timedelta(seconds=ttl_seconds))
            self._emit("AccessGranted", {
                "jti": jti, "letter_id": letter_id, "actor_id": actor["id"],
                "scope": scope, "purpose": purpose,
                "expires_at": expires.isoformat(), "ttl_seconds": ttl_seconds,
            }, actor)
            return {"grant_id": jti, "expires_at": expires.isoformat(),
                    "ttl_seconds": ttl_seconds}

    def reveal(self, actor: dict, grant_id: str) -> dict:
        with self._lock:
            require_actor(actor)
            grant = self.grants.get(grant_id)
            if not grant:
                raise DomainError("not_found", "访问凭据不存在", 404)
            if grant.actor_id != actor["id"]:
                raise DomainError("grant_owner_mismatch",
                                  "凭据仅限申请人本人使用", 403)
            if parse_ts(now_iso()) >= grant.expires_at:
                raise DomainError("grant_expired", "短时访问凭据已过期", 403)
            letter = self._require_letter(grant.letter_id)
            if not letter.consent or not letter.consent.has_scope(
                    grant.scope, parse_ts(now_iso())):
                raise DomainError("consent_invalid",
                                  "授权在凭据有效期内被撤回，访问被拒绝", 403)
            self._emit("AccessRevealed", {"jti": grant_id,
                                          "at": now_iso()}, actor)
            return {"letter_id": grant.letter_id,
                    "body": self.vault.reveal(letter.body_secret_ref)}

    # ---------------------------------------------------------- 查询视图

    def _require_letter(self, letter_id: str) -> LetterState:
        letter = self.letters.get(letter_id)
        if not letter:
            raise DomainError("not_found", f"信件 {letter_id} 不存在", 404)
        return letter

    def _require_batch(self, batch_id: str) -> BatchState:
        batch = self.batches.get(batch_id)
        if not batch:
            raise DomainError("not_found", f"批次 {batch_id} 不存在", 404)
        return batch

    def letter_view(self, letter_id: str) -> dict:
        letter = self._require_letter(letter_id)
        c = letter.consent
        return {
            "letter_id": letter.letter_id,
            "school_code": letter.school_code,
            "content_hash": letter.content_hash,
            "received_at": letter.received_at.isoformat(),
            "status": letter.status,
            "consent": None if not c else {
                "version": c.version, "guardian_id": c.guardian_id,
                "scopes": list(c.scopes),
                "valid_from": c.valid_from.isoformat(),
                "valid_until": c.valid_until.isoformat() if c.valid_until else None,
                "granted_at": c.granted_at.isoformat(),
                "revoked_at": c.revoked_at.isoformat() if c.revoked_at else None,
            },
            "review": None if not letter.decision else {
                "state": letter.decision.state,
                "first_reviewer": letter.decision.first_reviewer,
                "second_reviewer": letter.decision.second_reviewer,
            },
        }

    def batch_view(self, batch_id: str) -> dict:
        batch = self._require_batch(batch_id)
        versions = getattr(batch, "manifest_versions", [])
        current_entries = self._current_entries(batch)
        return {
            "batch_id": batch.batch_id, "name": batch.name,
            "stage": batch.stage,
            # 已封存后以当前生效清单为准，封存前为开放候选集
            "candidate_count": len(current_entries) if batch.stage == ST_SEALED
            else len(batch.open_items),
            "candidate_ids": sorted(
                e["letter_id"] for e in current_entries)
            if batch.stage == ST_SEALED else sorted(batch.open_items),
            "manifest_hash": batch.manifest_hash,
            "sealed_at": batch.sealed_at.isoformat() if batch.sealed_at else None,
            "current_manifest_version": len(versions),
            "current_entries": self._current_entries(batch),
            "corrections": [
                {"seq": c.seq, "action": c.action, "letter_id": c.letter_id,
                 "reason": c.reason, "replacement": c.replacement,
                 "manifest_hash": c.manifest_hash,
                 "at": c.at.isoformat()}
                for c in batch.corrections],
            "stage_history": batch.stage_history,
        }

    def display_view(self, display_id: str) -> dict:
        display = self.displays.get(display_id)
        if not display:
            raise DomainError("not_found", "展示不存在", 404)
        return {
            "display_id": display.display_id,
            "published_at": display.published_at.isoformat(),
            "manifest_hash": display.manifest_hash,
            "items": [
                {**i, "state": "TAKEN_DOWN" if i["letter_id"] in display.takedowns
                 else "ON_DISPLAY"}
                for i in display.items],
        }

    def list_grants(self, include_expired: bool = False) -> list[dict]:
        now = parse_ts(now_iso())
        out = []
        for g in self.grants.values():
            if not include_expired and g.expires_at <= now:
                continue
            out.append({
                "grant_id": g.jti, "letter_id": g.letter_id,
                "actor_id": g.actor_id, "scope": g.scope,
                "purpose": g.purpose, "expires_at": g.expires_at.isoformat(),
                "revealed": g.revealed,
            })
        return out
