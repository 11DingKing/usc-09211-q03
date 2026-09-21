"""家书接力核心领域测试。"""
from __future__ import annotations

import json
import os
import tempfile
import threading
import unittest
from datetime import datetime, timezone
from http.client import HTTPConnection
from http.server import ThreadingHTTPServer
from unittest import mock

from service import relay as relay_mod
from service.events import DomainError, EventStore
from service.main import Handler, build_service
from service.relay import LetterRelay
from service.vault import Vault

SCHOOL = {"id": "school-1", "roles": ["SCHOOL_COORDINATOR"]}
SCHOOL_B = {"id": "school-2", "roles": ["SCHOOL_COORDINATOR"]}
GUARDIAN = {"id": "guardian-1", "roles": ["GUARDIAN"]}
R1 = {"id": "reviewer-a", "roles": ["REVIEWER"]}
R2 = {"id": "reviewer-b", "roles": ["REVIEWER"]}
EDITOR = {"id": "editor-1", "roles": ["EDITOR"]}
CARRIER = {"id": "carrier-1", "roles": ["CARRIER"]}

ALL = ["REVIEW", "UPLINK", "DISPLAY"]
FIXED_KEY = bytes(range(32))


class FakeClock:
    def __init__(self):
        self.t = datetime(2026, 9, 1, 9, 0, tzinfo=timezone.utc)

    def iso(self) -> str:
        return self.t.isoformat()

    def advance(self, seconds: int):
        from datetime import timedelta
        self.t += timedelta(seconds=seconds)


class RelayCase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.clock = FakeClock()
        patch = mock.patch.object(relay_mod, "now_iso", self.clock.iso)
        patch.start()
        self.addCleanup(patch.stop)
        self.svc = self._build()

    def _build(self) -> LetterRelay:
        store = EventStore(os.path.join(self.tmp, "events.log"))
        return LetterRelay(store, Vault(FIXED_KEY))

    def _reload(self) -> LetterRelay:
        """模拟进程崩溃后重启：重放事件日志恢复全部状态。"""
        return self._build()

    # ------------------------------------------------------------ 辅助流程

    def intake(self, body="亲爱的航天员叔叔，我是小明……", school=SCHOOL,
               source="src-1", request="req-1"):
        return self.svc.import_letter(
            school, school["id"], source, request, body,
            {"student_name": "小明", "guardian_phone": "13800000000"})["letter_id"]

    def ready_letter(self, body="亲爱的航天员叔叔，我是小明……",
                     school=SCHOOL, source="src-1", request="req-1",
                     scopes=None, guardian=GUARDIAN):
        lid = self.intake(body, school, source, request)
        self.svc.grant_consent(guardian, lid, scopes or ALL)
        self.svc.decide_review(R1, lid, "APPROVE")
        self.svc.decide_review(R2, lid, "APPROVE")
        return lid

    def sealed_batch(self, name="九月批次", bodies=None):
        bodies = bodies or ["信件甲", "信件乙"]
        ids = []
        for i, body in enumerate(bodies):
            ids.append(self.ready_letter(body, source=f"s{i}", request=f"r{i}"))
        bid = self.svc.create_batch(EDITOR, name)["batch_id"]
        for lid in ids:
            self.svc.add_batch_item(EDITOR, bid, lid)
        self.svc.seal_batch(EDITOR, bid)
        return bid, ids


class IntakeTest(RelayCase):
    def test_retry_same_request_is_idempotent(self):
        r1 = self.svc.import_letter(SCHOOL, "school-1", "s1", "req-1",
                                    "正文A", {"n": "小明"})
        r2 = self.svc.import_letter(SCHOOL, "school-1", "s1", "req-1",
                                    "正文A", {"n": "小明"})
        self.assertFalse(r1["duplicate"])
        self.assertTrue(r2["duplicate"])
        self.assertEqual(r1["letter_id"], r2["letter_id"])
        received = [r for r in self.svc.store.records
                    if r["type"] == "LetterReceived"]
        self.assertEqual(len(received), 1)

    def test_multi_school_duplicate_content_suppressed(self):
        a = self.svc.import_letter(SCHOOL, "school-1", "s1", "r1",
                                   "同一封家书的内容", {})
        b = self.svc.import_letter(SCHOOL_B, "school-2", "x9", "r9",
                                   " 同一封家书的内容 ", {})
        self.assertFalse(a["duplicate"])
        self.assertTrue(b["duplicate"])
        self.assertEqual(b["reason"], "content_fingerprint")
        self.assertEqual(a["letter_id"], b["letter_id"])
        self.assertEqual(len(self.svc.letters), 1)

    def test_distinct_letters_get_distinct_ids(self):
        a = self.ready_letter("内容甲", source="a", request="ra")
        b = self.ready_letter("内容乙", source="b", request="rb")
        self.assertNotEqual(a, b)

    def test_plaintext_never_lands_in_event_log_or_views(self):
        secret_body = "机密正文：我的理想是当工程师"
        secret_pii = "张小明"
        lid = self.svc.import_letter(
            SCHOOL, "school-1", "s1", "r1", secret_body,
            {"student_name": secret_pii, "phone": "139"})["letter_id"]
        with open(self.svc.store.path, encoding="utf-8") as f:
            raw = f.read()
        self.assertNotIn(secret_body, raw)
        self.assertNotIn(secret_pii, raw)
        view = self.svc.letter_view(lid)
        self.assertNotIn("body", view)
        self.assertNotIn("pii", view)
        self.assertEqual(view["school_code"], "school-1")


class ConsentTest(RelayCase):
    def test_expired_consent_blocks_review(self):
        lid = self.intake()
        self.svc.grant_consent(GUARDIAN, lid, ["REVIEW"],
                               valid_until=self.clock.t.replace(
                                   hour=10).isoformat())
        self.clock.advance(3700)
        with self.assertRaises(DomainError) as ctx:
            self.svc.decide_review(R1, lid, "APPROVE")
        self.assertEqual(ctx.exception.code, "consent_required")

    def test_only_bound_guardian_can_revoke(self):
        lid = self.intake()
        self.svc.grant_consent(GUARDIAN, lid, ALL)
        other = {"id": "guardian-2", "roles": ["GUARDIAN"]}
        with self.assertRaises(DomainError) as ctx:
            self.svc.revoke_consent(other, lid)
        self.assertEqual(ctx.exception.code, "guardian_mismatch")

    def test_revoke_propagates_everywhere_and_is_reportable(self):
        l1 = self.ready_letter("第一封", source="1", request="1")
        l2 = self.ready_letter("第二封", source="2", request="2")
        bid = self.svc.create_batch(EDITOR, "批次")["batch_id"]
        self.svc.add_batch_item(EDITOR, bid, l1)
        self.svc.add_batch_item(EDITOR, bid, l2)

        # 1) 开放批次中的候选被移除
        result = self.svc.revoke_consent(GUARDIAN, l1, "家长改变主意")
        self.assertNotIn(l1, self.svc.batches[bid].open_items)
        self.assertIn(l2, self.svc.batches[bid].open_items)
        candidate = next(x for x in result["propagation"]["locations"]
                         if x["kind"] == "CANDIDATE_BATCH")
        self.assertEqual(candidate["state"], "REMOVED")
        self.assertEqual(candidate["reason"], "consent_withdrawn")

        # 2) 已封存批次产生增量更正（封存清单当时只含 l2）
        self.svc.seal_batch(EDITOR, bid)
        self.assertEqual(
            [e["letter_id"] for e in self.svc.batches[bid].manifest_versions[0]["entries"]],
            [l2])
        display = self.svc.publish_display(EDITOR, bid)
        did = display["display_id"]
        self.svc.revoke_consent(GUARDIAN, l2)
        view = self.svc.batch_view(bid)
        self.assertEqual(view["current_manifest_version"], 2)
        self.assertEqual(view["current_entries"], [])
        self.assertEqual(view["corrections"][0]["action"], "REMOVE")
        self.assertEqual(view["corrections"][0]["letter_id"], l2)

        # 3) 公开展示被下架
        disp = self.svc.display_view(did)
        self.assertEqual(
            next(i for i in disp["items"] if i["letter_id"] == l2)["state"],
            "TAKEN_DOWN")

        # 4) 传播报告逐处交代副本去向
        report = self.svc.propagation_report(l2)
        kinds = {(x["kind"], x.get("state")) for x in report["locations"]}
        self.assertIn(("SEALED_MANIFEST", "REMOVED_IN_LATER_REVISION"), kinds)
        self.assertIn(("PUBLIC_DISPLAY", "TAKEN_DOWN"), kinds)

    def test_double_revoke_is_idempotent(self):
        lid = self.intake()
        self.svc.grant_consent(GUARDIAN, lid, ALL)
        self.svc.revoke_consent(GUARDIAN, lid)
        again = self.svc.revoke_consent(GUARDIAN, lid)
        self.assertTrue(again["already_revoked"])


class ReviewTest(RelayCase):
    def test_two_eyes_must_be_different_people(self):
        lid = self.intake()
        self.svc.grant_consent(GUARDIAN, lid, ALL)
        self.svc.decide_review(R1, lid, "APPROVE")
        with self.assertRaises(DomainError) as ctx:
            self.svc.decide_review(R1, lid, "APPROVE")
        self.assertEqual(ctx.exception.code, "separation_of_duties")
        self.svc.decide_review(R2, lid, "APPROVE")
        self.assertEqual(self.svc.letter_view(lid)["review"]["state"],
                         "APPROVED")

    def test_first_round_reject_closes_review(self):
        lid = self.intake()
        self.svc.grant_consent(GUARDIAN, lid, ALL)
        self.svc.decide_review(R1, lid, "REJECT", note="地址信息不全")
        with self.assertRaises(DomainError) as ctx:
            self.svc.decide_review(R2, lid, "APPROVE")
        self.assertEqual(ctx.exception.code, "review_closed")

    def test_review_requires_consent(self):
        lid = self.intake()
        with self.assertRaises(DomainError):
            self.svc.decide_review(R1, lid, "APPROVE")


class SealingTest(RelayCase):
    def test_freeze_blocks_mutation_and_verify_checks(self):
        lid = self.ready_letter("甲", source="1", request="1")
        bid = self.svc.create_batch(EDITOR, "b")["batch_id"]
        self.svc.add_batch_item(EDITOR, bid, lid)
        self.svc.freeze_batch(EDITOR, bid)
        with self.assertRaises(DomainError) as ctx:
            self.svc.add_batch_item(
                EDITOR, bid, self.ready_letter("乙", source="2", request="2"))
        self.assertEqual(ctx.exception.code, "batch_not_open")

    def test_seal_resumes_after_simulated_crash_at_each_stage(self):
        for crash_stage, advance in [
            ("FROZEN", lambda b: self.svc.freeze_batch(EDITOR, b)),
            ("VERIFIED", lambda b: (
                self.svc.freeze_batch(EDITOR, b),
                self.svc.verify_batch(EDITOR, b))),
            ("MANIFEST_READY", lambda b: self.svc.seal_batch  # 先封一个再测重启
             ),
        ]:
            if crash_stage == "MANIFEST_READY":
                continue
            with self.subTest(crash_stage=crash_stage):
                lid = self.ready_letter(f"信-{crash_stage}",
                                        source=f"s-{crash_stage}",
                                        request=f"r-{crash_stage}")
                bid = self.svc.create_batch(EDITOR, f"批次-{crash_stage}")["batch_id"]
                self.svc.add_batch_item(EDITOR, bid, lid)
                advance(bid)
                # 崩溃：新进程从事件日志恢复后续跑封存
                self.svc = self._reload()
                view = self.svc.seal_batch(EDITOR, bid)
                self.assertEqual(view["stage"], "SEALED")
                self.assertIsNotNone(view["manifest_hash"])

    def test_crash_after_manifest_stage_resumes(self):
        lid = self.ready_letter("manifest-信", source="s", request="r")
        bid = self.svc.create_batch(EDITOR, "m批次")["batch_id"]
        self.svc.add_batch_item(EDITOR, bid, lid)
        self.svc.freeze_batch(EDITOR, bid)
        self.svc.verify_batch(EDITOR, bid)
        self.svc.prepare_manifest(EDITOR, bid)
        self.svc = self._reload()
        view = self.svc.seal_batch(EDITOR, bid)
        self.assertEqual(view["stage"], "SEALED")
        # 再次重启后批次仍是已封存，不产生重复封存事件
        self.svc = self._reload()
        view2 = self.svc.seal_batch(EDITOR, bid)
        self.assertEqual(view2["manifest_hash"], view["manifest_hash"])
        seals = [r for r in self.svc.store.records
                 if r["type"] == "BatchSealed"]
        self.assertEqual(len(seals), 1)

    def test_verification_catches_consent_withdrawn_before_seal(self):
        l1 = self.ready_letter("合格信", source="1", request="1")
        l2 = self.ready_letter("被撤回信", source="2", request="2")
        bid = self.svc.create_batch(EDITOR, "b")["batch_id"]
        self.svc.add_batch_item(EDITOR, bid, l1)
        self.svc.add_batch_item(EDITOR, bid, l2)
        self.svc.freeze_batch(EDITOR, bid)
        self.svc.revoke_consent(GUARDIAN, l2)  # 传播移除候选
        self.assertNotIn(l2, self.svc.batch_view(bid)["candidate_ids"])
        # 剩余候选核验通过
        self.svc.verify_batch(EDITOR, bid)


class CorrectionTest(RelayCase):
    def test_post_seal_remove_and_replace_chain_manifests(self):
        l1, l2 = self.ready_letter("甲", source="1", request="1"), None
        l2 = self.ready_letter("乙", source="2", request="2")
        l3 = self.ready_letter("丙", source="3", request="3")
        bid = self.svc.create_batch(EDITOR, "b")["batch_id"]
        self.svc.add_batch_item(EDITOR, bid, l1)
        self.svc.add_batch_item(EDITOR, bid, l2)
        self.svc.seal_batch(EDITOR, bid)
        batch = self.svc.batches[bid]
        v1_hash = batch.manifest_hash
        v1_entries = list(batch.manifest_versions[0]["entries"])

        # 封存后不能直接改候选集
        with self.assertRaises(DomainError) as ctx:
            self.svc.add_batch_item(EDITOR, bid, l3)
        self.assertEqual(ctx.exception.code, "batch_not_open")

        # 增量移除：v1 原样保留，v2 链式追加
        self.svc.propose_correction(EDITOR, bid, "REMOVE", l2, "发现新问题")
        self.assertEqual(batch.manifest_versions[0]["entries"], v1_entries)
        self.assertEqual(batch.manifest_versions[0]["manifest_hash"], v1_hash)
        self.assertEqual(batch.manifest_versions[1]["prev_hash"], v1_hash)
        self.assertEqual(
            [e["letter_id"] for e in batch.manifest_versions[1]["entries"]],
            [l1])

        # 增量替换
        self.svc.propose_correction(
            EDITOR, bid, "REPLACE", l1, "撤回后替换", l3)
        self.assertEqual(
            [e["letter_id"] for e in self.svc._current_entries(batch)], [l3])
        self.assertEqual(len(batch.manifest_versions), 3)

        # 更正记录本身也在崩溃恢复后完整保留
        self.svc = self._reload()
        view = self.svc.batch_view(bid)
        self.assertEqual(view["current_manifest_version"], 3)
        self.assertEqual(len(view["corrections"]), 2)


class DisplayProofTest(RelayCase):
    def test_display_and_proof_bind_to_consent_snapshot(self):
        l1 = self.ready_letter("展示信", source="1", request="1")
        bid = self.svc.create_batch(EDITOR, "b")["batch_id"]
        self.svc.add_batch_item(EDITOR, bid, l1)
        self.svc.seal_batch(EDITOR, bid)
        did = self.svc.publish_display(EDITOR, bid)["display_id"]

        proof = self.svc.display_authorization_proof(did, l1)
        self.assertTrue(proof["proof_valid"])
        self.assertTrue(proof["consent_valid_at_publish"])

        # 事后撤回：历史展示的授权举证依然成立，但展示项已下架
        self.svc.revoke_consent(GUARDIAN, l1)
        proof = self.svc.display_authorization_proof(did, l1)
        self.assertTrue(proof["consent_valid_at_publish"])
        self.assertTrue(proof["proof_valid"])
        self.assertTrue(proof["later_revoked"])
        self.assertEqual(
            self.svc.display_view(did)["items"][0]["state"], "TAKEN_DOWN")

        # 撤回后不能再发布新的展示
        with self.assertRaises(DomainError) as ctx:
            self.svc.publish_display(EDITOR, bid)
        self.assertEqual(ctx.exception.code, "display_consent_required")

    def test_display_requires_display_scope(self):
        lid = self.ready_letter("无展示授权", source="s", request="r",
                                scopes=["REVIEW", "UPLINK"])
        bid = self.svc.create_batch(EDITOR, "b")["batch_id"]
        self.svc.add_batch_item(EDITOR, bid, lid)
        self.svc.seal_batch(EDITOR, bid)
        with self.assertRaises(DomainError) as ctx:
            self.svc.publish_display(EDITOR, bid)
        self.assertEqual(ctx.exception.code, "display_consent_required")


class AccessTest(RelayCase):
    def test_short_lived_grant_reveal_expiry_and_revocation(self):
        lid = self.intake()
        self.svc.grant_consent(GUARDIAN, lid, ALL)

        # 未授权角色不能申请
        with self.assertRaises(DomainError):
            self.svc.request_access(SCHOOL, lid, "REVIEW", "看内容")

        grant = self.svc.request_access(R1, lid, "REVIEW", "一审",
                                        ttl_seconds=300)
        gid = grant["grant_id"]
        revealed = self.svc.reveal(R1, gid)
        self.assertIn("小明", revealed["body"])

        # 凭据只能本人使用
        with self.assertRaises(DomainError) as ctx:
            self.svc.reveal(R2, gid)
        self.assertEqual(ctx.exception.code, "grant_owner_mismatch")

        # TTL 上限 15 分钟
        with self.assertRaises(DomainError):
            self.svc.request_access(R1, lid, "REVIEW", "x", ttl_seconds=901)

        # 到期即失效
        self.clock.advance(301)
        with self.assertRaises(DomainError) as ctx:
            self.svc.reveal(R1, gid)
        self.assertEqual(ctx.exception.code, "grant_expired")

    def test_revocation_kills_grant_before_reveal(self):
        lid = self.intake()
        self.svc.grant_consent(GUARDIAN, lid, ALL)
        gid = self.svc.request_access(R1, lid, "REVIEW", "一审")["grant_id"]
        self.svc.revoke_consent(GUARDIAN, lid)
        with self.assertRaises(DomainError) as ctx:
            self.svc.reveal(R1, gid)
        self.assertEqual(ctx.exception.code, "consent_invalid")


class ReceiptTest(RelayCase):
    def test_receipt_idempotency_and_balanced_reconcile(self):
        bid, (l1, l2) = self.sealed_batch()
        for lid in (l1, l2):
            r = self.svc.record_receipt(
                CARRIER, bid, lid, "SUCCESS", f"carrier-{lid}", f"key-{lid}")
            dup = self.svc.record_receipt(
                CARRIER, bid, lid, "SUCCESS", f"carrier-{lid}", f"key-{lid}")
            self.assertFalse(r["duplicate"])
            self.assertTrue(dup["duplicate"])
        report = self.svc.reconcile(bid)
        self.assertTrue(report["balanced"])
        self.assertEqual(report["sent"], 2)

    def test_failed_and_missing_receipts_unbalance(self):
        bid, (l1, l2) = self.sealed_batch("另一批次", ["丙", "丁"])
        self.svc.record_receipt(CARRIER, bid, l1, "FAILED", "c1", "k1")
        report = self.svc.reconcile(bid)
        self.assertFalse(report["balanced"])
        self.assertEqual(report["failed"], 1)
        self.assertEqual(report["missing"], 1)

    def test_sent_then_corrected_is_flagged(self):
        bid, (l1, l2) = self.sealed_batch()
        self.svc.record_receipt(CARRIER, bid, l1, "SUCCESS", "c1", "k1")
        self.svc.record_receipt(CARRIER, bid, l2, "SUCCESS", "c2", "k2")
        # 封存后更正移除 l2（模拟撤回传播）
        self.svc.propose_correction(EDITOR, bid, "REMOVE", l2, "撤回")
        report = self.svc.reconcile(bid)
        self.assertFalse(report["balanced"])
        self.assertEqual([x["letter_id"] for x in report["sent_then_removed"]],
                         [l2])

    def test_receipt_rejects_unknown_manifest_member(self):
        bid, (l1, l2) = self.sealed_batch()
        with self.assertRaises(DomainError) as ctx:
            self.svc.record_receipt(CARRIER, bid, "L-deadbeef",
                                    "SUCCESS", "x", "kx")
        self.assertEqual(ctx.exception.code, "not_in_manifest_version")


class HashChainTest(RelayCase):
    def test_event_and_recorded_time_are_separate(self):
        lid = self.svc.import_letter(
            SCHOOL, "school-1", "s", "r", "正文", {},
            event_time="2026-08-01T08:00:00+00:00")
        rec = self.svc.store.records[0]
        self.assertEqual(rec["event_time"], "2026-08-01T08:00:00+00:00")
        self.assertIn("recorded_time", rec)
        self.assertNotEqual(rec["recorded_time"], rec["event_time"])

    def test_tampered_log_refuses_to_load(self):
        self.intake()
        path = self.svc.store.path
        with open(path, encoding="utf-8") as f:
            lines = f.read().splitlines()
        rec = json.loads(lines[-1])
        rec["data"]["source_key"] = "tampered"  # 模拟覆盖审计记录
        lines[-1] = json.dumps(rec, ensure_ascii=False)
        with open(path, "w", encoding="utf-8") as f:
            f.write("\n".join(lines) + "\n")
        with self.assertRaises(DomainError) as ctx:
            EventStore(path)
        self.assertEqual(ctx.exception.code, "log_tampered")


class HttpFlowTest(unittest.TestCase):
    """端到端 HTTP 冒烟：真实服务 + 临时数据目录。"""

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        Handler.service = build_service(self.tmp)
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.port = self.server.server_address[1]
        self.thread = threading.Thread(target=self.server.serve_forever,
                                       daemon=True)
        self.thread.start()

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()

    def call(self, method, path, payload=None):
        conn = HTTPConnection("127.0.0.1", self.port)
        body = json.dumps(payload) if payload is not None else None
        conn.request(method, path, body=body,
                     headers={"Content-Type": "application/json"})
        resp = conn.getresponse()
        data = json.loads(resp.read())
        return resp.status, data

    def test_full_flow_over_http(self):
        status, r = self.call("POST", "/letters/import", {
            "actor": {"id": "sch", "roles": ["SCHOOL_COORDINATOR"]},
            "school_code": "sch", "source_key": "s1", "request_id": "q1",
            "body": "HTTP 端到端家书", "pii": {"name": "小红"}})
        self.assertEqual(status, 201)
        lid = r["letter_id"]

        self.assertEqual(self.call("POST", f"/letters/{lid}/consent/grant", {
            "actor": {"id": "g", "roles": ["GUARDIAN"]},
            "scopes": ALL})[0], 200)
        for reviewer in ("ra", "rb"):
            self.assertEqual(self.call("POST", f"/letters/{lid}/review", {
                "actor": {"id": reviewer, "roles": ["REVIEWER"]},
                "result": "APPROVE"})[0], 200)

        bid = self.call("POST", "/batches", {
            "actor": {"id": "e", "roles": ["EDITOR"]}, "name": "HTTP批次"})[1]["batch_id"]
        self.assertEqual(self.call("POST", f"/batches/{bid}/items", {
            "actor": {"id": "e", "roles": ["EDITOR"]},
            "letter_id": lid})[0], 200)
        self.assertEqual(self.call("POST", f"/batches/{bid}/seal", {
            "actor": {"id": "e", "roles": ["EDITOR"]}})[0], 200)

        self.assertEqual(self.call("POST", f"/batches/{bid}/receipts", {
            "actor": {"id": "c", "roles": ["CARRIER"]},
            "letter_id": lid, "status": "SUCCESS",
            "carrier_ref": "uplink-1", "receipt_key": "rcp-1"})[0], 201)
        status, report = self.call("GET", f"/batches/{bid}/reconcile")
        self.assertTrue(report["balanced"])

        did = self.call("POST", f"/batches/{bid}/displays", {
            "actor": {"id": "e", "roles": ["EDITOR"]}})[1]["display_id"]
        status, proof = self.call(
            "GET", f"/displays/{did}/proof/{lid}")
        self.assertTrue(proof["proof_valid"])

        # 健康检查保持兼容
        self.assertEqual(self.call("GET", "/health"), (200, {"status": "ok"}))


if __name__ == "__main__":
    unittest.main()
