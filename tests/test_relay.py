"""家书接力核心业务测试。

每个测试对应任务书的一项要求：幂等收件、匿名化、授权有效期与撤回传播、
双人复核、封存不可变与增量更正、回执对账、短时访问、崩溃恢复、展示快照证明、
审计链防篡改。
"""
import json
import os
import tempfile
import unittest
from datetime import datetime, timedelta, timezone

from service.clock import ManualClock
from service.relay import (
    Conflict,
    Forbidden,
    NotFound,
    RelayService,
    SimulatedCrash,
    Validation,
)
from service.store import Store

T0 = datetime(2026, 9, 1, 8, 0, tzinfo=timezone.utc)
VAULT_KEY = b"test-vault-key-32bytes-padding!!"
CONTENT = "亲爱的航天员叔叔：你们在天上看地球是什么颜色？"


def make_service(path=":memory:", start=T0):
    clock = ManualClock(start)
    service = RelayService(Store(path), clock, VAULT_KEY)
    return service, clock


class RelayTestCase(unittest.TestCase):
    def setUp(self):
        self.service, self.clock = make_service()

    # ---- 常用流程辅助 -------------------------------------------------
    def import_letter(self, key="imp-1", name="小明", school="育才小学",
                      guardian="guardian-1", content=CONTENT, org="育才小学导入点"):
        return self.service.import_letter(
            actor="teacher-1", role="intake_officer", idempotency_key=key,
            child_name=name, school=school, guardian_ref=guardian,
            content=content, event_time="2026-09-01T09:00:00+00:00", source_org=org)

    def grant(self, pseudonym, scope="uplink", key=None, days=30):
        return self.service.grant_consent(
            actor="guardian-1", role="guardian",
            idempotency_key=key or f"consent-{scope}-{pseudonym}",
            pseudonym=pseudonym, scope=scope,
            valid_from="2026-09-01T00:00:00+00:00",
            valid_until=(T0 + timedelta(days=days)).isoformat(),
            event_time="2026-09-01T09:05:00+00:00")

    def approve(self, letter_id):
        first = self.service.review(
            actor="reviewer-1", role="reviewer", idempotency_key=f"rv1-{letter_id}",
            letter_id=letter_id, decision="approve", note="内容合规",
            event_time="2026-09-01T10:00:00+00:00")
        second = self.service.review(
            actor="reviewer-2", role="reviewer", idempotency_key=f"rv2-{letter_id}",
            letter_id=letter_id, decision="approve", note="复核通过",
            event_time="2026-09-01T10:05:00+00:00")
        return first, second

    def approved_letter(self, key="imp-1", content=CONTENT, name="小明",
                        school="育才小学", guardian="guardian-1", org="育才小学导入点"):
        letter = self.import_letter(key=key, name=name, school=school,
                                    guardian=guardian, content=content, org=org)
        self.grant(letter["pseudonym"], "uplink")
        self.approve(letter["letter_id"])
        return letter

    def sealed_batch(self, letters, key="batch-1"):
        batch = self.service.create_batch(
            actor="op-1", role="batch_operator", idempotency_key=key, title="九月上行批次")
        for i, letter in enumerate(letters):
            self.service.stage_letter(
                actor="op-1", role="batch_operator", idempotency_key=f"stage-{key}-{i}",
                batch_id=batch["batch_id"], letter_id=letter["letter_id"])
        return self.service.seal_batch(
            actor="op-1", role="batch_operator", batch_id=batch["batch_id"])

    def scalar(self, sql, args=()):
        return self.service.store.conn.execute(sql, args).fetchone()[0]


class ImportTest(RelayTestCase):
    def test_retry_import_deduplicates(self):
        """网络重试：同一幂等键不产生第二份记录。"""
        first = self.import_letter()
        again = self.import_letter()
        self.assertFalse(first["deduplicated"])
        self.assertTrue(again["deduplicated"])
        self.assertEqual(first["letter_id"], again["letter_id"])
        self.assertEqual(self.scalar("SELECT COUNT(*) FROM letters"), 1)

    def test_multi_school_duplicate_import_deduplicates(self):
        """多校重复导入：不同幂等键、同一孩子同一正文，仍只保留一份。"""
        a = self.import_letter(key="school-a/001", org="育才小学导入点")
        b = self.import_letter(key="school-b/009", org="第二实验小学导入点")
        self.assertFalse(a["deduplicated"])
        self.assertTrue(b["deduplicated"])
        self.assertEqual(a["letter_id"], b["letter_id"])
        self.assertEqual(self.scalar("SELECT COUNT(*) FROM letters"), 1)
        self.assertEqual(self.scalar("SELECT COUNT(*) FROM letter_refs"), 2)

    def test_intake_record_is_pseudonymous(self):
        """业务记录不含姓名/学校/正文，直接身份只在保险库且限角色读取。"""
        result = self.import_letter()
        row = self.service.store.conn.execute("SELECT * FROM letters").fetchone()
        row_json = json.dumps(dict(row), ensure_ascii=False)
        self.assertNotIn("小明", row_json)
        self.assertNotIn("育才小学\"", row_json)
        self.assertNotIn(CONTENT, row_json)
        with self.assertRaises(Forbidden):
            self.service.read_identity(actor="ed-1", role="editor",
                                       pseudonym=result["pseudonym"])
        pii = self.service.read_identity(actor="po-1", role="privacy_officer",
                                         pseudonym=result["pseudonym"])
        self.assertEqual(pii["identity"]["child_name"], "小明")


class ConsentTest(RelayTestCase):
    def test_expired_consent_blocks_staging_and_display(self):
        """授权过期后不能进候选、不能展示。"""
        letter = self.approved_letter()
        batch = self.service.create_batch(
            actor="op-1", role="batch_operator", idempotency_key="b-exp", title="过期测试")
        self.clock.advance(days=31)  # 授权只有 30 天
        with self.assertRaises(Conflict):
            self.service.stage_letter(
                actor="op-1", role="batch_operator", idempotency_key="st-exp",
                batch_id=batch["batch_id"], letter_id=letter["letter_id"])
        with self.assertRaises(Conflict):
            self.service.record_display(
                actor="ed-1", role="editor", idempotency_key="dp-exp",
                letter_id=letter["letter_id"], channel="官网",
                event_time=self.clock.now().isoformat())

    def test_missing_consent_blocks_staging(self):
        letter = self.import_letter()
        self.approve(letter["letter_id"])
        batch = self.service.create_batch(
            actor="op-1", role="batch_operator", idempotency_key="b-nc", title="无授权")
        with self.assertRaises(Conflict):
            self.service.stage_letter(
                actor="op-1", role="batch_operator", idempotency_key="st-nc",
                batch_id=batch["batch_id"], letter_id=letter["letter_id"])

    def test_revocation_propagates_and_is_idempotent(self):
        """撤回上行授权：候选池移除、开放批次移除、已封存批次增量更正，且可重试。"""
        staged = self.approved_letter(key="imp-s", content="第一封信")
        sealed = self.approved_letter(key="imp-f", content="第二封信")
        pseudonym = staged["pseudonym"]
        self.assertEqual(pseudonym, sealed["pseudonym"])

        open_batch = self.service.create_batch(
            actor="op-1", role="batch_operator", idempotency_key="b-open", title="开放批")
        self.service.stage_letter(
            actor="op-1", role="batch_operator", idempotency_key="st-open",
            batch_id=open_batch["batch_id"], letter_id=staged["letter_id"])
        sealed_result = self.sealed_batch([sealed], key="b-sealed")

        consent_id = self.scalar(
            "SELECT consent_id FROM consents WHERE pseudonym = ? AND scope = 'uplink'",
            (pseudonym,))
        result = self.service.revoke_consent(
            actor="guardian-1", role="guardian", idempotency_key="revoke-1",
            consent_id=consent_id, reason="孩子撤回授权",
            event_time="2026-09-02T09:00:00+00:00")

        propagation = result["propagation"]
        self.assertCountEqual(propagation["letters_withdrawn"],
                              [staged["letter_id"], sealed["letter_id"]])
        self.assertEqual(propagation["staging_removed"],
                         [{"batch_id": open_batch["batch_id"],
                           "letter_id": staged["letter_id"]}])
        self.assertEqual(len(propagation["amendments_created"]), 1)
        self.assertEqual(propagation["amendments_created"][0]["batch_id"],
                         sealed_result["batch_id"])

        # 位置查询能明确回答“副本是否仍在候选包中”
        loc1 = self.service.letter_locations(
            actor="guardian-1", role="guardian", letter_id=staged["letter_id"])
        self.assertEqual(loc1["status"], "withdrawn")
        self.assertFalse(loc1["candidate"])
        self.assertEqual(loc1["open_batches"], [])
        loc2 = self.service.letter_locations(
            actor="guardian-1", role="guardian", letter_id=sealed["letter_id"])
        self.assertTrue(loc2["sealed_batches"][0]["removed_by_amendment"])

        # 撤回重试返回首次传播结果，不产生重复更正
        retry = self.service.revoke_consent(
            actor="guardian-1", role="guardian", idempotency_key="revoke-1",
            consent_id=consent_id, reason="孩子撤回授权",
            event_time="2026-09-02T09:00:00+00:00")
        self.assertTrue(retry["deduplicated"])
        self.assertEqual(retry["propagation"], propagation)
        self.assertEqual(self.scalar("SELECT COUNT(*) FROM amendments"), 1)

    def test_display_revocation_blocks_future_displays(self):
        """撤回展示授权后，新展示被拒，历史展示证明仍然成立。"""
        letter = self.approved_letter()
        consent = self.grant(letter["pseudonym"], "display")
        display = self.service.record_display(
            actor="ed-1", role="editor", idempotency_key="dp-1",
            letter_id=letter["letter_id"], channel="官网",
            event_time="2026-09-10T09:00:00+00:00")
        self.clock.advance(days=20)
        self.service.revoke_consent(
            actor="guardian-1", role="guardian", idempotency_key="revoke-dp",
            consent_id=consent["consent_id"], reason="不再同意展示",
            event_time="2026-09-21T09:00:00+00:00")
        with self.assertRaises(Conflict):
            self.service.record_display(
                actor="ed-1", role="editor", idempotency_key="dp-2",
                letter_id=letter["letter_id"], channel="公众号",
                event_time="2026-09-22T09:00:00+00:00")
        proof = self.service.display_proof(actor="aud-1", role="auditor",
                                           display_id=display["display_id"])
        self.assertTrue(proof["verified"])


class ReviewTest(RelayTestCase):
    def test_two_person_separation(self):
        """双人分离：导入人不可复核、同一人不可复两次、两人通过后生效。"""
        letter = self.import_letter()
        lid = letter["letter_id"]
        with self.assertRaises(Forbidden):
            self.service.review(
                actor="teacher-1", role="reviewer", idempotency_key="rv-self",
                letter_id=lid, decision="approve", note="", event_time=T0.isoformat())

        first = self.service.review(
            actor="reviewer-1", role="reviewer", idempotency_key="rv-a",
            letter_id=lid, decision="approve", note="ok", event_time=T0.isoformat())
        self.assertEqual(first["letter_status"], "received")
        self.assertEqual(first["approvals"], 1)

        with self.assertRaises(Conflict):
            self.service.review(
                actor="reviewer-1", role="reviewer", idempotency_key="rv-a2",
                letter_id=lid, decision="approve", note="again", event_time=T0.isoformat())

        retry = self.service.review(
            actor="reviewer-1", role="reviewer", idempotency_key="rv-a",
            letter_id=lid, decision="approve", note="ok", event_time=T0.isoformat())
        self.assertTrue(retry["deduplicated"])

        second = self.service.review(
            actor="reviewer-2", role="reviewer", idempotency_key="rv-b",
            letter_id=lid, decision="approve", note="ok", event_time=T0.isoformat())
        self.assertEqual(second["letter_status"], "approved")
        self.assertEqual(second["approvals"], 2)

        with self.assertRaises(Conflict):
            self.service.review(
                actor="reviewer-3", role="reviewer", idempotency_key="rv-c",
                letter_id=lid, decision="approve", note="late", event_time=T0.isoformat())

    def test_reject_is_final(self):
        letter = self.import_letter()
        result = self.service.review(
            actor="reviewer-1", role="reviewer", idempotency_key="rv-r",
            letter_id=letter["letter_id"], decision="reject", note="含家庭住址",
            event_time=T0.isoformat())
        self.assertEqual(result["letter_status"], "rejected")
        with self.assertRaises(Conflict):
            self.service.review(
                actor="reviewer-2", role="reviewer", idempotency_key="rv-r2",
                letter_id=letter["letter_id"], decision="approve", note="",
                event_time=T0.isoformat())


class BatchTest(RelayTestCase):
    def test_sealed_batch_immutable_but_amendable(self):
        """封存后不能加候选、不能改清单，只能追加增量更正。"""
        first = self.approved_letter(key="imp-1", content="第一封")
        second = self.approved_letter(key="imp-2", content="第二封")
        sealed = self.sealed_batch([first])
        self.assertEqual(sealed["member_count"], 1)

        with self.assertRaises(Conflict):
            self.service.stage_letter(
                actor="op-1", role="batch_operator", idempotency_key="st-late",
                batch_id=sealed["batch_id"], letter_id=second["letter_id"])

        amendment = self.service.add_amendment(
            actor="op-1", role="batch_operator", idempotency_key="am-1",
            batch_id=sealed["batch_id"], letter_id=first["letter_id"],
            action="remove", reason="监护人要求撤下")
        retry = self.service.add_amendment(
            actor="op-1", role="batch_operator", idempotency_key="am-1",
            batch_id=sealed["batch_id"], letter_id=first["letter_id"],
            action="remove", reason="监护人要求撤下")
        self.assertTrue(retry["deduplicated"])
        self.assertEqual(amendment["amendment_id"], retry["amendment_id"])

        # 封存清单本身未被改动，对账口径才排除该信
        self.assertEqual(
            self.scalar("SELECT COUNT(*) FROM batch_members WHERE batch_id = ?",
                        (sealed["batch_id"],)), 1)
        report = self.service.reconcile(actor="au-1", role="auditor",
                                        batch_id=sealed["batch_id"])
        self.assertEqual(report["expected"], [])

        open_batch = self.service.create_batch(
            actor="op-1", role="batch_operator", idempotency_key="b-open",
            title="未封存")
        with self.assertRaises(Conflict):
            self.service.add_amendment(
                actor="op-1", role="batch_operator", idempotency_key="am-x",
                batch_id=open_batch["batch_id"], letter_id=second["letter_id"],
                action="remove", reason="尚未封存")

    def test_letter_cannot_be_sealed_twice(self):
        letter = self.approved_letter()
        self.sealed_batch([letter], key="b-first")
        batch2 = self.service.create_batch(
            actor="op-1", role="batch_operator", idempotency_key="b-second", title="第二批")
        with self.assertRaises(Conflict):
            self.service.stage_letter(
                actor="op-1", role="batch_operator", idempotency_key="st-dup",
                batch_id=batch2["batch_id"], letter_id=letter["letter_id"])


class ReceiptTest(RelayTestCase):
    def test_reconciliation(self):
        """对账：应发/已发/缺失/失败/异常分类正确，全部送达后平衡。"""
        letters = [self.approved_letter(key=f"imp-{i}", content=f"第{i}封")
                   for i in range(3)]
        sealed = self.sealed_batch(letters)
        batch_id = sealed["batch_id"]
        lids = [l["letter_id"] for l in letters]

        self.service.record_receipt(
            actor="op-1", role="batch_operator", idempotency_key="rc-0",
            batch_id=batch_id, letter_id=lids[0], status="delivered",
            event_time="2026-09-05T00:00:00+00:00")
        self.service.record_receipt(
            actor="op-1", role="batch_operator", idempotency_key="rc-1",
            batch_id=batch_id, letter_id=lids[1], status="failed",
            event_time="2026-09-05T00:01:00+00:00")

        report = self.service.reconcile(actor="op-1", role="batch_operator",
                                        batch_id=batch_id)
        self.assertEqual(report["delivered"], [lids[0]])
        self.assertEqual(report["failed"], [lids[1]])
        self.assertEqual(report["missing"], [lids[2]])
        self.assertFalse(report["balanced"])

        # 回执重试幂等；失败重发后状态更新
        retry = self.service.record_receipt(
            actor="op-1", role="batch_operator", idempotency_key="rc-0",
            batch_id=batch_id, letter_id=lids[0], status="delivered",
            event_time="2026-09-05T00:00:00+00:00")
        self.assertTrue(retry["deduplicated"])
        self.service.record_receipt(
            actor="op-1", role="batch_operator", idempotency_key="rc-1b",
            batch_id=batch_id, letter_id=lids[1], status="delivered",
            event_time="2026-09-05T01:00:00+00:00")
        self.service.record_receipt(
            actor="op-1", role="batch_operator", idempotency_key="rc-2",
            batch_id=batch_id, letter_id=lids[2], status="delivered",
            event_time="2026-09-05T00:02:00+00:00")
        report = self.service.reconcile(actor="op-1", role="batch_operator",
                                        batch_id=batch_id)
        self.assertTrue(report["balanced"])

        # 从未入批的回执记为异常，破坏平衡
        self.service.record_receipt(
            actor="op-1", role="batch_operator", idempotency_key="rc-x",
            batch_id=batch_id, letter_id="L_unknown", status="delivered",
            event_time="2026-09-05T03:00:00+00:00")
        report = self.service.reconcile(actor="op-1", role="batch_operator",
                                        batch_id=batch_id)
        self.assertEqual(report["unexpected"], ["L_unknown"])
        self.assertFalse(report["balanced"])


class ContentAccessTest(RelayTestCase):
    def test_short_lived_role_limited_access(self):
        """原文只对限定角色开放，授权短时有效，过期即拒，读取留痕。"""
        letter = self.import_letter()
        lid = letter["letter_id"]
        with self.assertRaises(Forbidden):
            self.service.request_content_access(
                actor="ed-1", role="editor", idempotency_key="g-0",
                letter_id=lid, ttl_seconds=60)
        with self.assertRaises(Validation):
            self.service.request_content_access(
                actor="reviewer-1", role="reviewer", idempotency_key="g-long",
                letter_id=lid, ttl_seconds=3600)

        grant = self.service.request_content_access(
            actor="reviewer-1", role="reviewer", idempotency_key="g-1",
            letter_id=lid, ttl_seconds=60)
        content = self.service.read_content(actor="reviewer-1",
                                            grant_id=grant["grant_id"])
        self.assertEqual(content["content"], CONTENT)

        with self.assertRaises(Forbidden):
            self.service.read_content(actor="reviewer-2", grant_id=grant["grant_id"])

        self.clock.advance(seconds=61)
        with self.assertRaises(Forbidden):
            self.service.read_content(actor="reviewer-1", grant_id=grant["grant_id"])

        reads = self.scalar("SELECT COUNT(*) FROM audit_log WHERE action = 'content.read'")
        self.assertEqual(reads, 1)


class SealRecoveryTest(unittest.TestCase):
    def test_crash_recovery_resumes_sealing(self):
        """封存中途崩溃：重启后从断点续跑，成员完整、无重复、日志收口。"""
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "relay.db")
            svc1, _ = make_service(path)
            letters = []
            for i in range(5):
                letter = svc1.import_letter(
                    actor="teacher-1", role="intake_officer", idempotency_key=f"imp-{i}",
                    child_name="小明", school="育才小学", guardian_ref="guardian-1",
                    content=f"第{i}封信", event_time="2026-09-01T09:00:00+00:00",
                    source_org="育才小学导入点")
                svc1.grant_consent(
                    actor="guardian-1", role="guardian",
                    idempotency_key=f"c-u-{i}", pseudonym=letter["pseudonym"],
                    scope="uplink", valid_from="2026-09-01T00:00:00+00:00",
                    valid_until="2026-10-01T00:00:00+00:00",
                    event_time="2026-09-01T09:05:00+00:00")
                for reviewer in ("reviewer-1", "reviewer-2"):
                    svc1.review(
                        actor=reviewer, role="reviewer",
                        idempotency_key=f"rv-{reviewer}-{i}",
                        letter_id=letter["letter_id"], decision="approve", note="",
                        event_time="2026-09-01T10:00:00+00:00")
                letters.append(letter)
            batch = svc1.create_batch(
                actor="op-1", role="batch_operator", idempotency_key="b-1", title="恢复测试")
            for i, letter in enumerate(letters):
                svc1.stage_letter(
                    actor="op-1", role="batch_operator", idempotency_key=f"st-{i}",
                    batch_id=batch["batch_id"], letter_id=letter["letter_id"])

            with self.assertRaises(SimulatedCrash):
                svc1.seal_batch(actor="op-1", role="batch_operator",
                                batch_id=batch["batch_id"], chunk_size=2, crash_after=3)
            svc1.store.close()  # 模拟进程退出

            svc2, _ = make_service(path)  # 新实例启动即自动恢复
            try:
                row = svc2.store.conn.execute(
                    "SELECT status, manifest_hash FROM batches WHERE batch_id = ?",
                    (batch["batch_id"],)).fetchone()
                self.assertEqual(row["status"], "sealed")
                self.assertIsNotNone(row["manifest_hash"])
                journal = svc2.store.conn.execute(
                    "SELECT state, done_count, planned_count FROM seal_journal"
                    " WHERE batch_id = ?", (batch["batch_id"],)).fetchone()
                self.assertEqual(journal["state"], "committed")
                self.assertEqual(journal["done_count"], journal["planned_count"])
                total = svc2.store.conn.execute(
                    "SELECT COUNT(*) AS c FROM batch_members WHERE batch_id = ?",
                    (batch["batch_id"],)).fetchone()["c"]
                distinct = svc2.store.conn.execute(
                    "SELECT COUNT(DISTINCT letter_id) AS c FROM batch_members WHERE batch_id = ?",
                    (batch["batch_id"],)).fetchone()["c"]
                self.assertEqual((total, distinct), (5, 5))

                again = svc2.seal_batch(actor="op-1", role="batch_operator",
                                        batch_id=batch["batch_id"])
                self.assertTrue(again["deduplicated"])
                self.assertTrue(svc2.store.verify_audit_chain()["ok"])
            finally:
                svc2.store.close()


class DisplayProofTest(RelayTestCase):
    def test_display_requires_valid_consent_and_proves_it(self):
        """展示锚定当时有效的授权快照；证明可独立验证。"""
        letter = self.approved_letter()
        self.grant(letter["pseudonym"], "display")

        with self.assertRaises(Conflict):
            self.service.record_display(
                actor="ed-1", role="editor", idempotency_key="dp-expired",
                letter_id=letter["letter_id"], channel="官网",
                event_time="2026-12-01T09:00:00+00:00")  # 已超出 30 天有效期

        display = self.service.record_display(
            actor="ed-1", role="editor", idempotency_key="dp-ok",
            letter_id=letter["letter_id"], channel="官网",
            event_time="2026-09-10T09:00:00+00:00")
        proof = self.service.display_proof(actor="au-1", role="auditor",
                                           display_id=display["display_id"])
        self.assertTrue(proof["verified"])
        self.assertTrue(all(proof["checks"].values()))

        retry = self.service.record_display(
            actor="ed-1", role="editor", idempotency_key="dp-ok",
            letter_id=letter["letter_id"], channel="官网",
            event_time="2026-09-10T09:00:00+00:00")
        self.assertTrue(retry["deduplicated"])
        self.assertEqual(retry["display_id"], display["display_id"])

    def test_display_without_display_consent_rejected(self):
        letter = self.approved_letter()  # 只有 uplink 授权
        with self.assertRaises(Conflict):
            self.service.record_display(
                actor="ed-1", role="editor", idempotency_key="dp-none",
                letter_id=letter["letter_id"], channel="官网",
                event_time="2026-09-10T09:00:00+00:00")


class AuditTest(RelayTestCase):
    def test_audit_chain_detects_tampering(self):
        """审计链可校验；任何覆盖式修改都会暴露。"""
        letter = self.approved_letter()
        self.grant(letter["pseudonym"], "display")
        result = self.service.verify_audit(actor="au-1", role="auditor")
        self.assertTrue(result["ok"])
        self.assertGreater(result["length"], 0)

        conn = self.service.store.conn
        conn.execute("UPDATE audit_log SET detail = '{}' WHERE seq = 1")
        conn.commit()
        result = self.service.verify_audit(actor="au-1", role="auditor")
        self.assertFalse(result["ok"])
        self.assertEqual(result["first_bad_seq"], 1)


class PermissionTest(RelayTestCase):
    def test_role_enforcement(self):
        with self.assertRaises(Forbidden):
            self.service.import_letter(
                actor="x", role="reviewer", idempotency_key="k",
                child_name="n", school="s", guardian_ref="g", content="c",
                event_time=T0.isoformat(), source_org="o")
        with self.assertRaises(Forbidden):
            self.service.create_batch(actor="x", role="editor",
                                      idempotency_key="b", title="t")
        with self.assertRaises(NotFound):
            self.service.letter_locations(actor="g", role="guardian",
                                          letter_id="L_missing")


if __name__ == "__main__":
    unittest.main()
