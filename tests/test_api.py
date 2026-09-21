"""HTTP 层端到端冒烟测试：走完整条接力链路。"""
import json
import threading
import unittest
from datetime import datetime, timezone
from http.client import HTTPConnection
from http.server import ThreadingHTTPServer

from service.api import Api
from service.clock import ManualClock
from service.main import Handler
from service.relay import RelayService
from service.store import Store

T0 = datetime(2026, 9, 1, 8, 0, tzinfo=timezone.utc)


class ApiTest(unittest.TestCase):
    def setUp(self):
        service = RelayService(Store(":memory:"), ManualClock(T0), b"api-test-key")
        Handler.api = Api(service)
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        Handler.api = None

    def call(self, method, path, payload=None, actor="user-1", role=""):
        conn = HTTPConnection("127.0.0.1", self.server.server_port)
        body = json.dumps(payload) if payload is not None else None
        conn.request(method, path, body=body, headers={
            "Content-Type": "application/json",
            "X-Actor": actor,
            "X-Role": role,
        })
        response = conn.getresponse()
        return response.status, json.loads(response.read())

    def test_full_relay_flow(self):
        status, body = self.call("GET", "/health")
        self.assertEqual((status, body), (200, {"status": "ok"}))

        # 收件（重试一次验证幂等）
        payload = {"idempotency_key": "imp-1", "child_name": "小明", "school": "育才小学",
                   "guardian_ref": "g-1", "content": "给航天员的信",
                   "event_time": "2026-09-01T09:00:00+00:00", "source_org": "育才小学"}
        status, letter = self.call("POST", "/letters/import", payload,
                                   actor="teacher-1", role="intake_officer")
        self.assertEqual(status, 200)
        status, dup = self.call("POST", "/letters/import", payload,
                                actor="teacher-1", role="intake_officer")
        self.assertTrue(dup["deduplicated"])
        self.assertEqual(dup["letter_id"], letter["letter_id"])

        # 授权
        for scope in ("uplink", "display"):
            status, _ = self.call("POST", "/consents/grant", {
                "idempotency_key": f"c-{scope}", "pseudonym": letter["pseudonym"],
                "scope": scope, "valid_from": "2026-09-01T00:00:00+00:00",
                "valid_until": "2026-10-01T00:00:00+00:00",
                "event_time": "2026-09-01T09:05:00+00:00"},
                actor="guardian-1", role="guardian")
            self.assertEqual(status, 200)

        # 双人复核
        for reviewer in ("reviewer-1", "reviewer-2"):
            status, review = self.call("POST", "/reviews", {
                "idempotency_key": f"rv-{reviewer}", "letter_id": letter["letter_id"],
                "decision": "approve", "event_time": "2026-09-01T10:00:00+00:00"},
                actor=reviewer, role="reviewer")
            self.assertEqual(status, 200)
        self.assertEqual(review["letter_status"], "approved")

        # 建批、候选、封存
        status, batch = self.call("POST", "/batches", {
            "idempotency_key": "b-1", "title": "九月批次"},
            actor="op-1", role="batch_operator")
        self.assertEqual(status, 200)
        status, _ = self.call("POST", "/batches/stage", {
            "idempotency_key": "st-1", "batch_id": batch["batch_id"],
            "letter_id": letter["letter_id"]}, actor="op-1", role="batch_operator")
        self.assertEqual(status, 200)
        status, sealed = self.call("POST", "/batches/seal",
                                   {"batch_id": batch["batch_id"]},
                                   actor="op-1", role="batch_operator")
        self.assertEqual(status, 200)
        self.assertEqual(sealed["member_count"], 1)

        # 回执与对账
        status, _ = self.call("POST", "/receipts", {
            "idempotency_key": "rc-1", "batch_id": batch["batch_id"],
            "letter_id": letter["letter_id"], "status": "delivered",
            "event_time": "2026-09-05T00:00:00+00:00"},
            actor="op-1", role="batch_operator")
        self.assertEqual(status, 200)
        status, report = self.call("GET", f"/batches/reconcile?batch_id={batch['batch_id']}",
                                   actor="au-1", role="auditor")
        self.assertTrue(report["balanced"])

        # 展示与证明
        status, display = self.call("POST", "/displays", {
            "idempotency_key": "dp-1", "letter_id": letter["letter_id"],
            "channel": "官网", "event_time": "2026-09-10T09:00:00+00:00"},
            actor="ed-1", role="editor")
        self.assertEqual(status, 200)
        status, proof = self.call(
            "GET", f"/displays/proof?display_id={display['display_id']}",
            actor="au-1", role="auditor")
        self.assertTrue(proof["verified"])

        # 位置查询与审计校验
        status, locations = self.call(
            "GET", f"/letters/locations?letter_id={letter['letter_id']}",
            actor="guardian-1", role="guardian")
        self.assertEqual(status, 200)
        self.assertEqual(len(locations["sealed_batches"]), 1)
        status, audit = self.call("GET", "/audit/verify", actor="au-1", role="auditor")
        self.assertTrue(audit["ok"])

    def test_errors(self):
        status, body = self.call("POST", "/letters/import", {
            "idempotency_key": "x", "child_name": "n", "school": "s",
            "guardian_ref": "g", "content": "c",
            "event_time": "2026-09-01T09:00:00+00:00", "source_org": "o"},
            actor="x", role="reviewer")
        self.assertEqual(status, 403)
        self.assertEqual(body["error"]["code"], "forbidden")

        status, _ = self.call("POST", "/no/such/route", {})
        self.assertEqual(status, 404)

        status, body = self.call("POST", "/reviews", {
            "idempotency_key": "rv", "letter_id": "L_none", "decision": "approve",
            "event_time": "2026-09-01T10:00:00+00:00"}, actor="r", role="reviewer")
        self.assertEqual(status, 404)


if __name__ == "__main__":
    unittest.main()
