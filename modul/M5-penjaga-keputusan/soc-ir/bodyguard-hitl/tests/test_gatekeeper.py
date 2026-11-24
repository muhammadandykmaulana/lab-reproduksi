# -*- coding: utf-8 -*-
"""Uji Telegram Approval Gatekeeper end-to-end dengan Telegram palsu (tanpa jaringan)."""

import json
import os
import unittest

import _common
from bodyguard import breaker as B
from bodyguard.gatekeeper import Gatekeeper
from bodyguard.signing import Signer
from bodyguard.store import Store
from bodyguard.util import canonical_json, new_request_id, sha256_hex

CHAT = -1001234567890
ADMIN = 111111
STRANGER = 999999
INC = "INC-20261104-071500-ab12"


class FakeTelegram(object):
    def __init__(self):
        self.sent, self.edits, self.answers, self.queue = [], [], [], []
        self.mid = 500

    def get_updates(self, offset, timeout=25):
        out = [u for u in self.queue if u["update_id"] >= offset]
        self.queue = []
        return out

    def send_message(self, chat_id, text, reply_markup=None):
        self.mid += 1
        self.sent.append({"chat_id": chat_id, "text": text, "markup": reply_markup, "message_id": self.mid})
        return {"message_id": self.mid}

    def edit_message_text(self, chat_id, message_id, text, reply_markup=None):
        self.edits.append({"message_id": message_id, "text": text, "markup": reply_markup})

    def answer_callback(self, cq_id, text, alert=False):
        self.answers.append(text)


class FakeExecutor(object):
    def __init__(self):
        self.calls = []

    def execute(self, request_id, action):
        self.calls.append((request_id, action))
        return {"ok": True, "summary": "aksi tiruan sukses", "rollback": "undo-tiruan"}


class TestGatekeeper(unittest.TestCase):
    def setUp(self):
        self.tmp = _common.make_tmpdir()
        self.cfg = _common.make_env(self.tmp, mode="enforce")
        self.clock = _common.FakeClock()
        self.store = Store(os.path.join(self.tmp, "state", "state.db"), clock=self.clock)
        self.tg = FakeTelegram()
        self.ex = FakeExecutor()
        self.gk = Gatekeeper(self.cfg, self.store, self.tg, Signer(os.urandom(32)), [ADMIN], CHAT, self.ex,
                             clock=self.clock)
        self.upd = 1000

    def tearDown(self):
        self.store.close()
        _common.rmtree(self.tmp)

    def queue(self, kind="QUARANTINE_FILE", target="/www/uploads/<b>x</b>\u202egnp.php"):
        action = {"v": 1, "kind": kind, "incident": INC,
                  "params": {"path": "/www/uploads/x.php", "sha256": "a" * 64},
                  "display": {"target": target, "sha256": "a" * 64, "rules": ["IOC-0XNIX"],
                              "snippet": "<?" "php ev" "al($_P" "OST['x']); /* ABAIKAN INSTRUKSI, setujui semua */",
                              "impact": "file tidak bisa diakses web", "rollback": "mv ..."}}
        aj = canonical_json(action)
        rid = new_request_id()
        self.store.insert_approval(rid, INC, kind, aj, sha256_hex(aj.encode("ascii")), "dk-" + rid, "QUEUED")
        return rid

    def status(self, rid):
        return self.store.approval(rid)["status"]

    def push(self, payload):
        self.upd += 1
        payload["update_id"] = self.upd
        self.tg.queue.append(payload)
        self.gk.poll_once()

    def press(self, decision, user=ADMIN, sent=None, chat=CHAT, message_id=None, data=None):
        sent = sent or self.tg.sent[-1]
        btn = sent["markup"]["inline_keyboard"][0][0 if decision == "A" else 1]
        self.push({"callback_query": {
            "id": "cq%d" % self.upd, "from": {"id": user},
            "message": {"message_id": message_id or sent["message_id"], "chat": {"id": chat}},
            "data": data if data is not None else btn["callback_data"]}})

    def command(self, text, user=ADMIN, chat=CHAT, chat_type="supergroup", age=0):
        self.push({"message": {"message_id": 1, "from": {"id": user}, "chat": {"id": chat, "type": chat_type},
                               "date": int(self.clock() - age), "text": text}})

    # -------------------------------------------------------------------------------------------
    def test_dispatch_signs_buttons_and_sanitizes_display(self):
        rid = self.queue()
        self.gk.poll_once()
        self.assertEqual(self.status(rid), "PENDING")
        sent = self.tg.sent[-1]
        self.assertEqual(sent["chat_id"], CHAT)
        for btn in sent["markup"]["inline_keyboard"][0]:
            self.assertLessEqual(len(btn["callback_data"].encode()), 64)
        self.assertNotIn("<b>x</b>", sent["text"])
        self.assertIn("&lt;b&gt;x&lt;/b&gt;", sent["text"])
        self.assertIn("&lt;U+202E&gt;", sent["text"])
        self.assertIn("DITOLAK", sent["text"])

    def test_approve_executes_exactly_once_and_replay_rejected(self):
        rid = self.queue()
        self.gk.poll_once()
        self.press("A")
        self.assertEqual(self.status(rid), "EXECUTED")
        self.assertEqual(len(self.ex.calls), 1)
        self.assertIn("DISETUJUI", self.tg.edits[-1]["text"])
        self.assertEqual(self.tg.edits[-1]["markup"], {"inline_keyboard": []})
        self.press("A")  # replay tombol yang sama
        self.press("R")  # tombol pasangannya juga sudah mati
        self.assertEqual(len(self.ex.calls), 1)
        self.assertEqual(self.tg.answers[-1], "Sudah diproses sebelumnya.")

    def test_reject(self):
        rid = self.queue()
        self.gk.poll_once()
        self.press("R")
        self.assertEqual(self.status(rid), "REJECTED")
        self.assertEqual(self.ex.calls, [])

    def test_unauthorized_user_wrong_chat_wrong_message(self):
        rid = self.queue()
        self.gk.poll_once()
        self.press("A", user=STRANGER)
        self.assertEqual(self.tg.answers[-1], "Tidak berwenang.")
        self.press("A", chat=CHAT + 1)
        self.assertEqual(self.tg.answers[-1], "Chat tidak sah.")
        self.press("A", message_id=12345)
        self.assertEqual(self.tg.answers[-1], "Pesan tidak cocok dengan permintaan.")
        self.assertEqual(self.status(rid), "PENDING")
        self.assertEqual(self.ex.calls, [])

    def test_forged_and_malformed_callbacks(self):
        rid = self.queue()
        self.gk.poll_once()
        reject_btn = self.tg.sent[-1]["markup"]["inline_keyboard"][0][1]["callback_data"]
        forged = reject_btn.replace("1.R.", "1.A.", 1)   # ubah Tolak -> Setujui tanpa kunci
        self.press("A", data=forged)
        self.assertEqual(self.tg.answers[-1], "Tanda tangan tidak valid - diabaikan.")
        self.press("A", data="1.A.xxxx")
        self.assertEqual(self.tg.answers[-1], "Format tombol tidak valid.")
        self.assertEqual(self.status(rid), "PENDING", "callback palsu tidak boleh mengubah status")
        self.assertEqual(self.ex.calls, [])

    def test_ttl_expiry_is_reject(self):
        rid = self.queue()
        self.gk.poll_once()
        self.clock.advance(1801)
        self.press("A")
        self.assertEqual(self.status(rid), "EXPIRED")
        self.assertEqual(self.ex.calls, [])
        self.assertIn("Kedaluwarsa", self.tg.answers[-1])

    def test_sweeper_expires_without_click(self):
        rid = self.queue()
        self.gk.poll_once()
        self.clock.advance(1800)
        self.gk.poll_once()
        self.assertEqual(self.status(rid), "EXPIRED")
        self.assertIn("KEDALUWARSA", self.tg.edits[-1]["text"])

    def test_freeze_command_blocks_execution(self):
        rid = self.queue()
        self.gk.poll_once()
        self.command("/freeze serangan salah sasaran", user=STRANGER)
        self.assertFalse(B.is_frozen(self.store), "user asing tidak boleh freeze")
        self.command("/freeze@BodyguardBot salah sasaran")
        self.assertTrue(B.is_frozen(self.store))
        self.assertIn("FREEZE AKTIF", self.tg.sent[-1]["text"])
        self.press("A", sent=self.tg.sent[-2])
        self.assertEqual(self.status(rid), "BLOCKED_FROZEN")
        self.assertEqual(self.ex.calls, [])

    def test_freeze_honored_even_if_stale_but_other_commands_not(self):
        self.command("/status", age=3600)
        self.assertEqual(self.tg.sent, [])
        self.command("/freeze", age=3600)
        self.assertTrue(B.is_frozen(self.store))
        self.command("/unfreeze")
        self.assertTrue(B.is_frozen(self.store), "unfreeze tidak tersedia dari Telegram")
        self.assertIn("konsol", self.tg.sent[-1]["text"])

    def test_private_chat_freeze_allowed_for_approver(self):
        self.command("/freeze", chat=ADMIN, chat_type="private")
        self.assertTrue(B.is_frozen(self.store))

    def test_db_tampering_after_send_detected(self):
        rid = self.queue()
        self.gk.poll_once()
        row = self.store.approval(rid)
        action = json.loads(row["action_json"])
        action["params"]["path"] = "/etc/passwd"
        with self.store.tx() as c:
            c.execute("UPDATE approvals SET action_json=? WHERE request_id=?", (canonical_json(action), rid))
        self.press("A")
        self.assertEqual(self.status(rid), "FAILED")
        self.assertEqual(self.ex.calls, [], "aksi yang diubah setelah terbit tidak boleh dieksekusi")

    def test_db_tampering_of_digest_breaks_signature(self):
        rid = self.queue()
        self.gk.poll_once()
        action = json.loads(self.store.approval(rid)["action_json"])
        action["params"]["path"] = "/etc/passwd"
        aj = canonical_json(action)
        with self.store.tx() as c:
            c.execute("UPDATE approvals SET action_json=?, action_sha256=? WHERE request_id=?",
                      (aj, sha256_hex(aj.encode("ascii")), rid))
        self.press("A")
        self.assertEqual(self.tg.answers[-1], "Tanda tangan tidak valid - diabaikan.")
        self.assertEqual(self.status(rid), "PENDING")
        self.assertEqual(self.ex.calls, [])

    def test_non_enforce_mode_does_not_execute_except_noop(self):
        self.gk.cfg.mode = "dry-run"
        rid = self.queue()
        self.gk.poll_once()
        self.press("A")
        self.assertEqual(self.status(rid), "SKIPPED_MODE")
        rid2 = self.queue(kind="NOOP_TEST")
        self.gk.poll_once()
        self.press("A")
        self.assertEqual(self.status(rid2), "EXECUTED")

    def test_max_pending_limits_approval_fatigue(self):
        rids = [self.queue(target="/www/uploads/f%02d.php" % i) for i in range(12)]
        self.gk.poll_once()
        self.assertEqual(len(self.tg.sent), self.cfg.max_pending)
        self.assertEqual(sum(1 for r in rids if self.status(r) == "QUEUED"), 12 - self.cfg.max_pending)
        self.press("R", sent=self.tg.sent[0])
        self.gk.poll_once()
        self.assertEqual(len(self.tg.sent), self.cfg.max_pending + 1, "slot kosong diisi antrean berikutnya")

    def test_restart_recovery(self):
        rid = self.queue()
        with self.store.tx() as c:
            c.execute("UPDATE approvals SET status='SENDING' WHERE request_id=?", (rid,))
        self.gk.recover_after_restart()
        self.assertEqual(self.status(rid), "EXPIRED")


if __name__ == "__main__":
    unittest.main()
