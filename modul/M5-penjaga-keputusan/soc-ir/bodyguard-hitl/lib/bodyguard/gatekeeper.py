# -*- coding: utf-8 -*-
"""Telegram Approval Gatekeeper (logika inti; dijalankan oleh bin/gatekeeper_bot.py).

Alur T2:
  1. Engine memasukkan usulan ke tabel approvals berstatus QUEUED (tanpa nonce/tanda tangan).
  2. Gatekeeper (satu-satunya pemegang token bot approval & kunci HMAC) menerbitkan nonce + ts,
     menandatangani tombol [Setujui]/[Tolak], mengirim pesan -> PENDING.
  3. Tekan tombol: cek allowlist user_id -> chat -> format -> nonce dikenal -> message_id cocok ->
     HMAC (waktu konstan) -> TTL 30 menit (kedaluwarsa = TOLAK) -> konsumsi nonce atomik (anti-replay).
  4. Disetujui: verifikasi ULANG dari payload tersimpan + digest aksi -> cek freeze & mode ->
     APPROVED -> EXECUTING (atomik, anti eksekusi ganda) -> eksekutor T2 -> EXECUTED/FAILED.
/freeze: kill-switch seketika (T1 + eksekusi T2). Unfreeze SENGAJA hanya dari konsol server:
membuat sistem lebih aman boleh dari jauh, membuatnya lebih agresif harus dari server.
"""

import html
import json
import logging
import time

from .breaker import KINDS, CircuitBreaker, freeze, is_frozen
from .sanitizer import clean, tg, tg_code, tg_pre
from .signing import new_nonce, parse_callback
from .t2 import ACTION_LABELS
from .telegram import TelegramError
from .util import canonical_json, fmt_local, log_event, sha256_hex

OFFSET_KEY = "gatekeeper:offset"
STALE_COMMAND_SECONDS = 300
QUEUED_MAX_AGE = 6 * 3600  # antrean yang tak sempat dikirim (mis. Telegram mati) kedaluwarsa = TOLAK
UNFREEZE_HINT = "sudo -u guard /opt/bodyguard/bin/bodyguard unfreeze --reason \"...\""


def render_request(cfg, request_id, action, expires_ts, simulated=False):
    d = action.get("display") or {}
    label = ACTION_LABELS.get(action.get("kind"), action.get("kind"))
    lines = [
        "\U0001f6e1\ufe0f <b>PERSETUJUAN T2</b>%s  \u2022  %s" % (" [SIMULASI]" if simulated else "", tg_code(action.get("incident"), 40)),
        "Permintaan: %s" % tg_code(request_id, 40),
        "Aksi: <b>%s</b>" % html.escape(str(label)),
        "Target: %s" % tg_code(d.get("target", "-"), 300),
    ]
    if d.get("site"):
        lines.append("Situs: %s" % tg_code(d["site"], 60))
    lines += ["", "<b>Bukti</b>"]
    if d.get("sha256"):
        lines.append("\u2022 SHA256: %s" % tg_code(d["sha256"], 64))
    if d.get("rules"):
        lines.append("\u2022 Aturan: %s" % tg_code(", ".join(str(r) for r in d["rules"][:8]), 200))
    for item in (d.get("evidence") or [])[:5]:
        lines.append("\u2022 %s" % tg(item, 300))
    if d.get("snippet"):
        lines.append("\u2022 Cuplikan (tersanitasi):")
        lines.append(tg_pre(d["snippet"], 400))
    lines += [
        "",
        "<b>Dampak:</b> %s" % tg(d.get("impact", "-"), 400),
        "<b>Rollback:</b> %s" % tg_code(d.get("rollback", "-"), 400),
        "",
        "\u23f3 Berlaku sampai %s (%d menit). Tanpa respons = <b>DITOLAK</b>." % (
            html.escape(fmt_local(expires_ts, cfg.tz_offset, cfg.tz_label)), cfg.t2_ttl // 60),
    ]
    return "\n".join(lines)


class Gatekeeper(object):
    def __init__(self, cfg, store, api, signer, approvers, chat_id, executor, clock=time.time):
        self.cfg = cfg
        self.store = store
        self.api = api
        self.signer = signer
        self.approvers = frozenset(approvers)
        self.chat_id = int(chat_id)
        self.executor = executor
        self.clock = clock
        self.ttl = cfg.t2_ttl

    # ---------------------------------------------------------------------------------------------
    def recover_after_restart(self):
        """Baris SENDING (crash di tengah kirim) tidak pernah dianggap sah: tandai kedaluwarsa."""
        now = self.clock()
        with self.store.tx() as c:
            c.execute("UPDATE approvals SET status='EXPIRED', updated_at=? WHERE status='SENDING'", (now,))
            c.execute("UPDATE approvals SET status='FAILED', updated_at=?, result_json=? WHERE status='EXECUTING'",
                      (now, json.dumps({"ok": False, "summary": "proses berhenti saat eksekusi - periksa manual"})))

    def poll_once(self):
        self.dispatch_queued()
        self.expire_due()
        offset = int(self.store.get(OFFSET_KEY) or 0)
        try:
            updates = self.api.get_updates(offset, timeout=self.cfg.poll_timeout)
        except TelegramError as e:
            log_event(logging.WARNING, "getUpdates gagal", err=str(e))
            return -1
        for u in updates:
            uid = u.get("update_id") if isinstance(u, dict) else None
            if not isinstance(uid, int) or isinstance(uid, bool):
                continue
            try:
                self.handle_update(u)
            except Exception as e:  # satu update rusak tidak boleh menghentikan gatekeeper
                log_event(logging.ERROR, "gagal memproses update", err=e.__class__.__name__)
            self.store.set(OFFSET_KEY, uid + 1)
        return len(updates)

    # ---- pengiriman permintaan -------------------------------------------------------------------
    def dispatch_queued(self):
        now = self.clock()
        with self.store.tx() as c:
            c.execute("UPDATE approvals SET status='EXPIRED', updated_at=? WHERE status='QUEUED' AND created_at < ?",
                      (now, now - QUEUED_MAX_AGE))
        pending = len(self.store.approvals_with_status(("PENDING", "SENDING"), limit=1000))
        room = max(0, self.cfg.max_pending - pending)
        for row in self.store.approvals_with_status(("QUEUED",), limit=min(room, 10)) if room else []:
            self._send_request(row)

    def _send_request(self, row):
        rid = row["request_id"]
        try:
            action = json.loads(row["action_json"])
        except ValueError:
            action = None
        if not isinstance(action, dict) or sha256_hex(canonical_json(action).encode("ascii")) != row["action_sha256"]:
            self._set_status(rid, "QUEUED", "FAILED", {"ok": False, "summary": "aksi rusak/tidak cocok digest"})
            return
        now = int(self.clock())
        nonce = new_nonce()
        expires = now + self.ttl
        with self.store.tx() as c:
            cur = c.execute("UPDATE approvals SET status='SENDING', nonce=?, issued_ts=?, expires_ts=?, chat_id=?, "
                            "updated_at=? WHERE request_id=? AND status='QUEUED'",
                            (nonce, now, expires, self.chat_id, now, rid))
            if cur.rowcount != 1:
                return
        markup = {"inline_keyboard": [[
            {"text": "\u2705 Setujui", "callback_data": self.signer.make_callback("A", nonce, now, rid, row["action_sha256"], self.chat_id)},
            {"text": "\u274c Tolak", "callback_data": self.signer.make_callback("R", nonce, now, rid, row["action_sha256"], self.chat_id)},
        ]]}
        try:
            msg = self.api.send_message(self.chat_id, render_request(self.cfg, rid, action, expires), reply_markup=markup)
            mid = int(msg["message_id"])
        except Exception as e:
            with self.store.tx() as c:
                c.execute("UPDATE approvals SET status='QUEUED', nonce=NULL, issued_ts=NULL, expires_ts=NULL, "
                          "updated_at=? WHERE request_id=? AND status='SENDING'", (now, rid))
            log_event(logging.WARNING, "gagal mengirim permintaan T2; akan dicoba lagi", request=rid, err=str(e)[:200])
            return
        with self.store.tx() as c:
            c.execute("UPDATE approvals SET status='PENDING', message_id=?, updated_at=? WHERE request_id=? "
                      "AND status='SENDING'", (mid, now, rid))
            self.store.audit("gatekeeper", "T2_SENT", {"request": rid, "kind": action.get("kind")}, conn=c)

    def expire_due(self):
        now = self.clock()
        rows = self.store.conn.execute("SELECT * FROM approvals WHERE status='PENDING' AND expires_ts <= ?",
                                       (now,)).fetchall()
        for row in rows:
            if self._set_status(row["request_id"], "PENDING", "EXPIRED", None, decided_at=now):
                self._edit(row, "\u231b <b>KEDALUWARSA</b> - tidak ada respons dalam %d menit, dianggap <b>DITOLAK</b>."
                           % (self.ttl // 60))

    # ---- update masuk ---------------------------------------------------------------------------
    def handle_update(self, u):
        if isinstance(u.get("callback_query"), dict):
            self.on_callback(u["callback_query"])
        elif isinstance(u.get("message"), dict):
            self.on_message(u["message"])

    def _authorized(self, frm):
        uid = frm.get("id") if isinstance(frm, dict) else None
        return isinstance(uid, int) and not isinstance(uid, bool) and uid in self.approvers

    def on_message(self, m):
        frm = m.get("from") or {}
        chat = m.get("chat") or {}
        text = m.get("text")
        if not isinstance(text, str):
            return
        if not self._authorized(frm):
            log_event(logging.WARNING, "pesan dari user tidak berwenang diabaikan",
                      user=clean(frm.get("id"), 20), username=clean(frm.get("username"), 40))
            return
        uid = frm["id"]
        chat_id = chat.get("id")
        if not (chat_id == self.chat_id or (chat.get("type") == "private" and chat_id == uid)):
            return
        cmd, _, arg = text.strip().partition(" ")
        cmd = cmd.split("@", 1)[0].lower()
        if cmd == "/freeze":
            fresh = freeze(self.store, "tg:%d" % uid, "Telegram: " + clean(arg, 200))
            self._reply(chat_id, "\U0001f9ca <b>FREEZE AKTIF</b>%s\nSemua aksi T1 dan eksekusi T2 dibekukan. "
                        "T0 (amati & alert) tetap berjalan.\nUnfreeze HANYA dari konsol server:\n%s"
                        % ("" if fresh else " (sudah aktif sebelumnya)", tg_code(UNFREEZE_HINT, 200)))
            return
        if self.clock() - float(m.get("date") or 0) > STALE_COMMAND_SECONDS:
            return  # perintah lama (antrean saat bot mati) diabaikan, kecuali /freeze
        if cmd == "/status":
            self._reply(chat_id, self._status_text())
        elif cmd == "/unfreeze":
            self._reply(chat_id, "Unfreeze sengaja tidak tersedia dari Telegram. Jalankan di konsol server:\n%s"
                        % tg_code(UNFREEZE_HINT, 200))
        elif cmd in ("/help", "/start"):
            self._reply(chat_id, "Perintah: /status, /freeze [alasan]. Persetujuan T2 lewat tombol pada pesan permintaan.")

    def on_callback(self, cq):
        cq_id = cq.get("id")
        frm = cq.get("from") or {}
        msg = cq.get("message") or {}
        data = cq.get("data")
        if not self._authorized(frm):
            log_event(logging.WARNING, "tombol ditekan user tidak berwenang", user=clean(frm.get("id"), 20))
            self._answer(cq_id, "Tidak berwenang.")
            return
        uid = frm["id"]
        if (msg.get("chat") or {}).get("id") != self.chat_id:
            self._answer(cq_id, "Chat tidak sah.")
            return
        parsed = parse_callback(data)
        if parsed is None:
            self._answer(cq_id, "Format tombol tidak valid.")
            return
        row = self.store.approval_by_nonce(parsed.nonce)
        if row is None:
            self._answer(cq_id, "Permintaan tidak dikenal.")
            return
        if row["message_id"] is None or msg.get("message_id") != row["message_id"]:
            self._answer(cq_id, "Pesan tidak cocok dengan permintaan.")
            return
        now = self.clock()
        vr = self.signer.verify(parsed, row["request_id"], row["action_sha256"], self.chat_id, row["issued_ts"], now,
                                ttl=self.ttl)
        if not vr.ok:
            self.store.audit("tg:%d" % uid, "T2_CALLBACK_REJECTED", {"request": row["request_id"], "status": vr.status})
            if vr.status == "EXPIRED":
                if self._set_status(row["request_id"], "PENDING", "EXPIRED", None, decided_at=now):
                    self._edit(row, "\u231b <b>KEDALUWARSA</b> - dianggap <b>DITOLAK</b>.")
                self._answer(cq_id, "Kedaluwarsa - dianggap DITOLAK.")
            else:
                self._answer(cq_id, "Tanda tangan tidak valid - diabaikan.")
            return
        status = "APPROVED" if parsed.decision == "A" else "REJECTED"
        with self.store.tx() as c:
            cur = c.execute("UPDATE approvals SET status=?, decided_by=?, decided_at=?, decision_payload=?, updated_at=? "
                            "WHERE request_id=? AND nonce=? AND status='PENDING'",
                            (status, uid, now, data, now, row["request_id"], parsed.nonce))
            consumed = cur.rowcount == 1
            if consumed:
                self.store.audit("tg:%d" % uid, "T2_" + status, {"request": row["request_id"]}, conn=c)
        if not consumed:
            self._answer(cq_id, "Sudah diproses sebelumnya.")
            return
        when = html.escape(fmt_local(now, self.cfg.tz_offset, self.cfg.tz_label))
        if status == "REJECTED":
            self._answer(cq_id, "Ditolak.")
            self._edit(row, "\u274c <b>DITOLAK</b> oleh %s pada %s." % (tg_code(uid, 20), when))
            return
        self._answer(cq_id, "Disetujui - memproses...")
        res = self.execute_approved(row["request_id"])
        icon = "\u2705" if res.get("ok") else "\u26a0\ufe0f"
        tail = "%s <b>DISETUJUI</b> oleh %s pada %s.\nHasil: %s" % (icon, tg_code(uid, 20), when, tg(res.get("summary", "-"), 400))
        if res.get("rollback"):
            tail += "\nRollback: %s" % tg_code(res["rollback"], 400)
        self._edit(row, tail)

    # ---- eksekusi ---------------------------------------------------------------------------------
    def execute_approved(self, request_id):
        row = self.store.approval(request_id)
        if row is None or row["status"] != "APPROVED":
            return {"ok": False, "summary": "status bukan APPROVED"}
        parsed = parse_callback(row["decision_payload"] or "")
        vr = self.signer.verify(parsed, row["request_id"], row["action_sha256"], row["chat_id"] if row["chat_id"] is not None else self.chat_id,
                                row["issued_ts"], float(row["decided_at"]), ttl=self.ttl)
        if not vr.ok or parsed.decision != "A":
            return self._finish(request_id, "FAILED", {"ok": False, "summary": "verifikasi ulang tanda tangan gagal"})
        try:
            action = json.loads(row["action_json"])
        except ValueError:
            action = None
        if not isinstance(action, dict) or sha256_hex(canonical_json(action).encode("ascii")) != row["action_sha256"]:
            return self._finish(request_id, "FAILED", {"ok": False, "summary": "isi aksi di DB berubah setelah disetujui - dibatalkan"})
        if is_frozen(self.store):
            return self._finish(request_id, "BLOCKED_FROZEN", {"ok": False, "summary": "sistem dalam FREEZE - tidak dieksekusi"})
        if self.cfg.mode != "enforce" and action.get("kind") != "NOOP_TEST":
            return self._finish(request_id, "SKIPPED_MODE", {"ok": False, "summary": "mode %s - aksi T2 tidak dieksekusi" % self.cfg.mode})
        if not self._set_status(request_id, "APPROVED", "EXECUTING", None):
            return {"ok": False, "summary": "sedang/sudah dieksekusi"}
        try:
            res = self.executor.execute(request_id, action)
        except Exception as e:
            res = {"ok": False, "summary": "galat eksekutor: %s" % e.__class__.__name__}
        return self._finish(request_id, "EXECUTED" if res.get("ok") else "FAILED", res, expect="EXECUTING")

    def _finish(self, request_id, status, res, expect="APPROVED"):
        self._set_status(request_id, expect, status, res)
        self.store.audit("gatekeeper", "T2_" + status, {"request": request_id, "summary": res.get("summary")})
        return res

    # ---- helper ---------------------------------------------------------------------------------
    def _set_status(self, request_id, expect, new, result, decided_at=None):
        now = self.clock()
        with self.store.tx() as c:
            if decided_at is not None:
                cur = c.execute("UPDATE approvals SET status=?, result_json=COALESCE(?, result_json), decided_at=?, "
                                "updated_at=? WHERE request_id=? AND status=?",
                                (new, json.dumps(result) if result is not None else None, decided_at, now, request_id, expect))
            else:
                cur = c.execute("UPDATE approvals SET status=?, result_json=COALESCE(?, result_json), updated_at=? "
                                "WHERE request_id=? AND status=?",
                                (new, json.dumps(result) if result is not None else None, now, request_id, expect))
            return cur.rowcount == 1

    def _status_text(self):
        live = CircuitBreaker(self.store, self.cfg.limits, "live", clock=self.clock).status()
        pending = len(self.store.approvals_with_status(("PENDING", "QUEUED"), limit=100))
        counts = live.get("counts_last_hour") or {}
        lines = [
            "\U0001f6e1\ufe0f <b>Status Bodyguard</b>",
            "Mode config: <b>%s</b>" % html.escape(self.cfg.mode),
            "Freeze: <b>%s</b>" % ("YA" if live.get("frozen") else "tidak"),
            "Breaker T1: <b>%s</b>" % ("TRIP (T0 saja)" if live.get("tripped") else "normal"),
            "Aksi T1 60 menit terakhir: " + ", ".join("%s %s/%s" % (k, counts.get(k, 0), self.cfg.limits[k]) for k in KINDS),
            "Permintaan T2 menunggu: %d" % pending,
        ]
        return "\n".join(lines)

    def _reply(self, chat_id, text):
        try:
            self.api.send_message(chat_id, text)
        except Exception as e:
            log_event(logging.WARNING, "gagal membalas", err=str(e)[:200])

    def _answer(self, cq_id, text):
        if not cq_id:
            return
        try:
            self.api.answer_callback(cq_id, text)
        except Exception:
            pass

    def _edit(self, row, tail):
        try:
            action = json.loads(row["action_json"])
            body = render_request(self.cfg, row["request_id"], action, row["expires_ts"] or 0)
            body = body.rsplit("\n\u23f3", 1)[0]
        except Exception:
            body = "Permintaan %s" % tg_code(row["request_id"], 40)
        try:
            self.api.edit_message_text(self.chat_id, row["message_id"], body + "\n\n" + tail,
                                       reply_markup={"inline_keyboard": []})
        except Exception as e:
            log_event(logging.WARNING, "gagal mengedit pesan", err=str(e)[:200])
