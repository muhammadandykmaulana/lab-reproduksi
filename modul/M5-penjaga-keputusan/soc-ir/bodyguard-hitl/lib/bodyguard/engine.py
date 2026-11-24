# -*- coding: utf-8 -*-
"""Siklus Bodyguard: T0 deteksi -> policy -> T1 (breaker) -> antre T2 -> checklist T3 -> alert.

Setiap detektor dibungkus try/except: satu detektor gagal tidak menghentikan yang lain, dan galatnya
sendiri menjadi temuan T0 (fail-safe ke alert/log).
"""

import json
import logging
import os
import time

from .checklist import write_checklist
from .detectors.accesslog import AccessLogScanner
from .detectors.accounts import AccountAuditor
from .detectors.integrity import IntegrityAdapter
from .detectors.ioc import IOCScanner
from .model import SEV_RANK, Finding
from .policy import decide
from .sanitizer import clean, tg, tg_code
from .t1 import T1Executor
from .t2 import ACTION_LABELS
from .util import canonical_json, fmt_local, log_event, new_incident_id, new_request_id, run_argv, sha256_hex, tkey
from .whitelist import Whitelist

DETECTORS = ("ioc", "accesslog", "accounts", "integrity")
IMPACT = {
    "QUARANTINE_FILE": "File di-rename di tempat (tanpa .php) & dikunci root:root 000; salinan bukti tersimpan. "
                       "Bila ternyata file sah, fitur terkait error sampai dipulihkan.",
    "DISABLE_PLUGIN": "Folder plugin di-rename sehingga WordPress berhenti memuatnya. Isi tidak dihapus.",
    "DISABLE_WP_USER": "Role akun dicabut (tidak bisa apa pun di wp-admin) dan semua sesinya diputus. Akun & data tidak dihapus.",
    "DISABLE_OJS_USER": "Akun OJS ditandai disabled sehingga tidak bisa login. Data tidak dihapus.",
    "ACCEPT_INTEGRITY_BASELINE": "Semua perubahan file saat ini dianggap sah oleh web-integrity-cek.sh. "
                                 "JANGAN setujui bila ada perubahan yang tidak Anda kenali.",
    "CF_APPROVE": "cf-guard menambah/melepas entri pada daftar IP atau aturan dinamis Cloudflare. Dapat dibatalkan.",
    "NOOP_TEST": "Tidak ada. Hanya menguji alur tombol, tanda tangan, dan eksekutor.",
}
ROLLBACK_HINT = {
    "QUARANTINE_FILE": "rename balik + chown/chmod asli (perintah persis dicetak setelah eksekusi)",
    "DISABLE_PLUGIN": "mv <plugin>.bg-disabled-<INC> <plugin>",
    "DISABLE_WP_USER": "UPDATE wp_usermeta ... UNHEX(nilai lama) (dicetak setelah eksekusi)",
    "DISABLE_OJS_USER": "UPDATE users SET disabled=<lama> ... (dicetak setelah eksekusi)",
    "ACCEPT_INTEGRITY_BASELINE": "pulihkan file baseline lama dari backup web-integrity-cek.sh",
    "CF_APPROVE": "cf-guard.py remove <nilai> (dicetak setelah eksekusi)",
    "NOOP_TEST": "-",
}
SEV_ICON = {"critical": "\U0001f534", "high": "\U0001f7e0", "medium": "\U0001f7e1", "low": "\u26aa", "info": "\u26aa"}


def effective_mode(cfg_mode, cli_dry_run=False):
    """CLI hanya boleh membuat lebih aman: --dry-run menurunkan enforce; tidak bisa menaikkan observe."""
    if cfg_mode == "observe":
        return "observe"
    return "dry-run" if cli_dry_run else cfg_mode


def build_action(incident_id, p):
    f = p.finding
    display = {"target": clean(p.target, 300), "impact": IMPACT.get(p.action, "-"),
               "rollback": ROLLBACK_HINT.get(p.action, "-")}
    if f is not None:
        display.update({"site": f.site, "sha256": f.detail.get("sha256") or p.params.get("sha256"),
                        "rules": list(f.rules[:8]), "snippet": f.detail.get("snippet") or ""})
        ev = []
        for key in ("login", "email", "registered", "plugin", "link_target"):
            if f.detail.get(key):
                ev.append("%s: %s" % (key, clean(f.detail[key], 120)))
        if f.detail.get("counts"):
            ev.append("perubahan: %s" % clean(json.dumps(f.detail["counts"], sort_keys=True), 200))
        for s in (f.detail.get("samples") or [])[:5]:
            ev.append(clean(s, 200))
        display["evidence"] = ev
    return {"v": 1, "kind": p.action, "incident": incident_id, "params": p.params, "display": display}


class Engine(object):
    def __init__(self, cfg, store, notifier, mode, rules, runner=run_argv, clock=time.time, mysql_ro=None,
                 whitelist_loader=None):
        self.cfg = cfg
        self.store = store
        self.notifier = notifier
        self.mode = mode
        self.rules = rules
        self.runner = runner
        self.clock = clock
        self.mysql_ro = mysql_ro
        self.whitelist_loader = whitelist_loader or (lambda: Whitelist.from_files(
            [("cloudflare", cfg.cloudflare_file), ("admin", cfg.admin_subnets_file)], extra=cfg.whitelist_extra))

    # ---- deteksi ---------------------------------------------------------------------------------
    def detect(self, only=None):
        fns = {
            "ioc": lambda: IOCScanner(self.cfg, self.store, self.rules, self.clock).scan(),
            "accesslog": lambda: AccessLogScanner(self.cfg, self.store, self.rules, self.clock).scan(),
            "accounts": lambda: AccountAuditor(self.cfg, self.store, self.rules, self.mysql_ro, self.clock).audit()
            if self.cfg.sites else [],
            "integrity": lambda: IntegrityAdapter(self.cfg, self.store, self.rules, self.runner, self.clock).collect(),
        }
        findings = []
        for name in DETECTORS:
            if only and name not in only:
                continue
            try:
                findings.extend(fns[name]())
            except Exception as e:
                findings.append(Finding("DETECTOR_ERROR", "medium", name, detail={
                    "error": clean("%s: %s" % (e.__class__.__name__, e), 300)}, source=name))
        return findings

    def _lookup_contained(self, path):
        row = self.store.conn.execute(
            "SELECT detail_json FROM actions WHERE kind='CONTAIN_FILE' AND target=? AND status='CONTAINED' "
            "ORDER BY id DESC LIMIT 1", (tkey(path),)).fetchone()
        if row is None:
            return None
        try:
            return json.loads(row[0] or "{}").get("sha256")
        except ValueError:
            return None

    # ---- siklus ----------------------------------------------------------------------------------
    def run_cycle(self, only=None):
        now = self.clock()
        incident = new_incident_id(now)
        findings = self.detect(only)
        self.store.expire_blocks(now)
        proposals = decide(findings, self.cfg, lookup_contained=self._lookup_contained)
        t1 = T1Executor(self.cfg, self.store, self.notifier, self.mode, self.whitelist_loader, self.runner, self.clock)
        t1_results = [r for r in (t1.run(incident, p) for p in proposals if p.tier == "T1") if r]
        t2_results = [self.queue_t2(incident, p) for p in proposals if p.tier == "T2"]
        new_findings = [f for f in findings if f.severity != "info"
                        and self.store.should_alert(f.fingerprint(), now, self.cfg.realert_seconds)]
        t1_notable = [r for r in t1_results if r.get("status") not in ("DUPLICATE",)]
        t2_new = [r for r in t2_results if r.get("status") in ("QUEUED", "DRYRUN", "OBSERVED")]
        checklist = None
        if new_findings and any(p.tier == "T3" for p in proposals):
            checklist = write_checklist(self.cfg, incident, findings, now)
        summary = {"incident": incident, "mode": self.mode, "findings": len(findings), "new_findings": len(new_findings),
                   "t1": [dict((k, r.get(k)) for k in ("kind", "status")) for r in t1_results],
                   "t2": [r.get("status") for r in t2_results], "checklist": checklist,
                   "t1_whitelist_error": t1.whitelist_error}
        notable = bool(new_findings or t1_notable or t2_new)
        if notable:
            self._save_incident(incident, now, findings, summary)
            self.notifier.send(self._render_alert(incident, new_findings, t1_notable, t2_new, checklist, t1),
                               urgent=any(f.severity == "critical" for f in new_findings))
        self._breaker_reminder(now)
        self.store.set("engine:last_run", {"at": now, "incident": incident if notable else None,
                                           "findings": len(findings), "mode": self.mode})
        log_event(logging.INFO, "siklus selesai", **summary)
        return summary

    def _breaker_reminder(self, now):
        """Selama breaker trip / freeze, ingatkan tiap jam: T1 sedang mati (bisa jadi dipicu sengaja)."""
        ns = "live" if self.mode == "enforce" else "dryrun"
        tripped = self.store.get("breaker:%s:tripped" % ns)
        frozen = self.store.get("freeze")
        if not (tripped or frozen):
            return
        last = self.store.get("engine:t1_off_reminder") or 0
        if now - float(last) < 3600:
            return
        self.store.set("engine:t1_off_reminder", now)
        why = ("FREEZE: %s" % (frozen or {}).get("reason", "?")) if frozen else ("breaker trip: %s" % (tripped or {}).get("reason", "?"))
        self.notifier.send("\u23f0 <b>Pengingat</b>: aksi T1 masih NONAKTIF (%s). T0 & alert tetap berjalan. "
                           "Periksa lalu pulihkan dari konsol bila aman." % tg(why, 200), urgent=True)

    def queue_t2(self, incident, p):
        action = build_action(incident, p)
        aj = canonical_json(action)
        dedupe = sha256_hex(canonical_json([p.action, p.params]).encode("ascii"))
        now = self.clock()
        st = self.store
        if st.approval_by_dedupe(dedupe, ("QUEUED", "SENDING", "PENDING", "APPROVED", "EXECUTING", "EXECUTED")):
            return {"status": "DUPLICATE"}
        if st.approval_by_dedupe(dedupe, ("REJECTED", "FAILED", "SKIPPED_MODE"), since=now - self.cfg.t2_suppress_reject):
            return {"status": "SUPPRESSED"}
        if st.approval_by_dedupe(dedupe, ("EXPIRED", "BLOCKED_FROZEN"), since=now - self.cfg.t2_reask_expired):
            return {"status": "SUPPRESSED"}
        if self.mode != "enforce" and st.approval_by_dedupe(dedupe, ("DRYRUN", "OBSERVED"),
                                                            since=now - self.cfg.t2_suppress_reject):
            return {"status": "DUPLICATE"}
        status = {"enforce": "QUEUED", "dry-run": "DRYRUN", "observe": "OBSERVED"}[self.mode]
        rid = new_request_id()
        st.insert_approval(rid, incident, p.action, aj, sha256_hex(aj.encode("ascii")), dedupe, status)
        return {"status": status, "request_id": rid, "action": p.action, "target": p.target}

    def _save_incident(self, incident, now, findings, summary):
        with self.store.tx() as c:
            c.execute("INSERT OR REPLACE INTO incidents(id, created_at, mode, summary_json) VALUES (?,?,?,?)",
                      (incident, now, self.mode, json.dumps(summary, ensure_ascii=True, default=str)))
            for f in findings:
                d = f.to_dict()
                c.execute("INSERT INTO findings(incident_id, kind, severity, target, site, rules, detail_json, created_at)"
                          " VALUES (?,?,?,?,?,?,?,?)",
                          (incident, f.kind, f.severity, clean(f.target, 500), f.site, json.dumps(f.rules),
                           json.dumps(d["detail"], ensure_ascii=True, default=str), now))

    def _render_alert(self, incident, new_findings, t1, t2, checklist, t1exec):
        cfg = self.cfg
        mode_label = {"enforce": "ENFORCE", "dry-run": "DRY-RUN (simulasi)", "observe": "OBSERVE (amati)"}[self.mode]
        lines = ["\U0001f6e1\ufe0f <b>Bodyguard</b> \u2022 %s \u2022 mode <b>%s</b>" % (tg_code(incident, 40), mode_label),
                 tg(fmt_local(self.clock(), cfg.tz_offset, cfg.tz_label), 40)]
        if new_findings:
            ordered = sorted(new_findings, key=lambda f: -SEV_RANK[f.severity])
            counts = {}
            for f in ordered:
                counts[f.severity] = counts.get(f.severity, 0) + 1
            lines += ["", "<b>Temuan baru: %d</b> (%s)" % (len(ordered), ", ".join(
                "%s %d" % (s, counts[s]) for s in ("critical", "high", "medium", "low") if s in counts))]
            for f in ordered[:12]:
                lines.append("%s %s %s%s" % (SEV_ICON[f.severity], tg(f.kind, 40), tg_code(f.target, 160),
                                             (" \u2014 " + tg(", ".join(f.rules[:4]), 120)) if f.rules else ""))
            if len(ordered) > 12:
                lines.append("\u2026 dan %d lainnya (lihat log/bodyguard status)" % (len(ordered) - 12))
        if t1:
            lines += ["", "<b>T1 otomatis</b>"]
            for r in t1[:10]:
                extra = ""
                if r["status"] == "SKIPPED":
                    extra = " \u2014 " + tg(r["detail"].get("reason", ""), 120)
                elif r["status"] == "SKIPPED_WHITELIST":
                    extra = " \u2014 " + tg(r["detail"].get("reason", ""), 80)
                elif r["status"] in ("FAILED", "REFUSED"):
                    extra = " \u2014 " + tg(r["detail"].get("error") or r["detail"].get("reason") or "", 120)
                elif r["kind"] == "BLOCK_IP" and r["detail"].get("ttl"):
                    extra = " \u2014 %d jam" % (int(r["detail"]["ttl"]) // 3600)
                lines.append("\u2022 %s %s %s%s" % (tg(r["status"], 20), tg(ACTION_LABELS.get(r["kind"], r["kind"]) if r["kind"] not in ("CONTAIN_FILE", "BLOCK_IP") else {"CONTAIN_FILE": "kunci file (chown root + chmod 000)", "BLOCK_IP": "blokir IP"}[r["kind"]], 60),
                                                   tg_code(r["target"], 140), extra))
            if any(r["status"] == "SKIPPED_WHITELIST" and "cloudflare" in str(r["detail"].get("reason", "")) for r in t1):
                lines.append("\u2139\ufe0f IP Cloudflare tidak pernah diblokir. Aktifkan real_ip nginx agar IP asli penyerang tercatat.")
        if t1exec.whitelist_error:
            lines.append("\u26a0\ufe0f Whitelist gagal dimuat - semua blokir IP dimatikan: %s" % tg(t1exec.whitelist_error, 200))
        if t2:
            n_q = sum(1 for r in t2 if r["status"] == "QUEUED")
            lines += ["", "<b>T2</b>: %d usulan %s" % (len(t2), "menunggu persetujuan di bot approval" if n_q
                                                       else "dicatat (mode %s, tidak dikirim ke bot approval)" % self.mode)]
            for r in t2[:6]:
                lines.append("\u2022 %s %s" % (tg(ACTION_LABELS.get(r.get("action"), r.get("action")), 60),
                                               tg_code(r.get("target"), 140)))
        if checklist:
            lines += ["", "<b>T3</b>: checklist manual %s" % tg_code(checklist, 200)]
        return "\n".join(lines)
