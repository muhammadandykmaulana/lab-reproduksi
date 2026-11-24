# -*- coding: utf-8 -*-
"""Eksekutor T1: aksi otomatis, ber-TTL & reversibel, selalu lewat circuit breaker.

Urutan gerbang (gagal di mana pun = TIDAK bertindak, cukup catat + alert):
  CONTAIN_FILE : mode -> dedupe (path+sha) -> pra-cek path di data_dirs -> breaker chmod -> dry-run? -> bg-root
  BLOCK_IP     : whitelist (gagal muat = tolak semua) -> mode -> dedupe blokir aktif -> breaker ip_block
                 -> dry-run? -> bg-root cf-block -> cf-guard.py block (daftar IP Cloudflare ber-TTL; satu jalur blokir)
Mode: observe = hanya dicatat; dry-run = disimulasikan dengan breaker namespace "dryrun"; enforce = nyata.
"""

import json
import logging
import os
import time

from .breaker import CircuitBreaker
from .rootcall import call_bg_root, planned_argv
from .sanitizer import tg, tg_code
from .util import log_event, run_argv, tkey
from .whitelist import WhitelistError

RETRY_AFTER = 3600  # aksi GAGAL/DITOLAK baru dicoba lagi setelah 1 jam
RESET_HINT = "sudo -u guard /opt/bodyguard/bin/bodyguard reset-breaker --reason \"...\""


class T1Executor(object):
    def __init__(self, cfg, store, notifier, mode, whitelist_loader, runner=run_argv, clock=time.time):
        if mode not in ("observe", "dry-run", "enforce"):
            raise ValueError("mode tidak dikenal")
        self.cfg = cfg
        self.store = store
        self.notifier = notifier
        self.mode = mode
        self.ns = "live" if mode == "enforce" else "dryrun"
        self.runner = runner
        self.clock = clock
        self.breaker = CircuitBreaker(store, cfg.limits, self.ns, clock=clock)
        self.whitelist, self.whitelist_error = None, None
        try:
            self.whitelist = whitelist_loader()
        except (WhitelistError, OSError) as e:
            self.whitelist_error = str(e)

    def run(self, incident_id, proposal):
        if proposal.action == "CONTAIN_FILE":
            return self.contain(incident_id, proposal)
        if proposal.action == "BLOCK_IP":
            return self.block_ip(incident_id, proposal)
        return None

    def _record(self, incident_id, kind, target, status, detail, rollback=None, expires_at=None):
        self.store.add_action(incident_id, "T1", kind, tkey(target), status, self.ns, detail, rollback, expires_at)
        log_event(logging.WARNING if status in ("CONTAINED", "BLOCKED", "FAILED") else logging.INFO,
                  "aksi T1", kind=kind, status=status, ns=self.ns, incident=incident_id)
        return {"kind": kind, "target": target, "status": status, "detail": detail, "rollback": rollback}

    def _breaker_denied(self, incident_id, kind, target, decision):
        r = self._record(incident_id, kind, target, "SKIPPED", {"reason": decision.reason})
        if decision.tripped_now:
            self.notifier.send(
                "\U0001f6a8 <b>CIRCUIT BREAKER TRIP</b> (%s)\n%s\nSemua aksi T1 dialihkan ke <b>T0 (amati saja)</b>. "
                "T0 & alert tetap berjalan.\nSetelah diperiksa, reset dari konsol:\n%s"
                % (tg(self.ns, 20), tg(decision.reason, 300), tg_code(RESET_HINT, 200)), urgent=True)
        return r

    def contain(self, incident_id, p):
        path = p.params["path"]
        sha = p.finding.detail.get("sha256") if p.finding is not None else None
        kind = "CONTAIN_FILE"
        if self.mode == "observe":
            return self._record(incident_id, kind, path, "OBSERVED", {"note": "mode observe: tidak ada aksi"})
        prev = self.store.find_action(kind, tkey(path), self.ns, ("CONTAINED", "DRYRUN"))
        if prev is not None:
            try:
                if json.loads(prev["detail_json"] or "{}").get("sha256") == sha:
                    return {"kind": kind, "target": path, "status": "DUPLICATE"}
            except ValueError:
                pass
        if self._recent_failure(kind, path):
            return {"kind": kind, "target": path, "status": "DUPLICATE"}
        if self.cfg.data_root_of(path) is None:
            return self._record(incident_id, kind, path, "REFUSED", {"reason": "path di luar [ioc] data_dirs"},
                                expires_at=self.clock() + RETRY_AFTER)
        d = self.breaker.acquire("chmod", path)
        if not d.allowed:
            return self._breaker_denied(incident_id, kind, path, d)
        args = ["contain", "--incident", incident_id, "--", os.fsencode(path)]
        if self.mode == "dry-run":
            return self._record(incident_id, kind, path, "DRYRUN", {"would_run": planned_argv(self.cfg, args),
                                                                    "sha256": sha, "count": d.count, "limit": d.limit})
        ok, res = call_bg_root(self.cfg, self.runner, args)
        if ok:
            return self._record(incident_id, kind, path, "CONTAINED", {
                "sha256": res.get("sha256"), "evidence": res.get("evidence"), "original": res.get("original"),
                "collect3": (res.get("collect3") or {}).get("status"), "warning": res.get("warning"),
                "already": bool(res.get("already_contained"))}, rollback=res.get("rollback"))
        return self._record(incident_id, kind, path, "FAILED", {"error": res.get("detail") or res.get("error"),
                                                                "rc": res.get("rc"), "stderr": res.get("stderr")},
                            expires_at=self.clock() + RETRY_AFTER)

    def _recent_failure(self, kind, target):
        """Aksi yang gagal/ditolak tidak diulang tiap siklus (hemat kuota breaker, tidak spam alert)."""
        return self.store.find_action(kind, tkey(target), self.ns, ("FAILED", "REFUSED"),
                                      active_at=self.clock()) is not None

    def block_ip(self, incident_id, p):
        ip = p.params["ip"]
        ttl = int(p.params["ttl"])
        kind = "BLOCK_IP"
        now = self.clock()
        if self.whitelist is None:
            return self._record(incident_id, kind, ip, "REFUSED",
                                {"reason": "whitelist gagal dimuat (fail-closed): %s" % self.whitelist_error})
        blockable, reason = self.whitelist.check(ip)
        if not blockable:
            if self.store.find_action(kind, tkey(ip), self.ns, ("SKIPPED_WHITELIST",), active_at=now) is not None:
                return {"kind": kind, "target": ip, "status": "DUPLICATE"}
            return self._record(incident_id, kind, ip, "SKIPPED_WHITELIST", {"reason": reason}, expires_at=now + 3600)
        if self.mode == "observe":
            return self._record(incident_id, kind, ip, "OBSERVED", {"ttl": ttl})
        if self.store.find_action(kind, tkey(ip), self.ns, ("BLOCKED", "DRYRUN"), active_at=now) is not None:
            return {"kind": kind, "target": ip, "status": "DUPLICATE"}
        if self._recent_failure(kind, ip):
            return {"kind": kind, "target": ip, "status": "DUPLICATE"}
        d = self.breaker.acquire("ip_block", ip)
        if not d.allowed:
            return self._breaker_denied(incident_id, kind, ip, d)
        args = ["cf-block", ip, str(ttl)]
        if self.mode == "dry-run":
            return self._record(incident_id, kind, ip, "DRYRUN", {"would_run": planned_argv(self.cfg, args), "ttl": ttl,
                                                                  "count": d.count, "limit": d.limit}, expires_at=now + ttl)
        ok, res = call_bg_root(self.cfg, self.runner, args, timeout=60)
        if ok:
            return self._record(incident_id, kind, ip, "BLOCKED", {"ttl": ttl, "via": "cf-guard"},
                                rollback=res.get("rollback"), expires_at=now + ttl)
        return self._record(incident_id, kind, ip, "FAILED", {"error": res.get("detail") or res.get("error"),
                                                              "rc": res.get("rc"), "stderr": res.get("stderr")},
                            expires_at=now + RETRY_AFTER)
