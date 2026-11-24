# -*- coding: utf-8 -*-
"""T0: adapter web-integrity-cek.sh (baseline hash ~136k file).

Bodyguard TIDAK menghitung ulang 136k hash. Ia mengikat kontrol yang sudah ada:
  mode=report  : membaca laporan terbaru (report_glob) yang ditulis cron web-integrity-cek.sh (disarankan,
                 tidak butuh hak tambahan).
  mode=command : menjalankan perintah cek read-only sebagai guard dan membaca stdout.
Baris laporan diparse dengan [integrity] line_regex (grup bernama `path`, opsional `kind`).
File PHP yang BARU/BERUBAH dicek ulang dengan aturan IOC -> IOC_IN_CODE.
"""

import glob
import os
import time

from ..model import Finding, max_sev
from ..sanitizer import clean, snippet
from ..util import canonical_json, run_argv, sha256_hex

SUSPECT_KINDS = ("PHP DI FOLDER DATA", "IOC", "EKSTENSI GANDA", "PHP DI DALAM GAMBAR", "PLUGIN/MU-PLUGIN BARU")
KIND_MAP = {"<": "CHANGED", ">": "CHANGED", "CHANGED": "CHANGED", "MODIFIED": "CHANGED", "BERUBAH": "CHANGED", "NEW": "NEW", "ADDED": "NEW",
            "BARU": "NEW", "DELETED": "DELETED", "MISSING": "DELETED", "HILANG": "DELETED"}
SENSITIVE_NAMES = (".htaccess", ".user.ini", "php.ini", "wp-config.php", "config.inc.php")
MAX_ENTRIES = 50000


class IntegrityAdapter(object):
    def __init__(self, cfg, store, rules, runner=run_argv, clock=time.time):
        self.cfg = cfg
        self.store = store
        self.rules = rules
        self.runner = runner
        self.clock = clock

    def collect(self):
        mode = self.cfg.integrity_mode
        if mode == "off":
            return []
        sig = None
        if mode == "report":
            files = [f for f in glob.glob(self.cfg.integrity_report_glob) if os.path.isfile(f)]
            if not files:
                return [Finding("INTEGRITY_NO_REPORT", "low", self.cfg.integrity_report_glob, source="integrity")]
            newest = max(files, key=lambda f: os.stat(f).st_mtime)
            st = os.stat(newest)
            sig = "%s|%d|%d" % (newest, st.st_mtime_ns, st.st_size)
            if self.store.get("integrity:last_report") == sig:
                return []
            with open(newest, "rb") as f:
                data = f.read(self.cfg.integrity_max_bytes)
        else:
            rc, data, err = self.runner(self.cfg.integrity_command, timeout=3600)
            if rc not in (0, 1):  # banyak skrip cek memakai rc=1 untuk "ada perubahan"
                return [Finding("INTEGRITY_ERROR", "low", "command", detail={"rc": rc, "err": clean(err[-200:], 200)},
                                source="integrity")]
        entries = self._parse(data)
        changeset = sha256_hex(canonical_json(sorted(entries)).encode("ascii"))
        self.store.set("integrity:changeset", {"sha256": changeset, "count": len(entries), "at": self.clock()})
        if sig:
            self.store.set("integrity:last_report", sig)
        if not entries:
            return []
        findings, counts, ioc_hits, sensitive = [], {}, 0, []
        truncated = len(entries) > MAX_ENTRIES
        entries = sorted(set(entries))
        for kind, path in entries:
            counts[kind] = counts.get(kind, 0) + 1
        for kind, path in entries[:MAX_ENTRIES]:
            base = os.path.basename(path).lower()
            if base in SENSITIVE_NAMES or base.startswith(".user.ini") or kind == "SUSPECT":
                sensitive.append(path)
            if kind == "DELETED" or not self._phpish(base):
                continue
            f = self._ioc(path)
            if f is not None:
                findings.append(f)
                ioc_hits += 1
        # Usulan "terima baseline" (policy) hanya bila: 0 IOC, 0 file konfigurasi sensitif, daftar tidak terpotong.
        blockers = ioc_hits + len(sensitive) + (1 if truncated else 0)
        findings.append(Finding("INTEGRITY_CHANGES", "high" if (ioc_hits or sensitive) else "medium", "web-integrity-cek",
                                detail={"counts": counts, "changeset": changeset, "ioc_hits": blockers,
                                        "sensitive": [clean(p, 200) for p in sensitive[:10]], "truncated": truncated,
                                        "samples": [clean("%s %s" % (k, p), 200) for k, p in entries[:15]]},
                                source="integrity"))
        return findings

    def _phpish(self, base):
        ext = os.path.splitext(base)[1]
        return ext in self.rules.php_ext or ".php" in base or ext in (".phtml", ".phar", ".pht")

    def _parse(self, data):
        rx = self.cfg.integrity_line_re
        out = []
        for line in data.decode("utf-8", "replace").splitlines():
            m = rx.match(line)
            if not m:
                continue
            raw = ""
            for g in ("kind", "kind2"):
                if g in rx.groupindex and m.group(g):
                    raw = m.group(g).upper()
            kind = "SUSPECT" if raw in SUSPECT_KINDS else KIND_MAP.get(raw, "CHANGED")
            path = m.group("path")
            if path and path.startswith("/"):
                out.append((kind, path))
        return out

    def _ioc(self, path):
        try:
            fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        except OSError:
            return None
        try:
            data = os.read(fd, self.cfg.max_php_bytes)
        finally:
            os.close(fd)
        hits = self.rules.content_hits(data, "php", "code")
        if not hits:
            return None
        detail = {"sha256": sha256_hex(data), "snippet": snippet(data, hits[0][1].start(), hits[0][1].end()),
                  "where": "code", "klass": "php"}
        pdir = self.cfg.plugin_dir_of(path)
        if pdir:
            detail["plugin_dir"] = pdir
        site = self.cfg.site_of(path)
        return Finding("IOC_IN_CODE", max_sev(*[r["severity"] for r, _m in hits]), path,
                       site=site.name if site else None, rules=[r["id"] for r, _m in hits], detail=detail,
                       source="integrity")
