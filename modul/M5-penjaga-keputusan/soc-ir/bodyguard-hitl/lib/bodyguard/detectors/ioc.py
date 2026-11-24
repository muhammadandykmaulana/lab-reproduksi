# -*- coding: utf-8 -*-
"""T0: pemindai IOC file (read-only).

* Folder DATA (uploads, fonts, ijazah, public): file PHP apa pun = temuan (kecuali index.php "Silence is
  golden" / allowlist / hash jinak); gambar & file lain dicek polyglot (<?php di EXIF/ekor file) + IOC.
* Folder KODE (opsional + mu-plugins WordPress otomatis): hanya PHP, hanya aturan IOC.
* Nama folder plugin dicek terhadap pola plugin samaran (security-headers-manager-*).
* Tidak mengikuti symlink; symlink di folder data dilaporkan. File mode 000 dilaporkan sebagai
  CONTAINED_FILE tanpa dibaca. Cache (dev, inode, ukuran, mtime, ctime) agar pemindaian ulang ringan.
"""

import fnmatch
import hashlib
import json
import os
import re
import stat
import time

from ..model import Finding, max_sev
from ..sanitizer import clean, snippet
from ..util import log_event

O_CLOEXEC = getattr(os, "O_CLOEXEC", 0)
POLYGLOT_RE = re.compile(rb"(?i)<\?" rb"php|__halt_" rb"compiler\s*\(")
BENIGN_INDEX_RE = re.compile(rb"\A\s*<\?" rb"php(?:\s*(?://[^\n]*|#[^\n]*|/\*.*?\*/))*\s*(?:\?>)?\s*\Z", re.S)
SEP = b"\x00\x00BG-SPLIT\x00\x00"
MAX_DEPTH = 64


def _pread_all(fd, n, off):
    chunks, got = [], 0
    while got < n:
        b = os.pread(fd, min(1 << 20, n - got), off + got)
        if not b:
            break
        chunks.append(b)
        got += len(b)
    return b"".join(chunks)


class IOCScanner(object):
    def __init__(self, cfg, store, rules, clock=time.time):
        self.cfg = cfg
        self.store = store
        self.rules = rules
        self.clock = clock
        self._seen = 0
        self._truncated = False
        self._cache_updates = []
        self._denied = []

    # ---- API -------------------------------------------------------------------------------------
    def scan(self):
        findings = []
        if not self.cfg.data_dirs:
            findings.append(Finding("CONFIG_WARNING", "medium", "ioc.data_dirs",
                                    detail={"error": "tidak ada data_dirs yang ditemukan"}, source="ioc"))
        for root in self.cfg.data_dirs:
            self._walk(root, "data", findings)
        for root in self._code_roots():
            self._walk(root, "code", findings)
        findings.extend(self._plugins())
        self.store.cache_put_many(self._cache_updates, self.clock())
        self._cache_updates = []
        if self._truncated:
            findings.append(Finding("SCAN_TRUNCATED", "low", "ioc",
                                    detail={"limit": self.cfg.max_files_per_run}, source="ioc"))
        if self._denied:
            findings.append(Finding("SCAN_DENIED", "medium", "ioc", detail={
                "count": len(self._denied), "samples": [clean(p, 200) for p in self._denied[:10]],
                "note": "direktori tidak terbaca user guard = titik buta pemindaian"}, source="ioc"))
        return findings

    def _code_roots(self):
        roots = list(self.cfg.code_dirs)
        for s in self.cfg.sites:
            if s.type == "wordpress":
                mu = os.path.join(s.root, "wp-content", "mu-plugins")
                if os.path.isdir(mu) and not os.path.islink(mu) and mu not in roots:
                    roots.append(mu)
        return roots

    # ---- penelusuran -----------------------------------------------------------------------------
    def _walk(self, root, where, findings):
        """Penelusuran ITERATIF (tanpa rekursi -> pohon sangat dalam tidak bisa memicu RecursionError),
        galat per direktori tidak menghentikan pemindaian, dan file berekstensi PHP SELALU diperiksa
        (batas max_files_per_run hanya berlaku untuk file non-PHP, agar banjir file kosong tidak membutakan)."""
        stack = [(os.fsencode(root), 0)]
        while stack:
            dirpath, depth = stack.pop()
            if depth > MAX_DEPTH:
                self._denied.append(dirpath)
                continue
            try:
                entries = list(os.scandir(dirpath))
            except OSError as e:
                self._denied.append(dirpath)
                log_event(30, "gagal membaca direktori saat pindai", path=clean(dirpath, 200), err=e.__class__.__name__)
                continue
            for ent in entries:
                full = ent.path
                try:
                    if ent.is_symlink():
                        if where == "data":
                            findings.append(self._symlink(full))
                        continue
                    if ent.is_dir(follow_symlinks=False):
                        stack.append((full, depth + 1))
                        continue
                except OSError:
                    continue
                name = ent.name
                if not self._is_phpish(name):
                    if self._seen >= self.cfg.max_files_per_run:
                        self._truncated = True
                        continue
                    self._seen += 1
                try:
                    f = self._check(full, name, where)
                except OSError:
                    continue
                if f is not None:
                    findings.append(f)

    def _is_phpish(self, name):
        lname = os.fsdecode(name).lower()
        return os.path.splitext(lname)[1] in self.rules.php_ext or ".php" in lname or ".phtml" in lname

    def _symlink(self, full):
        try:
            target = os.readlink(full)
        except OSError:
            target = b"?"
        return Finding("SYMLINK_IN_DATA_DIR", "medium", full, site=self._site(full),
                       detail={"link_target": clean(target, 200)}, source="ioc")

    def _site(self, path):
        s = self.cfg.site_of(path)
        return s.name if s else None

    def _check(self, full, name, where):
        st = os.lstat(full)
        if stat.S_ISLNK(st.st_mode):
            return self._symlink(full) if where == "data" else None
        if not stat.S_ISREG(st.st_mode):
            return None
        lname = name.lower()
        if b".bgq-" in lname or b".bg-disabled-" in lname:
            return None
        name_s = os.fsdecode(name)
        fn_hits = self.rules.filename_hits(name_s)
        ext = os.fsdecode(os.path.splitext(lname)[1])
        double = any(r["id"] == "FN-DOUBLE-EXT" for r in fn_hits)
        klass = "php" if (ext in self.rules.php_ext or double) else ("image" if ext in self.rules.image_ext else "other")
        if where == "code" and klass != "php":
            return None
        path_s = os.fsdecode(full)
        # "Terkunci" hanya bila mode 000 DAN milik root (hasil bg-root). Mode 000 milik www-data bisa
        # dibuka lagi kapan saja oleh pemiliknya (penyerang), jadi tetap diperlakukan mencurigakan.
        # (uid proses sendiri hanya relevan untuk uji non-root; guard tidak pernah memiliki file web.)
        if stat.S_IMODE(st.st_mode) == 0 and st.st_uid in (0, os.geteuid()):
            if where == "data":
                return Finding("CONTAINED_FILE", "info", path_s, site=self._site(path_s),
                               detail={"uid": st.st_uid}, source="ioc")
            return None
        sig = "%d:%d:%d:%d:%d" % (st.st_dev, st.st_ino, st.st_size, st.st_mtime_ns, st.st_ctime_ns)
        csig, verdict = self.store.cache_get(full)
        if csig == sig and verdict is not None:
            if verdict == "clean":
                return None
            try:
                d = json.loads(verdict)
                d["detail"]["cached"] = True
                return Finding(d["kind"], d["severity"], path_s, site=d.get("site"), rules=d.get("rules", []),
                               detail=d["detail"], source="ioc")
            except (ValueError, KeyError, TypeError):
                pass
        try:
            f = self._analyze(full, name, path_s, klass, where, st, fn_hits)
        except PermissionError:
            # Tidak terbaca oleh guard (mis. www-data 0600). PHP di folder data tetap mencurigakan;
            # bg-root (root) yang akan membaca, meng-hash, dan menyimpan buktinya saat T1.
            if where == "data" and klass == "php":
                return Finding("PHP_IN_DATA_DIR", max_sev("high", *[r["severity"] for r in fn_hits]), path_s,
                               site=self._site(path_s), rules=["UNREADABLE-BY-GUARD"] + [r["id"] for r in fn_hits],
                               detail={"sha256": None, "unreadable": True, "uid": st.st_uid,
                                       "mode": "%04o" % stat.S_IMODE(st.st_mode), "size": st.st_size}, source="ioc")
            self._denied.append(full)
            return None
        self._cache_updates.append((full, sig, "clean" if f is None else json.dumps(f.to_dict(), ensure_ascii=True)))
        if len(self._cache_updates) >= 2000:
            self.store.cache_put_many(self._cache_updates, self.clock())
            self._cache_updates = []
        return f

    def _read_sample(self, full, klass):
        fd = os.open(full, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | O_CLOEXEC)
        try:
            st = os.fstat(fd)
            if not stat.S_ISREG(st.st_mode):
                return None, False
            if klass == "php":
                data = _pread_all(fd, self.cfg.max_php_bytes, 0)
                return data, st.st_size > self.cfg.max_php_bytes
            head = _pread_all(fd, self.cfg.head_bytes, 0)
            if st.st_size <= self.cfg.head_bytes or self.cfg.tail_bytes == 0:
                return head, st.st_size > self.cfg.head_bytes
            start = max(self.cfg.head_bytes, st.st_size - self.cfg.tail_bytes)
            tail = _pread_all(fd, self.cfg.tail_bytes, start)
            return head + SEP + tail, st.st_size > self.cfg.head_bytes + self.cfg.tail_bytes
        finally:
            os.close(fd)

    @staticmethod
    def _sha256(full, limit=256 * 1024 * 1024):
        h = hashlib.sha256()
        fd = os.open(full, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | O_CLOEXEC)
        try:
            off = 0
            while off < limit:
                b = os.pread(fd, 1 << 20, off)
                if not b:
                    break
                h.update(b)
                off += len(b)
        finally:
            os.close(fd)
        return h.hexdigest()

    def _allowlisted(self, path_s):
        return any(fnmatch.fnmatch(path_s, pat) for pat in self.cfg.data_php_allow)

    def _analyze(self, full, name, path_s, klass, where, st, fn_hits):
        data, truncated = self._read_sample(full, klass)
        if data is None:
            return None
        hits = self.rules.content_hits(data, klass, where)
        rules = [r["id"] for r, _m in hits] + [r["id"] for r in fn_hits]
        sev = max_sev(*([r["severity"] for r, _m in hits] + [r["severity"] for r in fn_hits]))
        first = hits[0][1] if hits else None
        if where == "data" and klass == "php":
            if not hits and name.lower() == b"index.php" and st.st_size <= 1024 and BENIGN_INDEX_RE.match(data):
                return None
            if not hits and self._allowlisted(path_s):
                return None
            kind, sev = "PHP_IN_DATA_DIR", max_sev("high", sev)
        elif where == "data":
            poly = POLYGLOT_RE.search(data)
            if not poly and not hits and not fn_hits:
                return None
            if poly or hits:
                kind = "POLYGLOT_FILE"
                if poly:
                    rules.insert(0, "POLYGLOT-PHP-DI-NONPHP")
                    first = first or poly
                sev = max_sev("critical" if (poly and hits) else "high", sev)
            else:
                kind = "SUSPICIOUS_FILENAME"
        else:
            if not hits and not fn_hits:
                return None
            kind = "IOC_IN_CODE"
        sha = self._sha256(full)
        if not hits and sha in self.rules.benign_sha256:
            return None
        detail = {
            "sha256": sha, "size": st.st_size, "mode": "%04o" % stat.S_IMODE(st.st_mode), "uid": st.st_uid,
            "mtime": int(st.st_mtime), "klass": klass, "where": where, "truncated": truncated,
            "snippet": snippet(data, first.start(), first.end()) if first is not None else "",
        }
        if where == "code":
            pdir = self.cfg.plugin_dir_of(path_s)
            if pdir:
                detail["plugin_dir"] = pdir
        return Finding(kind, sev, path_s, site=self._site(path_s), rules=rules, detail=detail, source="ioc")

    # ---- plugin samaran ----------------------------------------------------------------------------
    def _plugins(self):
        out = []
        for s in self.cfg.sites:
            if s.type != "wordpress":
                continue
            root = os.path.join(s.root, "wp-content", "plugins")
            try:
                names = sorted(os.listdir(root))
            except OSError:
                continue
            for name in names:
                if ".bg-disabled-" in name:
                    continue
                hits = self.rules.plugin_hits(name)
                if hits:
                    out.append(Finding("SUSPICIOUS_PLUGIN", max_sev(*[r["severity"] for r in hits]),
                                       os.path.join(root, name), site=s.name, rules=[r["id"] for r in hits],
                                       detail={"plugin": clean(name, 120)}, source="ioc"))
        return out
