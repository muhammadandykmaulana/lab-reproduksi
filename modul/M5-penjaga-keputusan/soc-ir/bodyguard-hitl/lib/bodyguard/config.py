# -*- coding: utf-8 -*-
"""Konfigurasi /etc/bodyguard/bodyguard.conf (INI). Wajib milik root dan tidak writable group/other.

Semua nilai divalidasi dengan batas keras di kode: salah ketik di config (mis. 2000 blokir/jam)
tidak bisa membuat sistem lebih agresif dari batas aman.
Rahasia (token bot, kunci HMAC, allowlist approver) TIDAK ada di file ini; rahasia datang dari
environment yang dimuat systemd dari file env root:root 0600.
"""

import configparser
import glob
import os
import re
import shlex
import stat

from .util import BodyguardError, SecurityError, check_file_secure

MODES = ("observe", "dry-run", "enforce")
HARD_MAX = {"ip_block": 60, "chmod": 20}
TTL_MIN, TTL_MAX = 3600, 86400
SITE_NAME_RE = re.compile(r"\A[A-Za-z0-9_-]{1,40}\Z")
DBNAME_RE = re.compile(r"\A[A-Za-z0-9_]{1,64}\Z")
PREFIX_RE = re.compile(r"\A[A-Za-z0-9_]{1,32}\Z")
APPROVER_RE = re.compile(r"\A\d{1,15}\Z")
CHAT_RE = re.compile(r"\A-?\d{1,20}\Z")

DEFAULT_ACCESS_RE = (
    r'^(?P<ip>[0-9A-Fa-f:.]{2,45}) \S+ \S+ \[(?P<time>[^\]]{1,40})\] '
    r'"(?P<method>[A-Z]{1,12}) (?P<uri>[^ "]{1,8192})(?: [^"]{0,24})?" (?P<status>\d{3}) '
)
# Cocok dengan keluaran web-integrity-cek.sh v2/v3 (v3 memberi awalan "[FAIL] " pada baris alert): baris diff "< sha  /path" / "> sha  /path" dan
# baris alert "PHP DI FOLDER DATA: /path", "IOC: /path (baris N)", "EKSTENSI GANDA: /path",
# "PHP DI DALAM GAMBAR: /path", "PLUGIN/MU-PLUGIN BARU: /dir", plus format generik CHANGED/NEW/DELETED.
DEFAULT_INTEGRITY_RE = (
    r"^\s*(?:\[FAIL\]\s*)?(?:(?P<kind>[<>]) [0-9a-f]{64}  |\[?(?P<kind2>CHANGED|MODIFIED|NEW|ADDED|DELETED|MISSING|BERUBAH|BARU|HILANG"
    r"|PHP DI FOLDER DATA|IOC|EKSTENSI GANDA|PHP DI DALAM GAMBAR|PLUGIN/MU-PLUGIN BARU)\]?\s*:\s*)(?P<path>/[^ \t]+)"
)


class ConfigError(BodyguardError):
    pass


class Site(object):
    __slots__ = ("name", "type", "root", "db", "prefix")

    def __init__(self, name, type_, root, db, prefix):
        self.name, self.type, self.root, self.db, self.prefix = name, type_, root, db, prefix

    def __repr__(self):
        return "Site(%s,%s)" % (self.name, self.type)


class Config(object):
    def __init__(self, cp, path="<memory>"):
        self.path = path
        self._cp = cp
        g = "general"
        self.mode = self._choice(g, "mode", MODES, "dry-run")
        self.state_dir = self._abs(g, "state_dir", "/var/lib/bodyguard")
        self.log_file = cp.get(g, "log_file", fallback="/var/log/bodyguard/bodyguard.jsonl").strip() or None
        self.tz_offset = self._float(g, "display_tz_offset_hours", 7.0, -12.0, 14.0)
        self.tz_label = (cp.get(g, "display_tz_label", fallback="WIB").strip() or "WIB")[:8]
        self.realert_seconds = self._int(g, "realert_after_hours", 24, 1, 720) * 3600

        lim = "limits"
        self.limits = {
            "ip_block": self._int(lim, "max_ip_blocks_per_hour", 20, 1, HARD_MAX["ip_block"]),
            "chmod": self._int(lim, "max_chmod_per_hour", 5, 1, HARD_MAX["chmod"]),
        }
        self.ip_ttl = {
            "critical": self._int(lim, "ip_block_ttl_critical", 86400, TTL_MIN, TTL_MAX),
            "high": self._int(lim, "ip_block_ttl_high", 21600, TTL_MIN, TTL_MAX),
            "medium": self._int(lim, "ip_block_ttl_medium", 3600, TTL_MIN, TTL_MAX),
        }
        self.t2_ttl = self._int(lim, "t2_ttl_seconds", 1800, 300, 3600)
        self.t2_suppress_reject = self._int(lim, "t2_suppress_after_reject_days", 7, 1, 90) * 86400
        self.t2_reask_expired = self._int(lim, "t2_reask_after_expired_hours", 6, 1, 168) * 3600

        w = "whitelist"
        self.cloudflare_file = self._abs(w, "cloudflare_file", "/etc/bodyguard/cloudflare-ips.txt")
        self.admin_subnets_file = self._abs(w, "admin_subnets_file", "/etc/bodyguard/admin-subnets.txt")
        self.whitelist_extra = cp.get(w, "extra", fallback="").split()

        x = "wrappers"
        self.sudo = self._abs(x, "sudo", "/usr/bin/sudo")
        self.bg_root = self._abs(x, "bg_root", "/usr/local/sbin/bg-root")

        i = "ioc"
        self.rules_file = cp.get(i, "rules_file", fallback="/etc/bodyguard/ioc_rules.json").strip()
        self.data_dirs, self.data_dirs_missing = self._dirs(i, "data_dirs")
        self.code_dirs, self.code_dirs_missing = self._dirs(i, "code_dirs")
        self.data_php_allow = cp.get(i, "data_php_allow", fallback="").split()
        self.head_bytes = self._int(i, "head_bytes", 131072, 4096, 8 * 1024 * 1024)
        self.tail_bytes = self._int(i, "tail_bytes", 65536, 0, 8 * 1024 * 1024)
        self.max_php_bytes = self._int(i, "max_php_bytes", 2 * 1024 * 1024, 65536, 64 * 1024 * 1024)
        self.max_files_per_run = self._int(i, "max_files_per_run", 300000, 100, 5000000)

        a = "accesslog"
        # Glob diizinkan (mis. /var/log/nginx/*_access.log); file .gz & rotasi bernomor dilewati.
        self.access_logs = []
        for item in cp.get(a, "files", fallback="").split():
            for m in (sorted(glob.glob(item)) if any(ch in item for ch in "*?[") else [item]):
                if not re.search(r"\.(?:gz|\d+)$", m) and m not in self.access_logs:
                    self.access_logs.append(m)
        self.access_line_re = self._regex(a, "line_regex", DEFAULT_ACCESS_RE, required_groups=("ip", "uri", "status"))
        self.access_initial_tail = self._int(a, "initial_tail_bytes", 2 * 1024 * 1024, 0, 512 * 1024 * 1024)
        self.access_max_bytes = self._int(a, "max_bytes_per_run", 50 * 1024 * 1024, 65536, 2 * 1024 * 1024 * 1024)
        self.score_medium = self._int(a, "block_score_medium", 3, 1, 1000)
        self.score_high = self._int(a, "block_score_high", 6, 1, 1000)
        self.score_critical = self._int(a, "block_score_critical", 10, 1, 1000)
        if not (self.score_medium <= self.score_high <= self.score_critical):
            raise ConfigError("[accesslog] skor harus medium <= high <= critical")

        c = "accounts"
        self.mysql_bin = self._abs(c, "mysql", "/usr/bin/mysql")
        self.mysql_ro_cnf = self._abs(c, "ro_defaults_file", "/etc/bodyguard/mysql-ro.cnf")
        self.mysql_t2_cnf = self._abs(c, "t2_defaults_file", "/etc/bodyguard/mysql-t2.cnf")
        self.ojs_logout_sessions = cp.getboolean(c, "ojs_logout_sessions", fallback=False)
        self.sites = self._sites()

        gi = "integrity"
        self.integrity_mode = self._choice(gi, "mode", ("off", "report", "command"), "off")
        self.integrity_report_glob = cp.get(gi, "report_glob", fallback="").strip()
        self.integrity_command = shlex.split(cp.get(gi, "command", fallback=""))
        self.integrity_line_re = self._regex(gi, "line_regex", DEFAULT_INTEGRITY_RE, required_groups=("path",))
        self.integrity_max_bytes = self._int(gi, "max_report_bytes", 8 * 1024 * 1024, 4096, 256 * 1024 * 1024)
        if self.integrity_mode == "report" and not self.integrity_report_glob:
            raise ConfigError("[integrity] mode=report butuh report_glob")
        if self.integrity_mode == "command" and not self.integrity_command:
            raise ConfigError("[integrity] mode=command butuh command")

        n = "notify"
        self.notify_backend = self._choice(n, "backend", ("telegram", "command", "log"), "telegram")
        self.notify_command = shlex.split(cp.get(n, "command", fallback=""))
        self.notify_max_per_hour = self._int(n, "max_messages_per_hour", 30, 1, 600)
        self.notify_urgent_max_per_hour = self._int(n, "urgent_max_per_hour", 20, 1, 600)
        if self.notify_backend == "command" and not self.notify_command:
            raise ConfigError("[notify] backend=command butuh command")

        k = "gatekeeper"
        self.gatekeeper_env_file = self._abs(k, "env_file", "/etc/bodyguard/gatekeeper.env")
        self.alert_env_file = self._abs(k, "alert_env_file", "/etc/bodyguard/alert.env")
        self.poll_timeout = self._int(k, "poll_timeout", 25, 1, 50)
        # Batas permintaan T2 yang tampil bersamaan: mencegah "kelelahan persetujuan" (approval fatigue)
        # saat penyerang memicu puluhan usulan sekaligus. Sisanya menunggu dalam antrean.
        self.max_pending = self._int(k, "max_pending", 8, 1, 30)

    # ---- helper validasi ------------------------------------------------------------------------
    def _int(self, sec, key, default, lo, hi):
        raw = self._cp.get(sec, key, fallback=str(default)).strip()
        if not re.match(r"\A-?\d{1,12}\Z", raw):
            raise ConfigError("[%s] %s harus bilangan bulat" % (sec, key))
        v = int(raw)
        if v < lo or v > hi:
            raise ConfigError("[%s] %s=%d di luar batas aman %d..%d" % (sec, key, v, lo, hi))
        return v

    def _float(self, sec, key, default, lo, hi):
        try:
            v = float(self._cp.get(sec, key, fallback=str(default)))
        except ValueError:
            raise ConfigError("[%s] %s harus angka" % (sec, key))
        if v < lo or v > hi:
            raise ConfigError("[%s] %s di luar batas" % (sec, key))
        return v

    def _choice(self, sec, key, choices, default):
        v = self._cp.get(sec, key, fallback=default).strip().lower()
        if v not in choices:
            raise ConfigError("[%s] %s harus salah satu dari %s" % (sec, key, "/".join(choices)))
        return v

    def _abs(self, sec, key, default):
        v = self._cp.get(sec, key, fallback=default).strip()
        if not v.startswith("/"):
            raise ConfigError("[%s] %s harus path absolut" % (sec, key))
        return v

    def _regex(self, sec, key, default, required_groups=()):
        raw = self._cp.get(sec, key, fallback="").strip() or default
        try:
            rx = re.compile(raw)
        except re.error as e:
            raise ConfigError("[%s] %s regex tidak valid: %s" % (sec, key, e))
        for gname in required_groups:
            if gname not in rx.groupindex:
                raise ConfigError("[%s] %s wajib punya grup bernama (?P<%s>...)" % (sec, key, gname))
        return rx

    def _dirs(self, sec, key):
        found, missing = [], []
        for item in self._cp.get(sec, key, fallback="").split():
            if not item.startswith("/"):
                raise ConfigError("[%s] %s: %r bukan path absolut" % (sec, key, item))
            matches = sorted(glob.glob(item)) if any(ch in item for ch in "*?[") else [item]
            if not matches:
                missing.append(item)
            for m in matches:
                rp = os.path.realpath(m)
                if os.path.isdir(rp):
                    if rp not in found:
                        found.append(rp)
                else:
                    missing.append(m)
        return found, missing

    def _sites(self):
        sites = []
        for sec in self._cp.sections():
            if not sec.startswith("site:"):
                continue
            name = sec[5:]
            if not SITE_NAME_RE.match(name):
                raise ConfigError("nama situs tidak valid: %r" % name)
            typ = self._choice(sec, "type", ("wordpress", "ojs"), "wordpress")
            root = self._abs(sec, "root", "/nonexistent")
            db = self._cp.get(sec, "db", fallback="").strip()
            if db and not DBNAME_RE.match(db):
                raise ConfigError("[%s] db tidak valid" % sec)
            prefix = self._cp.get(sec, "prefix", fallback="wp_" if typ == "wordpress" else "").strip()
            if typ == "wordpress" and not PREFIX_RE.match(prefix):
                raise ConfigError("[%s] prefix tabel tidak valid" % sec)
            sites.append(Site(name, typ, os.path.realpath(root), db, prefix))
        return sites

    # ---- helper path (pra-cek sisi guard; sisi root tetap otoritatif) ----------------------------
    @staticmethod
    def _real(path):
        if isinstance(path, bytes):
            path = os.fsdecode(path)
        return os.path.realpath(path)

    def data_root_of(self, path):
        p = self._real(path)
        best = None
        for r in self.data_dirs:
            if p.startswith(r.rstrip("/") + "/") and (best is None or len(r) > len(best)):
                best = r
        return best

    def site_of(self, path):
        p = self._real(path)
        best = None
        for s in self.sites:
            if p == s.root or p.startswith(s.root.rstrip("/") + "/"):
                if best is None or len(s.root) > len(best.root):
                    best = s
        return best

    def site_by_name(self, name):
        for s in self.sites:
            if s.name == name:
                return s
        return None

    def wp_plugin_roots(self):
        return [os.path.join(s.root, "wp-content", "plugins") for s in self.sites if s.type == "wordpress"]

    def plugin_dir_of(self, path):
        """Kembalikan path direktori/file plugin tingkat-1 bila path ada di dalam wp-content/plugins."""
        p = self._real(path)
        for root in self.wp_plugin_roots():
            base = root.rstrip("/") + "/"
            if p.startswith(base):
                first = p[len(base):].split("/", 1)[0]
                if first:
                    return base + first
        return None


def load_config(path, check_perms=True):
    if check_perms:
        check_file_secure(path, owner_uid=0, forbid_bits=0o022)
    cp = configparser.ConfigParser(interpolation=None, strict=True)
    with open(path, "r", encoding="utf-8") as f:
        cp.read_file(f)
    return Config(cp, path)


def config_from_string(text):
    cp = configparser.ConfigParser(interpolation=None, strict=True)
    cp.read_string(text)
    return Config(cp)


# ---- rahasia dari environment (dimuat systemd dari file env root:root 0600) ---------------------
def check_env_file(path):
    """Validasi file env hanya lewat stat (user guard memang tidak boleh bisa membacanya)."""
    st = os.lstat(path)
    if stat.S_ISLNK(st.st_mode) or not stat.S_ISREG(st.st_mode):
        raise SecurityError("%s harus file biasa (bukan symlink)" % path)
    if st.st_uid != 0:
        raise SecurityError("%s harus milik root" % path)
    if stat.S_IMODE(st.st_mode) & 0o077:
        raise SecurityError("%s harus mode 0600 (sekarang %04o)" % (path, stat.S_IMODE(st.st_mode)))
    return st


def parse_approvers(raw):
    ids = set()
    for item in (raw or "").replace(";", ",").split(","):
        item = item.strip()
        if not item:
            continue
        if not APPROVER_RE.match(item) or int(item) <= 0:
            raise ConfigError("BG_APPROVER_IDS berisi entri tidak valid")
        ids.add(int(item))
    return frozenset(ids)


def parse_chat_id(raw, name):
    s = (raw or "").strip()
    if not CHAT_RE.match(s):
        raise ConfigError("%s harus angka chat id Telegram" % name)
    return int(s)
