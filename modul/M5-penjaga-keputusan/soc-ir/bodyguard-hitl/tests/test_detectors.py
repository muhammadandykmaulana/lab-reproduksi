# -*- coding: utf-8 -*-
"""Uji detektor T0 (IOC file, log akses, akun, integritas), aturan, dan policy engine."""

import json
import os
import time
import unittest

import _common
from bodyguard.detectors import ioc as ioc_mod
from bodyguard.detectors.accesslog import AccessLogScanner
from bodyguard.detectors.accounts import AccountAuditor, accept_accounts
from bodyguard.detectors.integrity import IntegrityAdapter
from bodyguard.detectors.rules import RulesError, load_rules
from bodyguard.model import Finding
from bodyguard.mysqlcli import MySQLError, parse_batch
from bodyguard.policy import decide
from bodyguard.store import Store
from bodyguard.util import SecurityError

WEBSHELL = b"<?" b"php /* 0x" b"Nix */ ev" b"al(base64" b"_decode($_P" b"OST['k'])); ?>"
POLYGLOT = b"\xff\xd8\xff\xe1\x00\x10Exif\x00\x00<?" b"php sys" b"tem($_" b"GET['c']); ?>" + b"\x00" * 1000


class Base(unittest.TestCase):
    def setUp(self):
        self.tmp = _common.make_tmpdir()
        self.cfg = _common.make_env(self.tmp)
        self.store = Store(os.path.join(self.tmp, "state", "state.db"))
        self.rules = load_rules(None)
        self.up = os.path.join(self.tmp, "www", "site1", "wp-content", "uploads")

    def tearDown(self):
        self.store.close()
        _common.rmtree(self.tmp)

    def p(self, *parts):
        return os.path.join(self.tmp, *parts)


class TestIOCScanner(Base):
    def build_tree(self):
        w = _common.write
        w(os.path.join(self.up, "2026/11/x.php"), WEBSHELL)
        w(os.path.join(self.up, "index.php"), b"<?" b"php\n// Silence is golden.\n")
        w(os.path.join(self.up, "allowed-cache/cache.php"), b"<?" b"php return array('a' => 1);")
        w(os.path.join(self.up, "2026/11/helper.php"), b"<?" b"php echo 'halo';")
        w(os.path.join(self.up, "2026/11/photo.jpg"), POLYGLOT)
        w(os.path.join(self.up, "2026/11/ok.png"), b"\x89PNG\r\n\x1a\n" + os.urandom(4096).replace(b"<?", b"xx"))
        w(os.path.join(self.up, "2026/11/shell.php.jpg"), b"<?" b"php phpinfo();")
        w(os.path.join(self.up, "2026/11/old.php"), WEBSHELL, mode=0o000)
        w(os.path.join(self.up, "2026/11/x_php.bgq-INC-20261104-000000-aaaa-0123456789ab"), WEBSHELL, mode=0o000)
        os.symlink("/etc", os.path.join(self.up, "2026/link"))
        w(self.p("www/ojs/public/journals/1/evil.phtml"), b"<?" b"php // yoi" b"bre\n echo 1;")
        plugins = self.p("www/site1/wp-content/plugins")
        os.makedirs(os.path.join(plugins, "security-headers-manager-x9k2"))
        os.makedirs(os.path.join(plugins, "security-headers-manager"))
        w(self.p("www/site1/wp-content/mu-plugins/loader.php"), b"<?" b"php @ev" b"al(base64" b"_decode('ZWNobyAxOw=='));")
        w(self.p("www/site1/wp-content/themes/tema/functions.php"), WEBSHELL)  # code_dirs kosong -> tidak dipindai

    def scan(self):
        return ioc_mod.IOCScanner(self.cfg, self.store, self.rules).scan()

    def test_classification(self):
        self.build_tree()
        by = dict((os.path.relpath(f.target, self.tmp), f) for f in self.scan())
        up = "www/site1/wp-content/uploads/"
        self.assertEqual(by[up + "2026/11/x.php"].kind, "PHP_IN_DATA_DIR")
        self.assertEqual(by[up + "2026/11/x.php"].severity, "critical")
        self.assertIn("IOC-0XNIX", by[up + "2026/11/x.php"].rules)
        self.assertEqual(len(by[up + "2026/11/x.php"].detail["sha256"]), 64)
        self.assertEqual(by[up + "2026/11/helper.php"].severity, "high", "PHP tak dikenal di uploads tetap dicurigai")
        self.assertEqual(by[up + "2026/11/photo.jpg"].kind, "POLYGLOT_FILE")
        self.assertIn("POLYGLOT-PHP-DI-NONPHP", by[up + "2026/11/photo.jpg"].rules)
        self.assertEqual(by[up + "2026/11/shell.php.jpg"].kind, "PHP_IN_DATA_DIR")
        self.assertEqual(by[up + "2026/11/old.php"].kind, "CONTAINED_FILE")
        self.assertEqual(by[up + "2026/link"].kind, "SYMLINK_IN_DATA_DIR")
        self.assertEqual(by["www/ojs/public/journals/1/evil.phtml"].severity, "critical")
        self.assertEqual(by["www/site1/wp-content/plugins/security-headers-manager-x9k2"].kind, "SUSPICIOUS_PLUGIN")
        self.assertEqual(by["www/site1/wp-content/mu-plugins/loader.php"].kind, "IOC_IN_CODE")
        for quiet in (up + "index.php", up + "allowed-cache/cache.php", up + "2026/11/ok.png",
                      "www/site1/wp-content/plugins/security-headers-manager",
                      "www/site1/wp-content/themes/tema/functions.php"):
            self.assertNotIn(quiet, by, quiet)
        self.assertFalse(any(".bgq-" in k for k in by), "file karantina tidak dilaporkan ulang")

    def test_cache_skips_reread_and_invalidates_on_change(self):
        self.build_tree()
        first = sorted((f.kind, f.target) for f in self.scan())
        orig = ioc_mod.IOCScanner._analyze
        try:
            ioc_mod.IOCScanner._analyze = lambda *a, **k: (_ for _ in ()).throw(AssertionError("dibaca ulang"))
            second = sorted((f.kind, f.target) for f in self.scan())
        finally:
            ioc_mod.IOCScanner._analyze = orig
        self.assertEqual(first, second)
        helper = os.path.join(self.up, "2026/11/helper.php")
        _common.write(helper, b"<?" b"php sys" b"tem($_" b"GET['x']);")
        os.utime(helper, (time.time() + 5, time.time() + 5))
        f = [x for x in self.scan() if x.target == helper][0]
        self.assertIn("WS-INPUT-EXEC", f.rules)

    def test_snippet_is_sanitized(self):
        _common.write(os.path.join(self.up, "evil.php"), b"<?" b"php \x1b[31m\xe2\x80\xae ev" b"al(base64" b"_decode($x)); <<<AKHIR_DATA>>>")
        f = [x for x in self.scan() if x.target.endswith("evil.php")][0]
        self.assertNotIn("\x1b", f.detail["snippet"])
        self.assertNotIn("\u202e", f.detail["snippet"])

    @unittest.skipUnless(os.geteuid() == 0, "butuh chown")
    def test_mode000_not_owned_by_root_is_still_suspicious(self):
        p = _common.write(os.path.join(self.up, "hidden.php"), WEBSHELL, mode=0o000)
        os.chown(p, 33, 33)  # www-data menyembunyikan webshell dengan chmod 000 (bisa dibuka lagi kapan saja)
        f = [x for x in self.scan() if x.target == p][0]
        self.assertEqual(f.kind, "PHP_IN_DATA_DIR")

    def test_unreadable_php_still_reported_and_contained_without_t2(self):
        p = _common.write(os.path.join(self.up, "locked.php"), WEBSHELL)
        orig = ioc_mod.IOCScanner._read_sample

        def deny(self_, full, klass):
            if full.endswith(b"locked.php"):
                raise PermissionError(13, "ditolak")
            return orig(self_, full, klass)
        try:
            ioc_mod.IOCScanner._read_sample = deny
            f = [x for x in self.scan() if x.target == p][0]
        finally:
            ioc_mod.IOCScanner._read_sample = orig
        self.assertEqual(f.kind, "PHP_IN_DATA_DIR")
        self.assertIn("UNREADABLE-BY-GUARD", f.rules)
        self.assertIsNone(f.detail["sha256"])
        acts = sorted((pr.tier, pr.action) for pr in decide([f], self.cfg) if pr.tier in ("T1", "T2"))
        self.assertEqual(acts, [("T1", "CONTAIN_FILE")], "tanpa SHA tidak ada usulan T2 yang mengikat isi")

    def test_unreadable_directory_becomes_finding(self):
        d = os.path.join(self.up, "rahasia")
        os.makedirs(d)
        orig = ioc_mod.os.scandir

        def scandir(path):
            if path == os.fsencode(d):
                raise PermissionError(13, "ditolak")
            return orig(path)
        try:
            ioc_mod.os.scandir = scandir
            kinds = [x.kind for x in self.scan()]
        finally:
            ioc_mod.os.scandir = orig
        self.assertIn("SCAN_DENIED", kinds)

    def test_deep_tree_does_not_crash_scan(self):
        deep = self.up
        for i in range(80):
            deep = os.path.join(deep, "d")
        os.makedirs(deep)
        _common.write(os.path.join(self.up, "x.php"), WEBSHELL)
        kinds = [x.kind for x in self.scan()]
        self.assertIn("PHP_IN_DATA_DIR", kinds, "temuan lain tetap ada")
        self.assertIn("SCAN_DENIED", kinds, "melewati batas kedalaman dilaporkan")

    def test_file_flood_cannot_hide_php(self):
        self.cfg.max_files_per_run = 100
        for i in range(300):
            _common.write(os.path.join(self.up, "flood", "f%03d.txt" % i), b"x")
        _common.write(os.path.join(self.up, "zz", "late.php"), WEBSHELL)
        kinds = dict((x.target, x.kind) for x in self.scan())
        self.assertEqual(kinds.get(os.path.join(self.up, "zz", "late.php")), "PHP_IN_DATA_DIR")

    def test_redos_resistance(self):
        rules = load_rules(None)
        evil = [b"ev" b"al(" + b" " * 2000000, b"sys" b"tem(" + b" " * 1000000 + b"@" * 1000000,
                (b"A" * 2999 + b"!") * 700, b"$_P" b"OST[" + b"x" * 2000000]
        for data in evil:
            t = time.time()
            rules.content_hits(data, "php", "data")
            self.assertLess(time.time() - t, 5.0, "regex IOC harus linear pada input 2 MB")


class TestRulesFile(Base):
    def test_extend_override_disable(self):
        path = _common.write(self.p("ioc_rules.json"), json.dumps({
            "content": [{"id": "IOC-KAMPUS", "severity": "high", "pattern": "(?i)hacked by", "files": ["php"], "where": ["data"]}],
            "disable": ["WS-LONG-B64"], "benign_sha256": ["a" * 64]}))
        rs = load_rules(path, check_perms=False)
        ids = [r["id"] for r in rs.content]
        self.assertIn("IOC-KAMPUS", ids)
        self.assertNotIn("WS-LONG-B64", ids)
        self.assertIn("a" * 64, rs.benign_sha256)

    def test_invalid_rules_rejected(self):
        bad = _common.write(self.p("bad.json"), json.dumps({"content": [{"id": "X-1", "severity": "high", "pattern": "("}]}))
        with self.assertRaises(RulesError):
            load_rules(bad, check_perms=False)
        with self.assertRaises(RulesError):
            load_rules(_common.write(self.p("bad2.json"), "{bukan json"), check_perms=False)

    @unittest.skipUnless(os.geteuid() == 0, "cek kepemilikan root hanya relevan saat dijalankan sebagai root")
    def test_writable_rules_file_refused(self):
        path = _common.write(self.p("rules.json"), "{}", mode=0o666)
        with self.assertRaises(SecurityError):
            load_rules(path, check_perms=True)


LOG_LINES = [
    '45.33.32.156 - - [04/Nov/2026:07:10:00 +0700] "POST /wp-content/uploads/2026/11/x.php HTTP/1.1" 200 12 "-" "curl/8"',
    '173.245.48.9 - - [04/Nov/2026:07:10:01 +0700] "GET /wp-content/uploads/2026/11/x.php?cmd=id HTTP/1.1" 200 9 "-" "x"',
    '198.51.100.7 - - [04/Nov/2026:07:10:02 +0700] "GET /wso.php HTTP/1.1" 404 0 "-" "scanner"',
    '198.51.100.7 - - [04/Nov/2026:07:10:03 +0700] "GET /alfa.php HTTP/1.1" 404 0 "-" "scanner"',
    '198.51.100.7 - - [04/Nov/2026:07:10:04 +0700] "GET /b3' '74k.php HTTP/1.1" 404 0 "-" "scanner"',
    '198.51.100.8 - - [04/Nov/2026:07:10:05 +0700] "GET /wso.php HTTP/1.1" 404 0 "-" "scanner"',
    '203.0.113.200 - - [04/Nov/2026:07:10:06 +0700] "GET /index.php HTTP/1.1" 200 5 "-" "browser"',
    'baris rusak tanpa format \x1b[31m',
]


class TestAccessLog(Base):
    def scan(self):
        return dict((f.target, f) for f in AccessLogScanner(self.cfg, self.store, self.rules).scan())

    def test_scoring_and_offsets(self):
        log = _common.write(self.p("access.log"), "\n".join(LOG_LINES) + "\n")
        by = self.scan()
        self.assertEqual(by["45.33.32.156"].severity, "critical")
        # GET sukses ke URL webshell bisa dipicu <img src> dari pengunjung sah: tidak langsung critical.
        self.assertEqual(by["173.245.48.9"].severity, "medium")
        self.assertEqual(by["198.51.100.7"].severity, "medium")
        self.assertNotIn("198.51.100.8", by)
        self.assertNotIn("203.0.113.200", by)
        self.assertEqual(self.scan(), {}, "baris lama tidak dibaca ulang")
        with open(log, "a") as f:
            f.write(LOG_LINES[0] + "\n")
            f.write('45.33.32.1')  # baris belum lengkap: jangan dibaca dulu
        self.assertEqual(list(self.scan()), ["45.33.32.156"])
        with open(log, "a") as f:
            f.write('57 - - [04/Nov/2026:07:11:00 +0700] "POST /wp-content/uploads/a.php HTTP/1.1" 200 1 "-" "x"\n')
        self.assertEqual(list(self.scan()), ["45.33.32.157"])

    def test_rotation_reads_remainder_of_old_file(self):
        log = _common.write(self.p("access.log"), LOG_LINES[6] + "\n")
        self.scan()
        with open(log, "a") as f:
            f.write(LOG_LINES[0] + "\n")  # ditulis tepat sebelum rotasi, belum terbaca
        os.rename(log, log + ".1")
        _common.write(log, LOG_LINES[2] + "\n" + LOG_LINES[3] + "\n" + LOG_LINES[4] + "\n")
        by = self.scan()
        self.assertIn("45.33.32.156", by)
        self.assertIn("198.51.100.7", by)

    def test_unreadable_log_is_a_finding(self):
        by = self.scan()
        self.assertEqual(by[self.p("access.log")].kind, "ACCESSLOG_UNREADABLE")

    def test_spoofed_ip_field_rejected(self):
        _common.write(self.p("access.log"), '1.2.3.4, 8.8.8.8 - - [x] "POST /wp-content/uploads/a.php HTTP/1.1" 200 1 "-" "x"\n')
        self.assertEqual(self.scan(), {})


class FakeMySQL(object):
    def __init__(self):
        self.wp = [["1", "admin", "admin@kampus.ac.id", "2019-01-01 00:00:00"],
                   ["7", "wpsvc_sync", "x@evil.test", "2026-11-01 02:00:00"]]
        self.ojs = [["3", "editor", "e@kampus.ac.id", "2020-01-01", "0", "16"],
                    ["3", "editor", "e@kampus.ac.id", "2020-01-01", "0", "1"],
                    ["9", "lama", "l@x", "2019-01-01", "1", "1"]]
        self.fail = False

    def query(self, db, sql):
        if self.fail:
            raise MySQLError("akses ditolak")
        return [list(r) for r in (self.wp if db == "wp_site1" else self.ojs)]


class TestAccounts(Base):
    def test_ioc_baseline_new_and_errors(self):
        my = FakeMySQL()
        aud = AccountAuditor(self.cfg, self.store, self.rules, mysql=my)
        kinds = sorted((f.kind, f.target) for f in aud.audit())
        self.assertIn(("WP_ADMIN_IOC", "wp1/user/7"), kinds)
        self.assertIn(("ACCOUNTS_NO_BASELINE", "wp1"), kinds)
        self.assertNotIn(("OJS_PRIV_NEW", "ojs/user/3"), kinds, "tanpa baseline, akun non-IOC tidak dilaporkan")
        self.assertEqual(accept_accounts(self.store, ["wp1", "ojs"], "uji"), ["wp1", "ojs"])
        my.wp.append(["12", "baru", "b@x", "2026-11-04 06:00:00"])
        my.ojs.append(["15", "mgr_baru", "m@x", "2026-11-04", "0", "16"])
        found = dict((f.target, f) for f in aud.audit())
        self.assertEqual(found["wp1/user/12"].kind, "WP_ADMIN_NEW")
        self.assertEqual(found["ojs/user/15"].kind, "OJS_PRIV_NEW")
        self.assertEqual(found["ojs/user/15"].detail["roles"], ["manager"])
        self.assertNotIn("ojs/user/9", found, "akun yang sudah disabled diabaikan")
        my.fail = True
        self.assertEqual(set(f.kind for f in aud.audit()), {"ACCOUNT_AUDIT_ERROR"})

    def test_batch_parsing(self):
        rows = parse_batch(b"7\twpsvc\\tx\\nline\tNULL\n8\ta\\\\b\tz\n")
        self.assertEqual(rows, [["7", "wpsvc\tx\nline", None], ["8", "a\\b", "z"]])


class TestIntegrity(Base):
    def test_report_mode(self):
        evil = _common.write(self.p("www/site1/wp-content/plugins/akismet/evil.php"), WEBSHELL)
        cfg = _common.make_env(self.tmp, extra="")
        cfg.integrity_mode = "report"
        cfg.integrity_report_glob = self.p("reports", "*.log")
        _common.write(self.p("reports", "cek-20261104.log"),
                      "CHANGED: %s\nNEW: %s\nDELETED: /var/www/html/x/readme.txt\nbaris lain\n" % (
                          self.p("www/site1/index.php"), evil))
        ad = IntegrityAdapter(cfg, self.store, self.rules)
        by = dict((f.kind, f) for f in ad.collect())
        self.assertEqual(by["IOC_IN_CODE"].target, evil)
        self.assertTrue(by["IOC_IN_CODE"].detail["plugin_dir"].endswith("/plugins/akismet"))
        self.assertEqual(by["INTEGRITY_CHANGES"].detail["counts"], {"CHANGED": 1, "NEW": 1, "DELETED": 1})
        self.assertEqual(by["INTEGRITY_CHANGES"].severity, "high")
        self.assertEqual(ad.collect(), [], "laporan yang sama tidak diproses dua kali")
        self.assertEqual(len(self.store.get("integrity:changeset")["sha256"]), 64)


class TestStaiAliFormats(Base):
    def test_web_integrity_cek_v2_output(self):
        evil = _common.write(self.p("www/site1/wp-content/plugins/akismet/x.php"), b"<?" b"php if(hash_" b"equals($k,$_" b"GET['t'])){}")
        cfg = _common.make_env(self.tmp)
        cfg.integrity_mode = "report"
        cfg.integrity_report_glob = self.p("wi", "last.log")
        _common.write(self.p("wi", "last.log"), (
            "\u26a0\ufe0f Web Integrity ALERT kampus 2026-11-04 08:00:00\n"
            "PHP DI FOLDER DATA: /var/www/html/lppm.kampus.ac.id/wp-content/uploads/a.php\n"
            "IOC: %s (baris 1)\n"
            "> %s  /var/www/html/kampus.ac.id/wp-includes/version.php\n"
            "< %s  /var/www/html/kampus.ac.id/wp-includes/version.php\n"
            "(total file berubah: 3)\n") % (evil, "a" * 64, "b" * 64))
        by = dict((f.kind, f) for f in IntegrityAdapter(cfg, self.store, self.rules).collect())
        self.assertIn("IOC-STAI-TOKEN-SHELL", by["IOC_IN_CODE"].rules)
        self.assertEqual(by["INTEGRITY_CHANGES"].detail["counts"], {"SUSPECT": 2, "CHANGED": 1}, "baris < dan > file yang sama dihitung sekali")
        self.assertGreater(by["INTEGRITY_CHANGES"].detail["ioc_hits"], 0, "ada temuan -> tidak boleh usul accept")
        self.assertFalse([p for p in decide(list(by.values()), cfg) if p.action == "ACCEPT_INTEGRITY_BASELINE"])

    def test_internal_email_and_hex_plugin(self):
        class My(object):
            def query(self, db, sql):
                return [["5", "editor2", "x@wordpress-svc.internal", "2026-07-19"]] if db == "wp_site1" else []
        kinds = [(f.kind, f.rules) for f in AccountAuditor(self.cfg, self.store, self.rules, mysql=My()).audit()]
        self.assertIn(("WP_ADMIN_IOC", ["IOC-EMAIL-INTERNAL"]), kinds)
        os.makedirs(self.p("www/site1/wp-content/plugins/security-headers-manager-289fd9"))
        os.makedirs(self.p("www/site1/wp-content/plugins/cache-helper-a1b2c3"))
        names = [os.path.basename(f.target) for f in ioc_mod.IOCScanner(self.cfg, self.store, self.rules).scan()
                 if f.kind == "SUSPICIOUS_PLUGIN"]
        self.assertEqual(sorted(names), ["cache-helper-a1b2c3", "security-headers-manager-289fd9"])

    def test_access_log_glob(self):
        for n in ("a_access.log", "b_access.log", "b_access.log.1", "c_access.log.2.gz"):
            _common.write(self.p("logs", n), "")
        from bodyguard.config import config_from_string
        cfg = config_from_string(_common.BASE_CONFIG.replace("files = %(tmp)s/access.log", "files = %(tmp)s/logs/*_access.log*")
                                 % {"tmp": self.tmp, "mode": "dry-run"})
        self.assertEqual([os.path.basename(x) for x in cfg.access_logs], ["a_access.log", "b_access.log"])


class TestPolicy(Base):
    def test_mapping(self):
        F = Finding
        fs = [F("PHP_IN_DATA_DIR", "critical", "/u/x.php", detail={"sha256": "a" * 64}),
              F("ATTACKER_IP", "critical", "45.33.32.156"), F("ATTACKER_IP", "medium", "198.51.100.7"),
              F("SUSPICIOUS_PLUGIN", "critical", "/p/security-headers-manager-x"),
              F("WP_ADMIN_IOC", "critical", "wp1/user/7", site="wp1", detail={"user_id": 7, "_login": "wpsvc_x"}),
              F("IOC_IN_CODE", "critical", "/p/akismet/a.php", detail={"plugin_dir": "/p/akismet"}),
              F("IOC_IN_CODE", "high", "/t/functions.php"),
              F("INTEGRITY_CHANGES", "medium", "x", detail={"ioc_hits": 0, "changeset": "c" * 64}),
              F("CONTAINED_FILE", "info", "/u/old.php"),
              F("DETECTOR_ERROR", "medium", "accounts")]
        props = decide(fs, self.cfg, lookup_contained=lambda p: "b" * 64 if p == "/u/old.php" else None)
        got = sorted((p.tier, p.action, p.target) for p in props if p.tier != "T0")
        self.assertEqual(got, sorted([
            ("T1", "CONTAIN_FILE", "/u/x.php"), ("T2", "QUARANTINE_FILE", "/u/x.php"),
            ("T1", "BLOCK_IP", "45.33.32.156"), ("T1", "BLOCK_IP", "198.51.100.7"),
            ("T2", "DISABLE_PLUGIN", "/p/security-headers-manager-x"), ("T2", "DISABLE_WP_USER", "wp1/user/7"),
            ("T2", "DISABLE_PLUGIN", "/p/akismet"), ("T2", "ACCEPT_INTEGRITY_BASELINE", "web-integrity-cek"),
            ("T2", "QUARANTINE_FILE", "/u/old.php"), ("T3", "CHECKLIST", "insiden")]))
        ttl = dict((p.target, p.params["ttl"]) for p in props if p.action == "BLOCK_IP")
        self.assertEqual(ttl, {"45.33.32.156": 86400, "198.51.100.7": 3600})
        self.assertFalse(any(p.tier == "T1" and p.target.startswith(("/p/", "/t/")) for p in props),
                         "file kode tidak pernah dikenai T1")


if __name__ == "__main__":
    unittest.main()
