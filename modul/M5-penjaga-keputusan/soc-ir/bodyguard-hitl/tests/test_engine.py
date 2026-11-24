# -*- coding: utf-8 -*-
"""Uji integrasi siklus penuh: detektor -> policy -> T1 (lewat bg-root ASLI, mode uji) -> antre T2 -> T3.

`sudo -n bg-root ...` dialihkan ke modul sbin/bg-root sungguhan (require_root=False) dengan root.conf uji,
sehingga jalur guard -> pintu root diuji utuh tanpa sudo.
"""

import io
import json
import os
import stat
import unittest

import _common
from bodyguard.detectors.rules import load_rules
from bodyguard.engine import Engine, effective_mode
from bodyguard.notifier import Notifier
from bodyguard.store import Store

WEBSHELL = b"<?" b"php /* 0x" b"Nix */ ev" b"al(base64" b"_decode($_P" b"OST['k'])); ?>"
ATTACK_LOG = (
    '45.33.32.156 - - [04/Nov/2026:07:10:00 +0700] "POST /wp-content/uploads/2026/11/x.php HTTP/1.1" 200 12 "-" "x"\n'
    '173.245.48.9 - - [04/Nov/2026:07:10:01 +0700] "POST /wp-content/uploads/2026/11/x.php HTTP/1.1" 200 12 "-" "x"\n'
)


class SudoBridge(object):
    def __init__(self, cfg, tmp):
        self.cfg = cfg
        self.mod = _common.load_bg_root()
        self.calls = []
        self.state = os.path.join(tmp, "rootstate")
        self.cf_log = os.path.join(tmp, "cfguard.log")
        fake_cf = _common.write_fake_cfguard(os.path.join(tmp, "fake-cf-guard.py"), self.cf_log)
        evidence = os.path.join(tmp, "evidence")
        os.mkdir(evidence, 0o700)
        self.conf = _common.write(os.path.join(tmp, "root.conf"), (
            "[contain]\ndata_roots = %s %s\nevidence_dir = %s\nbukti_bin = %s\nhourly_cap = 50\nmin_free_bytes = 0\n"
            "[blokir]\ncloudflare_file = %s\nwhitelist_files = %s\n[cfguard]\nbin = %s\n"
            "[plugins]\nplugin_roots = %s\n") % (
            os.path.join(tmp, "www", "*", "wp-content", "uploads"), os.path.join(tmp, "www", "ojs", "public"),
            evidence, _common.BUKTI_PY, cfg.cloudflare_file, cfg.admin_subnets_file, fake_cf,
            os.path.join(tmp, "www", "*", "wp-content", "plugins")))

    def __call__(self, argv, timeout=60, input_bytes=None, env=None):
        argv = list(argv)
        self.calls.append(argv)
        if argv[:3] != [self.cfg.sudo, "-n", self.cfg.bg_root]:
            raise AssertionError("perintah tak terduga: %r" % (argv,))
        buf = io.StringIO()
        code = self.mod.main(argv[3:], config_path=self.conf, state_dir=self.state, require_root=False, out=buf)
        return code, buf.getvalue().encode("ascii"), b""

    def ipset_calls(self):
        return [c for c in _common.calls(self.cf_log) if c.startswith("block")]


class FakeMySQL(object):
    def query(self, db, sql):
        if db == "wp_site1":
            return [["1", "admin", "a@kampus.ac.id", "2019-01-01"], ["7", "wpsvc_sync", "x@evil.test", "2026-11-01"]]
        return []


class TestEngine(unittest.TestCase):
    def setUp(self):
        self.tmp = _common.make_tmpdir()
        self.clock = _common.FakeClock()
        self.up = os.path.join(self.tmp, "www", "site1", "wp-content", "uploads", "2026", "11")

    def tearDown(self):
        if getattr(self, "store", None) is not None:
            self.store.close()
        _common.rmtree(self.tmp)

    def build(self, mode, shells=1):
        self.cfg = _common.make_env(self.tmp, mode=mode)
        self.store = Store(os.path.join(self.tmp, "state", "state.db"), clock=self.clock)
        self.bridge = SudoBridge(self.cfg, self.tmp)
        for i in range(shells):
            _common.write(os.path.join(self.up, "x.php" if i == 0 else "s%02d.php" % i), WEBSHELL + (b"//%d" % i))
        _common.write(os.path.join(self.up, "photo.jpg"), b"\xff\xd8\xff\xe1Exif<?" b"php sys" b"tem($_" b"GET[1]); ?>")
        os.makedirs(os.path.join(self.tmp, "www", "site1", "wp-content", "plugins", "security-headers-manager-q1"))
        _common.write(os.path.join(self.tmp, "access.log"), ATTACK_LOG)
        self.notifier = Notifier("log", self.store, clock=self.clock)
        return Engine(self.cfg, self.store, self.notifier, effective_mode(self.cfg.mode), load_rules(None),
                      runner=self.bridge, clock=self.clock, mysql_ro=FakeMySQL())

    def mode_of(self, name):
        return stat.S_IMODE(os.lstat(os.path.join(self.up, name)).st_mode)

    def approvals(self):
        return [(r["action_kind"], r["status"]) for r in self.store.conn.execute("SELECT * FROM approvals")]

    def test_dry_run_touches_nothing(self):
        eng = self.build("dry-run")
        s = eng.run_cycle()
        self.assertEqual(self.bridge.calls, [], "dry-run tidak boleh memanggil sudo sama sekali")
        self.assertEqual(self.mode_of("x.php"), 0o644)
        statuses = sorted((r["kind"], r["status"]) for r in s["t1"])
        self.assertIn(("CONTAIN_FILE", "DRYRUN"), statuses)
        self.assertIn(("BLOCK_IP", "DRYRUN"), statuses)
        self.assertIn(("BLOCK_IP", "SKIPPED_WHITELIST"), statuses)
        self.assertTrue(all(st == "DRYRUN" for _k, st in self.approvals()))
        alert = self.notifier.sent[-1]["text"]
        self.assertIn("DRY-RUN", alert)
        self.assertIn("real_ip", alert, "petunjuk Cloudflare/real_ip harus muncul")
        self.assertIsNone(self.store.get("breaker:live:tripped"), "simulasi tidak menyentuh breaker live")
        self.assertEqual(self.store.conn.execute("SELECT COUNT(*) FROM breaker_events WHERE ns='live'").fetchone()[0], 0)

    def test_cli_dry_run_overrides_enforce_but_not_observe(self):
        self.assertEqual(effective_mode("enforce", True), "dry-run")
        self.assertEqual(effective_mode("observe", False), "observe")
        self.assertEqual(effective_mode("observe", True), "observe")
        self.assertEqual(effective_mode("dry-run", False), "dry-run")

    def test_enforce_full_cycle(self):
        eng = self.build("enforce")
        s = eng.run_cycle()
        self.assertEqual(self.mode_of("x.php"), 0, "webshell harus terkunci")
        self.assertEqual(self.mode_of("photo.jpg"), 0, "polyglot harus terkunci")
        self.assertEqual(self.bridge.ipset_calls(), ["block 45.33.32.156 --ttl 86400 --oleh soc-ir"],
                         "hanya IP penyerang global yang diblokir; IP Cloudflare tidak pernah")
        kinds = sorted(self.approvals())
        self.assertIn(("QUARANTINE_FILE", "QUEUED"), kinds)
        self.assertIn(("DISABLE_PLUGIN", "QUEUED"), kinds)
        self.assertIn(("DISABLE_WP_USER", "QUEUED"), kinds)
        self.assertTrue(s["checklist"] and os.path.exists(s["checklist"]))
        with open(s["checklist"]) as f:
            md = f.read()
        self.assertIn("Rotasi rahasia", md)
        self.assertIn("Plugin samaran", md)
        evidence = os.listdir(os.path.join(self.tmp, "evidence"))
        self.assertEqual(len(evidence), 1, "satu folder bukti per insiden")
        # Siklus kedua: file sudah terkunci -> tidak ada aksi T1 ganda, tidak ada permintaan T2 ganda.
        n_before = len(self.approvals())
        self.clock.advance(600)
        s2 = eng.run_cycle()
        self.assertEqual([r for r in s2["t1"] if r["status"] not in ("DUPLICATE", "SKIPPED_WHITELIST")], [])
        self.assertEqual(len(self.approvals()), n_before)
        self.assertEqual(s2["new_findings"], 0, "alert tidak diulang untuk temuan yang sama")

    def test_breaker_trips_on_sixth_file_and_alerts_once(self):
        eng = self.build("enforce", shells=7)
        _common.write(os.path.join(self.tmp, "access.log"), "")
        s = eng.run_cycle()
        contain = [r["status"] for r in s["t1"] if r["kind"] == "CONTAIN_FILE"]
        self.assertEqual(contain.count("CONTAINED"), 5)
        self.assertEqual(contain.count("SKIPPED"), 3, "file ke-6 dst. tidak disentuh (7 webshell + 1 polyglot)")
        locked = sum(1 for n in os.listdir(self.up) if self.mode_of(n) == 0)
        self.assertEqual(locked, 5)
        urgent = [m for m in self.notifier.sent if m["urgent"] and "CIRCUIT BREAKER TRIP" in m["text"]]
        self.assertEqual(len(urgent), 1, "alert darurat tepat sekali")
        self.assertIsNotNone(self.store.get("breaker:live:tripped"))
        # Masih trip di siklus berikut (latched) walau 2 jam berlalu: tidak ada chmod baru.
        self.clock.advance(7200)
        s2 = eng.run_cycle()
        self.assertFalse(any(r["status"] == "CONTAINED" for r in s2["t1"]))

    def test_failed_t1_not_retried_every_cycle(self):
        eng = self.build("enforce")
        calls = []

        def broken(argv, timeout=60, input_bytes=None, env=None):
            calls.append(list(argv))
            return 1, b"", b"sudo: a password is required"
        eng.runner = broken
        s1 = eng.run_cycle()
        self.assertIn("FAILED", [r["status"] for r in s1["t1"]])
        n = len(calls)
        self.clock.advance(600)
        eng.run_cycle()
        self.assertEqual(len(calls), n, "kegagalan yang sama tidak dicoba ulang dalam 1 jam")
        self.clock.advance(3600)
        eng.run_cycle()
        self.assertGreater(len(calls), n, "dicoba lagi setelah 1 jam")
        self.assertIsNone(self.store.get("breaker:live:tripped"), "kegagalan berulang tidak menguras breaker")

    def test_observe_mode_records_only(self):
        eng = self.build("observe")
        s = eng.run_cycle()
        self.assertEqual(self.bridge.calls, [])
        self.assertTrue(all(r["status"] in ("OBSERVED", "SKIPPED_WHITELIST") for r in s["t1"]))
        self.assertTrue(all(st == "OBSERVED" for _k, st in self.approvals()))

    def test_detector_crash_becomes_finding_not_outage(self):
        eng = self.build("enforce")

        class Boom(object):
            def query(self, db, sql):
                raise RuntimeError("koneksi putus")

        eng.mysql_ro = Boom()
        s = eng.run_cycle()
        self.assertEqual(self.mode_of("x.php"), 0, "detektor lain tetap jalan")
        rows = self.store.conn.execute("SELECT site FROM findings WHERE kind='ACCOUNT_AUDIT_ERROR'").fetchall()
        self.assertEqual(sorted(r[0] for r in rows), ["ojs", "wp1"], "satu galat per situs, bukan crash")


if __name__ == "__main__":
    unittest.main()
