# -*- coding: utf-8 -*-
"""Uji eksekutor T2 dengan runner palsu (tanpa sudo/mysql sungguhan)."""

import json
import os
import unittest

import _common
from bodyguard.store import Store
from bodyguard.t2 import T2Executor

INC = "INC-20261104-071500-ab12"


class FakeRunner(object):
    def __init__(self, cfg):
        self.cfg = cfg
        self.calls = []
        self.db = {"wp_login": "wpsvc_backdoor", "caps": "a:1:{s:13:\"administrator\";b:1;}", "level": "10",
                   "ojs_user": "evil_mgr", "ojs_disabled": "0"}

    def __call__(self, argv, timeout=60, input_bytes=None, env=None):
        argv = list(argv)
        self.calls.append(argv)
        if argv[0] == self.cfg.sudo:
            return 0, (json.dumps({"ok": True, "quarantined_as": "/q", "disabled_as": "/d", "rollback": "mv"}) + "\n").encode(), b""
        sql = argv[-1][len("--execute="):]
        if sql.startswith("SELECT user_login"):
            return 0, (self.db["wp_login"] + "\n").encode(), b""
        if sql.startswith("SELECT meta_key, HEX"):
            return 0, ("wp_capabilities\t%s\nwp_user_level\t%s\n" % (
                self.db["caps"].encode().hex().upper(), self.db["level"].encode().hex().upper())).encode(), b""
        if sql.startswith("UPDATE `wp_usermeta`"):
            self.db["caps"] = "a:0:{}"
            return 0, b"", b""
        if sql.startswith("SELECT meta_value"):
            return 0, (self.db["caps"] + "\n").encode(), b""
        if sql.startswith("SELECT username"):
            return 0, ("%s\t%s\t\n" % (self.db["ojs_user"], self.db["ojs_disabled"])).encode(), b""
        if sql.startswith("UPDATE users"):
            self.db["ojs_disabled"] = "1"
            return 0, b"", b""
        if sql.startswith("SELECT disabled"):
            return 0, (self.db["ojs_disabled"] + "\n").encode(), b""
        return 1, b"", b"SQL tak terduga"


class TestT2Executor(unittest.TestCase):
    def setUp(self):
        self.tmp = _common.make_tmpdir()
        self.cfg = _common.make_env(self.tmp)
        self.store = Store(os.path.join(self.tmp, "state", "state.db"))
        self.run = FakeRunner(self.cfg)
        self.ex = T2Executor(self.cfg, self.store, runner=self.run)

    def tearDown(self):
        self.store.close()
        _common.rmtree(self.tmp)

    def act(self, kind, params):
        return self.ex.execute("REQ-000000000001", {"kind": kind, "incident": INC, "params": params})

    def test_wp_user_disable_and_rollback(self):
        res = self.act("DISABLE_WP_USER", {"site": "wp1", "user_id": 7, "user_login": "wpsvc_backdoor"})
        self.assertTrue(res["ok"], res)
        self.assertIn("UNHEX('", res["rollback"])
        sqls = [c[-1] for c in self.run.calls]
        self.assertTrue(any("meta_value='a:0:{}'" in s and "user_id=7" in s for s in sqls))
        self.assertTrue(all(c[1].startswith("--defaults-extra-file=") for c in self.run.calls),
                        "kredensial wajib dari defaults file, opsi pertama")
        self.assertFalse(any("wpsvc_backdoor" in s for s in sqls), "teks dari DB/penyerang tidak masuk SQL")

    def test_wp_user_login_mismatch_aborts(self):
        res = self.act("DISABLE_WP_USER", {"site": "wp1", "user_id": 7, "user_login": "admin_sah"})
        self.assertFalse(res["ok"])
        self.assertFalse(any("UPDATE" in c[-1] for c in self.run.calls))

    def test_bad_inputs_rejected_before_any_command(self):
        for params in ({"site": "wp1", "user_id": "7 OR 1=1", "user_login": "x"},
                       {"site": "wp1", "user_id": True, "user_login": "x"},
                       {"site": "tidak-ada", "user_id": 7, "user_login": "x"},
                       {"site": "ojs", "user_id": 7, "user_login": "x"}):
            self.assertFalse(self.act("DISABLE_WP_USER", params)["ok"], params)
        self.assertFalse(self.ex.execute("REQ-1", {"kind": "DISABLE_WP_USER", "incident": "INC-x", "params": {}})["ok"])
        self.assertFalse(self.act("HAPUS_SEMUA", {})["ok"])
        self.assertEqual(self.run.calls, [])

    def test_ojs_user_disable(self):
        res = self.act("DISABLE_OJS_USER", {"site": "ojs", "user_id": 42, "username": "evil_mgr"})
        self.assertTrue(res["ok"], res)
        self.assertIn("UPDATE users SET disabled=0, disabled_reason=NULL WHERE user_id=42;", res["rollback"])
        self.assertTrue(any("disabled_reason='bodyguard %s'" % INC in c[-1] for c in self.run.calls))

    def test_quarantine_path_validation(self):
        res = self.act("QUARANTINE_FILE", {"path": "/etc/passwd", "sha256": "a" * 64})
        self.assertFalse(res["ok"])
        self.assertEqual(self.run.calls, [])
        p = os.path.join(self.tmp, "www", "site1", "wp-content", "uploads", "2026", "11", "x.php")
        res = self.act("QUARANTINE_FILE", {"path": p, "sha256": "b" * 64})
        self.assertTrue(res["ok"], res)
        self.assertEqual(self.run.calls[-1], [self.cfg.sudo, "-n", self.cfg.bg_root, "quarantine", "--incident", INC,
                                             "--expect-sha256", "b" * 64, "--", os.fsencode(p)])

    def test_plugin_must_be_top_level(self):
        root = os.path.join(self.tmp, "www", "site1", "wp-content", "plugins")
        os.makedirs(os.path.join(root, "security-headers-manager-x1", "inc"))
        self.assertFalse(self.act("DISABLE_PLUGIN", {"path": os.path.join(root, "security-headers-manager-x1", "inc")})["ok"])
        res = self.act("DISABLE_PLUGIN", {"path": os.path.join(root, "security-headers-manager-x1")})
        self.assertTrue(res["ok"], res)
        self.assertEqual(self.run.calls[-1][3], "plugin-disable")

    def test_accept_baseline_requires_unchanged_changeset(self):
        self.store.set("integrity:changeset", {"sha256": "c" * 64})
        self.assertFalse(self.act("ACCEPT_INTEGRITY_BASELINE", {"changeset": "d" * 64})["ok"])
        self.assertEqual(self.run.calls, [])
        self.assertTrue(self.act("ACCEPT_INTEGRITY_BASELINE", {"changeset": "c" * 64})["ok"])


    def test_cf_approve_satu_gerbang(self):
        res = self.act("CF_APPROVE", {"pending_id": "0123456789ab", "jenis": "ip", "nilai": "198.51.100.7"})
        self.assertTrue(res["ok"], res)
        self.assertEqual(self.run.calls[-1][-5:], ["cf-approve", "--incident", INC, "--id", "0123456789ab"])
        n = len(self.run.calls)
        for bad in ({"pending_id": "../x", "jenis": "ip"}, {"pending_id": "0123456789ab", "jenis": "hapus"}):
            self.assertFalse(self.act("CF_APPROVE", bad)["ok"])
        self.assertEqual(len(self.run.calls), n, "usulan tidak valid tidak boleh sampai ke bg-root")

if __name__ == "__main__":
    unittest.main()
