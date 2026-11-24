# -*- coding: utf-8 -*-
"""Uji pintu root bg-root: safe-walk O_NOFOLLOW, bukti-dulu, whitelist sisi root, rate cap, karantina.

Mode 'tanpa hak' (require_root=False) selalu dijalankan. Bila tes dijalankan sebagai root, kelas
TestBgRootPrivileged ikut menguji jalur produksi sesungguhnya (cek kepemilikan + chown root).
Semua operasi terjadi di direktori sementara; cf-guard/collect3/accept memakai skrip palsu; bukti lewat bukti.py asli.
"""

import hashlib
import importlib.machinery
import importlib.util
import io
import json
import os
import stat
import unittest
from unittest import mock

import _common

BG_ROOT = os.path.join(_common.PROJECT, "sbin", "bg-root")
WEBSHELL = b"GIF89a<?" b"php /* 0x" b"Nix */ ev" b"al(base64" b"_decode($_P" b"OST['x'])); ?>"
INC = "INC-20261104-071500-ab12"
NOBODY = 65534


def load_bg_root():
    loader = importlib.machinery.SourceFileLoader("bg_root_mod", BG_ROOT)
    spec = importlib.util.spec_from_loader("bg_root_mod", loader)
    mod = importlib.util.module_from_spec(spec)
    loader.exec_module(mod)
    return mod


class BgRootBase(object):
    privileged = False

    def setUp(self):
        self.mod = load_bg_root()
        t = self.tmp = _common.make_tmpdir()
        self.uploads = os.path.join(t, "www", "site1", "wp-content", "uploads")
        self.plugins = os.path.join(t, "www", "site1", "wp-content", "plugins")
        os.makedirs(os.path.join(self.uploads, "2026", "11"))
        os.makedirs(self.plugins)
        self.evidence = os.path.join(t, "evidence")
        os.mkdir(self.evidence, 0o700)
        self.state = os.path.join(t, "rootstate")
        cf = _common.write_cloudflare(os.path.join(t, "cloudflare-ips.txt"))
        admin = _common.write(os.path.join(t, "admin.txt"), "203.0.113.0/24\n")
        self.cf_log = os.path.join(t, "cfguard.log")
        fake_cf = _common.write_fake_cfguard(os.path.join(t, "fake-cf-guard.py"), self.cf_log)
        self.c3_log = os.path.join(t, "collect3.log")
        fake_c3 = _common.write(os.path.join(t, "collect3_evidence.sh"),
                                '#!/bin/sh\nprintf "%%s|" "$@" >> %s\necho >> %s\nexit 0\n' % (self.c3_log, self.c3_log), 0o755)
        self.accept_log = os.path.join(t, "accept.log")
        fake_accept = _common.write(os.path.join(t, "accept.sh"),
                                    '#!/bin/sh\necho accepted "$@" >> %s\nexit 0\n' % self.accept_log, 0o755)
        self.conf_text = (
            "[contain]\ndata_roots = %s\nevidence_dir = %s\nbukti_bin = %s\nhourly_cap = 3\ncollect3 = %s\n"
            "collect3_args = --case {incident} {path}\nmin_free_bytes = 0\n"
            "[blokir]\ncloudflare_file = %s\nwhitelist_files = %s\nhourly_cap = 4\n"
            "[cfguard]\nbin = %s\n"
            "[plugins]\nplugin_roots = %s\n"
            "[integrity]\naccept_cmd = %s --rebaseline\n"
        ) % (os.path.join(t, "www", "*", "wp-content", "uploads"), self.evidence, _common.BUKTI_PY, fake_c3,
             cf, admin, fake_cf, os.path.join(t, "www", "*", "wp-content", "plugins"), fake_accept)
        self.conf = _common.write(os.path.join(t, "root.conf"), self.conf_text)

    def tearDown(self):
        _common.rmtree(self.tmp)

    def run_bg(self, *argv, **kw):
        buf = io.StringIO()
        code = self.mod.main(list(argv), config_path=kw.get("conf", self.conf), state_dir=self.state,
                             require_root=self.privileged, out=buf, now=kw.get("now"))
        return code, json.loads(buf.getvalue().strip().splitlines()[-1])

    def shell(self, rel="2026/11/x.php", data=WEBSHELL):
        p = _common.write(os.path.join(self.uploads, rel), data, 0o644)
        if self.privileged:
            os.chown(p, NOBODY, NOBODY)  # simulasikan file milik www-data
        return p

    # ---- contain ----------------------------------------------------------------------------
    def test_contain_success_evidence_first(self):
        p = self.shell()
        code, res = self.run_bg("contain", "--incident", INC, "--", p)
        self.assertEqual(code, 0, res)
        st = os.lstat(p)
        self.assertEqual(stat.S_IMODE(st.st_mode), 0)
        if self.privileged:
            self.assertEqual((st.st_uid, st.st_gid), (0, 0), "harus di-chown root agar www-data tak bisa chmod balik")
            self.assertIn("chown %d:%d" % (NOBODY, NOBODY), res["rollback"])
        self.assertEqual(res["original"]["mode"], "0644")
        with open(res["evidence"], "rb") as f:
            self.assertEqual(f.read(), WEBSHELL)
        self.assertEqual(res["sha256"], hashlib.sha256(WEBSHELL).hexdigest())
        metas = [n for n in os.listdir(os.path.dirname(res["evidence"])) if n.endswith(".json")]
        self.assertEqual(len(metas), 1)
        self.assertEqual(res["collect3"]["status"], "ok")
        with open(self.c3_log) as f:
            self.assertEqual(f.read().strip(), "--case|%s|%s|" % (INC, p))

    def test_contain_idempotent_without_consuming_cap(self):
        p = self.shell()
        self.assertEqual(self.run_bg("contain", "--incident", INC, "--", p)[0], 0)
        code, res = self.run_bg("contain", "--incident", INC, "--", p)
        self.assertEqual(code, 0)
        self.assertTrue(res.get("already_contained"))
        with open(os.path.join(self.state, "ratecap.json")) as f:
            self.assertEqual(len(json.load(f)["contain"]), 1)

    def test_refuses_outside_roots_and_traversal(self):
        outside = _common.write(os.path.join(self.tmp, "www", "site1", "index.php"), WEBSHELL)
        for path in (outside, os.path.join(self.uploads, "..", "index.php"),
                     self.uploads + "/2026/../../index.php", "/etc/passwd", "relative/x.php",
                     self.uploads + "//x.php", self.uploads + "/./x.php"):
            code, res = self.run_bg("contain", "--incident", INC, "--", path)
            self.assertEqual(code, 3, (path, res))
        self.assertEqual(stat.S_IMODE(os.lstat(outside).st_mode), 0o644)

    def test_refuses_symlinks_anywhere(self):
        victim = _common.write(os.path.join(self.tmp, "victim.php"), WEBSHELL)
        link = os.path.join(self.uploads, "link.php")
        os.symlink(victim, link)
        code, _ = self.run_bg("contain", "--incident", INC, "--", link)
        self.assertEqual(code, 3)
        os.symlink(self.tmp, os.path.join(self.uploads, "linkdir"))
        code, _ = self.run_bg("contain", "--incident", INC, "--", os.path.join(self.uploads, "linkdir", "victim.php"))
        self.assertEqual(code, 3)
        self.assertEqual(stat.S_IMODE(os.lstat(victim).st_mode), 0o644, "target symlink tidak boleh tersentuh")

    def test_refuses_hardlink(self):
        victim = _common.write(os.path.join(self.uploads, "a.php"), WEBSHELL)
        os.link(victim, os.path.join(self.uploads, "b.php"))
        code, res = self.run_bg("contain", "--incident", INC, "--", victim)
        self.assertEqual(code, 3)
        self.assertIn("hardlink", res["detail"])

    def test_requires_php_marker(self):
        p = _common.write(os.path.join(self.uploads, "notes.php"), b"hanya teks biasa")
        self.assertEqual(self.run_bg("contain", "--incident", INC, "--", p)[0], 3)
        self.assertEqual(stat.S_IMODE(os.lstat(p).st_mode), 0o644)
        weak = _common.write(os.path.join(self.uploads, "pic.jpg"), b"\xff\xd8\xff<" b"?=junk")
        self.assertEqual(self.run_bg("contain", "--incident", INC, "--", weak)[0], 3,
                         "gambar butuh penanda kuat <?" "php, bukan <" "?=")
        poly = _common.write(os.path.join(self.uploads, "poly.jpg"), b"\xff\xd8\xff\xe1Exif<?" b"php sys" b"tem($_" b"GET[1]);")
        self.assertEqual(self.run_bg("contain", "--incident", INC, "--", poly)[0], 0)

    def test_fifo_refused_without_hanging(self):
        fifo = os.path.join(self.uploads, "pipe.php")
        os.mkfifo(fifo)
        code, res = self.run_bg("contain", "--incident", INC, "--", fifo)
        self.assertEqual(code, 3)
        self.assertIn("bukan file biasa", res["detail"])

    def test_rate_cap_root_side(self):
        for i in range(3):
            self.assertEqual(self.run_bg("contain", "--incident", INC, "--", self.shell("s%d.php" % i))[0], 0)
        code, res = self.run_bg("contain", "--incident", INC, "--", self.shell("s9.php"))
        self.assertEqual(code, 4, res)
        self.assertEqual(stat.S_IMODE(os.lstat(os.path.join(self.uploads, "s9.php")).st_mode), 0o644)

    def test_usage_errors(self):
        p = self.shell()
        for argv in (("contain", p), ("contain", "--incident", "INC-1", "--", p),
                     ("contain", "--incident", INC, p, "--"), ("contain", "--incident", INC, "--", p, "extra"),
                     ("hapus-semua",), ()):
            code, _ = self.run_bg(*argv)
            self.assertEqual(code, 2, argv)

    def test_collect3_skipped_for_unsafe_names_but_still_contained(self):
        p = self.shell("x$(id)y.php")
        code, res = self.run_bg("contain", "--incident", INC, "--", p)
        self.assertEqual(code, 0, res)
        self.assertEqual(res["collect3"]["status"], "skipped")
        self.assertFalse(os.path.exists(self.c3_log), "nama berbahaya tidak boleh diteruskan ke skrip shell")
        self.assertEqual(stat.S_IMODE(os.lstat(p).st_mode), 0)

    # ---- blokir IP lewat cf-guard (satu jalur blokir) ------------------------------------------
    def ipset_calls(self):
        return _common.calls(self.cf_log)

    def test_ipset_whitelist_and_validation(self):
        cases = [("173.245.48.5", "3600", 3), ("2606:4700::1", "3600", 3), ("::ffff:104.16.0.1", "3600", 3),
                 ("203.0.113.7", "3600", 3), ("127.0.0.1", "3600", 3), ("10.1.2.3", "3600", 3),
                 ("8.8.8.8", "59", 3), ("8.8.8.8", "86401", 3), ("8.8.8.8", "1h", 2), ("8.8.8.8;id", "3600", 3)]
        for ip, ttl, want in cases:
            code, res = self.run_bg("cf-block", ip, ttl)
            self.assertEqual(code, want, (ip, ttl, res))
        self.assertEqual(self.ipset_calls(), [], "tidak satu pun boleh sampai ke cf-guard")

    def test_ipset_success_v4_v6(self):
        code, res = self.run_bg("cf-block", "45.33.32.156", "21600")
        self.assertEqual(code, 0, res)
        code6, res6 = self.run_bg("cf-block", "2a01:4f8::1", "3600")
        self.assertEqual(code6, 0, res6)
        self.assertEqual(self.ipset_calls(), [
            "block 45.33.32.156 --ttl 21600 --oleh soc-ir", "block 2a01:4f8::1 --ttl 3600 --oleh soc-ir"])
        self.assertEqual(res["rollback"], "cf-guard.py remove 45.33.32.156")

    def test_cf_approve_only_valid_id(self):
        code, res = self.run_bg("cf-approve", "--incident", INC, "--id", "0123456789ab")
        self.assertEqual(code, 0, res)
        self.assertEqual(res["status"], "diterapkan")
        for bad in ("0123456789AB", "0123", "0123456789ab;id", "../../etc"):
            code, res = self.run_bg("cf-approve", "--incident", INC, "--id", bad)
            self.assertEqual(code, 2, (bad, res))
        self.assertEqual(self.ipset_calls(), ["approve 0123456789ab --oleh gerbang:%s" % INC])

    def test_ipset_fail_closed_without_cloudflare(self):
        empty = _common.write(os.path.join(self.tmp, "cf-empty.txt"), "# kosong\n")
        conf2 = _common.write(os.path.join(self.tmp, "root2.conf"),
                              self.conf_text.replace(os.path.join(self.tmp, "cloudflare-ips.txt"), empty))
        code, res = self.run_bg("cf-block", "45.33.32.156", "3600", conf=conf2)
        self.assertEqual(code, 3)
        self.assertIn("Cloudflare", res["detail"])
        self.assertEqual(self.ipset_calls(), [])

    # ---- karantina, plugin, integrity -----------------------------------------------------------
    def test_quarantine_binds_sha_and_renames_without_php(self):
        p = self.shell("2026/11/evil.php")
        sha = hashlib.sha256(WEBSHELL).hexdigest()
        code, res = self.run_bg("quarantine", "--incident", INC, "--expect-sha256", "0" * 64, "--", p)
        self.assertEqual(code, 3, "isi berubah sejak disetujui -> tolak")
        self.assertTrue(os.path.exists(p))
        code, res = self.run_bg("quarantine", "--incident", INC, "--expect-sha256", sha, "--", p)
        self.assertEqual(code, 0, res)
        self.assertFalse(os.path.exists(p))
        new = res["quarantined_as"]
        self.assertNotIn(".php", os.path.basename(new))
        self.assertEqual(stat.S_IMODE(os.lstat(new).st_mode), 0)
        self.assertTrue(os.path.exists(res["evidence"]))
        code, _ = self.run_bg("quarantine", "--incident", INC, "--expect-sha256", sha, "--", new)
        self.assertEqual(code, 3, "file yang sudah dikarantina tidak diproses ulang")

    def test_plugin_disable(self):
        plug = os.path.join(self.plugins, "security-headers-manager-x9k2")
        os.makedirs(plug)
        _common.write(os.path.join(plug, "plugin.php"), WEBSHELL)
        code, res = self.run_bg("plugin-disable", "--incident", INC, "--", plug)
        self.assertEqual(code, 0, res)
        self.assertFalse(os.path.exists(plug))
        self.assertTrue(os.path.isdir(res["disabled_as"]))
        self.assertTrue(os.path.exists(os.path.join(res["disabled_as"], "plugin.php")), "isi plugin tidak dihapus")
        nested = os.path.join(self.plugins, "akismet")
        os.makedirs(os.path.join(nested, "sub"))
        self.assertEqual(self.run_bg("plugin-disable", "--incident", INC, "--", os.path.join(nested, "sub"))[0], 3)
        os.symlink(self.tmp, os.path.join(self.plugins, "linked"))
        self.assertEqual(self.run_bg("plugin-disable", "--incident", INC, "--", os.path.join(self.plugins, "linked"))[0], 3)
        self.assertEqual(self.run_bg("plugin-disable", "--incident", INC, "--", os.path.join(self.plugins, "tidak-ada"))[0], 3)

    def test_integrity_accept_runs_fixed_command_only(self):
        code, res = self.run_bg("integrity-accept", "--incident", INC)
        self.assertEqual(code, 0, res)
        with open(self.accept_log) as f:
            self.assertEqual(f.read().strip(), "accepted --rebaseline")
        self.assertEqual(self.run_bg("integrity-accept", "--incident", INC, "--extra")[0], 2)

    def test_selftest_read_only(self):
        code, res = self.run_bg("selftest")
        self.assertEqual(code, 0, res)
        self.assertEqual(len(res["data_roots"]), 1)
        self.assertGreater(res["whitelist_entries"], 20)
        self.assertFalse(os.path.exists(self.state), "selftest tidak boleh membuat/menulis state")

    def test_non_root_refused_in_production_mode(self):
        p = self.shell()
        buf = io.StringIO()
        with mock.patch.object(self.mod.os, "geteuid", return_value=1000):
            code = self.mod.main(["contain", "--incident", INC, "--", p], config_path=self.conf,
                                 state_dir=self.state, require_root=True, out=buf)
        self.assertEqual(code, 3)
        self.assertEqual(stat.S_IMODE(os.lstat(p).st_mode), 0o644)


class TestBgRootUnprivileged(BgRootBase, unittest.TestCase):
    privileged = False


@unittest.skipUnless(os.geteuid() == 0, "jalur produksi (chown root, cek kepemilikan) hanya bisa diuji sebagai root")
class TestBgRootPrivileged(BgRootBase, unittest.TestCase):
    privileged = True

    def test_config_must_be_root_owned_and_not_writable(self):
        os.chown(self.conf, NOBODY, NOBODY)
        code, res = self.run_bg("selftest")
        self.assertEqual(code, 3)
        os.chown(self.conf, 0, 0)
        os.chmod(self.conf, 0o666)
        code, res = self.run_bg("selftest")
        self.assertEqual(code, 3)

    def test_untrusted_ipset_binary_refused(self):
        os.chown(os.path.join(self.tmp, "fake-cf-guard.py"), NOBODY, NOBODY)
        code, res = self.run_bg("cf-block", "45.33.32.156", "3600")
        self.assertEqual(code, 3)
        self.assertEqual(self.ipset_calls(), [])


if __name__ == "__main__":
    unittest.main()
