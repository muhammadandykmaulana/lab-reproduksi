# -*- coding: utf-8 -*-
import os
import unittest

import _common
from bodyguard.whitelist import Whitelist, WhitelistError


class TestWhitelist(unittest.TestCase):
    def setUp(self):
        self.tmp = _common.make_tmpdir()
        self.cf = _common.write_cloudflare(os.path.join(self.tmp, "cloudflare-ips.txt"))
        self.admin = _common.write(os.path.join(self.tmp, "admin.txt"), "# kantor\n103.10.10.0/24\n2001:db8:abcd::/48\n")
        self.wl = Whitelist.from_files([("cloudflare", self.cf), ("admin", self.admin)], extra=["45.1.2.3/32"])

    def tearDown(self):
        _common.rmtree(self.tmp)

    def assertProtected(self, ip, contains=None):
        ok, reason = self.wl.check(ip)
        self.assertFalse(ok, "%s seharusnya dilindungi" % ip)
        if contains:
            self.assertIn(contains, reason)

    def test_cloudflare_never_blocked(self):
        self.assertProtected("173.245.48.5", "whitelist:cloudflare")
        self.assertProtected("104.16.1.1", "whitelist:cloudflare")
        self.assertProtected("2606:4700::1111", "whitelist:cloudflare")
        self.assertProtected("::ffff:173.245.48.5", "whitelist:cloudflare")  # IPv4-mapped

    def test_admin_and_extra(self):
        self.assertProtected("103.10.10.20", "whitelist:admin")
        self.assertProtected("45.1.2.3", "whitelist:config")

    def test_non_global_never_blocked(self):
        for ip in ("127.0.0.1", "10.0.0.5", "192.168.1.1", "172.16.0.9", "100.64.1.1", "169.254.1.1",
                   "::1", "fe80::1", "fc00::5", "0.0.0.0", "224.0.0.1", "255.255.255.255"):
            self.assertProtected(ip)

    def test_global_attacker_blockable(self):
        for ip in ("45.33.32.156", "8.8.8.8", "2a01:4f8::1"):
            ok, reason = self.wl.check(ip)
            self.assertTrue(ok, "%s: %s" % (ip, reason))

    def test_garbage_rejected(self):
        for bad in ("", "not-an-ip", "1.2.3.4; rm -rf /", "1.2.3.4 ", "999.1.1.1", "fe80::1%eth0", "1.2.3.4\n"):
            ok, _ = self.wl.check(bad if bad != "1.2.3.4 " else "1.2.3.4 x")
            self.assertFalse(ok, repr(bad))

    def test_fail_closed_on_missing_or_empty_or_invalid(self):
        with self.assertRaises(WhitelistError):
            Whitelist.from_files([("cloudflare", os.path.join(self.tmp, "nope.txt"))])
        empty = _common.write(os.path.join(self.tmp, "empty.txt"), "# kosong\n")
        with self.assertRaises(WhitelistError):
            Whitelist.from_files([("cloudflare", empty)])
        bad = _common.write(os.path.join(self.tmp, "bad.txt"), "173.245.48.0/20\nbukan-cidr\n")
        with self.assertRaises(WhitelistError):
            Whitelist.from_files([("cloudflare", bad)])


if __name__ == "__main__":
    unittest.main()
