# -*- coding: utf-8 -*-
"""Higiene repositori: kode ASCII murni (anti Trojan Source), sintaks & API Python 3.6, contoh config valid,
sudoers lolos visudo, dan daftar Cloudflare konsisten di semua tempat."""

import ast
import glob
import json
import os
import re
import shutil
import subprocess
import sys
import unittest

import _common
from bodyguard.config import config_from_string
from bodyguard.detectors.rules import load_rules

P = _common.PROJECT
PY_SOURCES = (glob.glob(os.path.join(P, "lib", "bodyguard", "**", "*.py"), recursive=True)
              + [os.path.join(P, "sbin", "bg-root"), os.path.join(P, "bin", "bodyguard"),
                 os.path.join(P, "bin", "gatekeeper_bot.py"), os.path.join(P, "tools", "gen_grants.py")]
              + glob.glob(os.path.join(P, "tests", "*.py")))
ALL_TEXT = PY_SOURCES + glob.glob(os.path.join(P, "tools", "*.sh")) + glob.glob(os.path.join(P, "etc", "**", "*"), recursive=True)
BANNED_API = [r"capture_output\s*=", r"\btext\s*=\s*True", r"@dataclass", r"fromisoformat", r"\btime_ns\(",
              r"nullcontext", r"\.isascii\(", r"removeprefix", r"removesuffix", r"(?m)^\s*(?:import|from)\s+(?:zoneinfo|dataclasses)\b", r"cached_property",
              r"shlex\.join", r"add_subparsers\([^)]*required", r"from __future__ import annotations", r":=",
              r"ON CONFLICT"]
BIDI = re.compile("[\u202a-\u202e\u2066-\u2069\u200b-\u200f\u2028\u2029\ufeff]")


def _read(path):
    with open(path, "r", encoding="utf-8") as f:
        return f.read()


class TestHygiene(unittest.TestCase):
    def test_sources_ascii_only(self):
        for path in PY_SOURCES:
            bad = [i for i, ch in enumerate(_read(path)) if ord(ch) > 127]
            self.assertEqual(bad, [], "karakter non-ASCII di %s (pakai escape \\uXXXX)" % path)

    def test_no_invisible_or_bidi_chars_anywhere(self):
        for path in ALL_TEXT:
            if os.path.isfile(path):
                self.assertIsNone(BIDI.search(_read(path)), "karakter bidi/zero-width di %s" % path)

    @unittest.skipUnless(sys.version_info >= (3, 8), "feature_version butuh Python >= 3.8 untuk memeriksa")
    def test_python36_syntax(self):
        for path in PY_SOURCES:
            ast.parse(_read(path), filename=path, feature_version=(3, 6))

    def test_no_post36_apis(self):
        for path in PY_SOURCES:
            if path.endswith("test_repo_hygiene.py"):
                continue
            src = _read(path)
            for pat in BANNED_API:
                self.assertIsNone(re.search(pat, src), "API Python > 3.6 / SQLite baru (%s) di %s" % (pat, path))

    def test_example_configs_parse(self):
        cfg = config_from_string(_read(os.path.join(P, "etc", "bodyguard.conf.example")))
        self.assertEqual(cfg.mode, "dry-run", "default contoh harus dry-run")
        self.assertEqual(cfg.limits, {"ip_block": 20, "chmod": 5})
        self.assertEqual(cfg.t2_ttl, 1800)
        import configparser
        cp = configparser.ConfigParser(interpolation=None, strict=True)
        cp.read_string(_read(os.path.join(P, "etc", "root.conf.example")))
        self.assertIn("data_roots", cp["contain"])
        rules = load_rules(os.path.join(P, "etc", "ioc_rules.json.example"), check_perms=False)
        self.assertIn("IOC-HACKED-BY", [r["id"] for r in rules.content])
        json.loads(_read(os.path.join(P, "etc", "ioc_rules.json.example")))

    @unittest.skipUnless(os.path.isdir(os.path.join(P, "server", "kampus")), "konfigurasi khusus server tidak disertakan di lab")
    def test_server_specific_configs(self):
        cfg = config_from_string(_read(os.path.join(P, "server", "kampus", "bodyguard.conf")))
        self.assertEqual(cfg.mode, "dry-run")
        self.assertEqual(sorted(s.name for s in cfg.sites), ["baak", "jurnal", "lpm", "lppm", "publishing", "stai"])
        import configparser
        cp = configparser.ConfigParser(interpolation=None, strict=True)
        cp.read_string(_read(os.path.join(P, "server", "kampus", "root.conf")))
        guard_side = _read(os.path.join(P, "server", "kampus", "bodyguard.conf")).split("data_dirs =")[1].split("code_dirs")[0].split()
        self.assertEqual(guard_side, cp.get("contain", "data_roots").split(), "data_dirs harus sama dengan data_roots")

    @unittest.skipUnless(shutil.which("visudo") or os.path.exists("/usr/sbin/visudo"), "visudo tidak tersedia")
    def test_sudoers_valid_and_minimal(self):
        path = os.path.join(P, "etc", "sudoers.d", "guard-bodyguard")
        visudo = shutil.which("visudo") or "/usr/sbin/visudo"
        p = subprocess.run([visudo, "-cf", path], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        self.assertEqual(p.returncode, 0, p.stdout + p.stderr)
        rules = [l for l in _read(path).splitlines() if l.strip() and not l.lstrip().startswith("#")]
        for line in rules:
            for word in ("ALL=(ALL)", "/bin/chmod", "/usr/bin/chmod", "/usr/sbin/ipset", "/bin/sh", "/bin/bash", "!/"):
                self.assertNotIn(word, line, "sudoers tidak boleh memberi %s" % word)
        self.assertNotIn(".", os.path.basename(path), "sudo mengabaikan nama file berisi titik")

    def test_cloudflare_lists_consistent(self):
        pkg = sorted(l.strip() for l in _read(os.path.join(P, "etc", "cloudflare-ips.txt")).splitlines()
                     if l.strip() and not l.startswith("#"))
        nginx = sorted(re.findall(r"set_real_ip_from ([0-9a-f:./]+);", _read(os.path.join(P, "etc", "nginx-realip-cloudflare.conf.example"))))
        self.assertEqual(pkg, nginx)
        self.assertEqual(pkg, sorted(_common.CLOUDFLARE_V4 + _common.CLOUDFLARE_V6))


if __name__ == "__main__":
    unittest.main()
