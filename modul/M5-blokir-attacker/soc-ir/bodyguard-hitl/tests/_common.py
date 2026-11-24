# -*- coding: utf-8 -*-
"""Helper bersama untuk unit test (stdlib unittest - bisa dijalankan juga di server)."""

import logging
import os
import shutil
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
PROJECT = os.path.dirname(HERE)
LIB = os.path.join(PROJECT, "lib")
if LIB not in sys.path:
    sys.path.insert(0, LIB)

# Fungsi bukti bersama (modul/umum/simpan-bukti.py di lab reproduksi; bisa diganti lewat BUKTI_PY).
BUKTI_PY = os.environ.get("BUKTI_PY") or os.path.normpath(os.path.join(PROJECT, "..", "..", "..", "umum", "simpan-bukti.py"))
# FREEZE bersama diarahkan ke folder sementara supaya tes tidak pernah menyentuh /var/lib/freeze.
os.environ["FREEZE_FILE"] = os.path.join(tempfile.mkdtemp(prefix="bgfreeze-"), "FREEZE")

FAKE_CFGUARD = """import json, sys
with open(%r, "a") as f:
    f.write(" ".join(sys.argv[1:]) + "\\n")
if sys.argv[1] == "block":
    print(json.dumps({"ok": True, "ip": sys.argv[2], "ttl": int(sys.argv[4]), "rollback": "cf-guard.py remove " + sys.argv[2]}))
elif sys.argv[1] == "approve":
    print(json.dumps({"ok": True, "status": "diterapkan", "nilai": "198.51.100.7", "rollback": "cf-guard.py remove 198.51.100.7"}))
else:
    print(json.dumps({"ok": False, "galat": "tidak dikenal"}))
    sys.exit(2)
"""


def write_fake_cfguard(path, log):
    """cf-guard.py palsu: mencatat argumen dan menjawab JSON seperti aslinya."""
    return write(path, FAKE_CFGUARD % log, 0o644)


def calls(log):
    if not os.path.exists(log):
        return []
    with open(log) as f:
        return [l.strip() for l in f if l.strip()]


# Diamkan log JSON saat tes (tetap bisa diaktifkan dengan BG_TEST_LOG=1).
if not os.environ.get("BG_TEST_LOG"):
    _lg = logging.getLogger("bodyguard")
    _lg.addHandler(logging.NullHandler())
    _lg.propagate = False

CLOUDFLARE_V4 = [
    "173.245.48.0/20", "103.21.244.0/22", "103.22.200.0/22", "103.31.4.0/22", "141.101.64.0/18",
    "108.162.192.0/18", "190.93.240.0/20", "188.114.96.0/20", "197.234.240.0/22", "198.41.128.0/17",
    "162.158.0.0/15", "104.16.0.0/13", "104.24.0.0/14", "172.64.0.0/13", "131.0.72.0/22",
]
CLOUDFLARE_V6 = [
    "2400:cb00::/32", "2606:4700::/32", "2803:f800::/32", "2405:b500::/32", "2405:8100::/32",
    "2a06:98c0::/29", "2c0f:f248::/32",
]


class FakeClock(object):
    def __init__(self, t=1800000000.0):
        self.t = float(t)

    def __call__(self):
        return self.t

    def advance(self, seconds):
        self.t += seconds


def load_bg_root():
    """Muat sbin/bg-root (tanpa ekstensi .py) sebagai modul untuk diuji."""
    import importlib.machinery
    import importlib.util
    path = os.path.join(PROJECT, "sbin", "bg-root")
    loader = importlib.machinery.SourceFileLoader("bg_root_mod", path)
    spec = importlib.util.spec_from_loader("bg_root_mod", loader)
    mod = importlib.util.module_from_spec(spec)
    loader.exec_module(mod)
    return mod


def make_tmpdir(prefix="bgtest-"):
    d = os.path.realpath(tempfile.mkdtemp(prefix=prefix))
    os.environ["FREEZE_FILE"] = os.path.join(d, "FREEZE")  # FREEZE bersama terpisah per tes
    return d


def rmtree(path):
    """Bersihkan direktori sementara milik tes (pulihkan izin dulu karena ada file chmod 000)."""
    for root, dirs, files in os.walk(path):
        for name in dirs + files:
            p = os.path.join(root, name)
            try:
                if not os.path.islink(p):
                    os.chmod(p, 0o700)
            except OSError:
                pass
    shutil.rmtree(path, ignore_errors=True)


def write(path, data, mode=0o644):
    d = os.path.dirname(path)
    if d and not os.path.isdir(d):
        os.makedirs(d)
    with open(path, "wb") as f:
        f.write(data if isinstance(data, bytes) else data.encode("utf-8"))
    os.chmod(path, mode)
    return path


def write_cloudflare(path):
    write(path, "# Cloudflare\n" + "\n".join(CLOUDFLARE_V4 + CLOUDFLARE_V6) + "\n")
    return path


BASE_CONFIG = """
[general]
mode = %(mode)s
state_dir = %(tmp)s/state
log_file =
[limits]
max_ip_blocks_per_hour = 20
max_chmod_per_hour = 5
[whitelist]
cloudflare_file = %(tmp)s/cloudflare-ips.txt
admin_subnets_file = %(tmp)s/admin.txt
[wrappers]
sudo = /usr/bin/sudo
bg_root = /usr/local/sbin/bg-root
[ioc]
rules_file =
data_dirs = %(tmp)s/www/*/wp-content/uploads %(tmp)s/www/ojs/public
code_dirs =
data_php_allow = */wp-content/uploads/allowed-cache/*.php
[accesslog]
files = %(tmp)s/access.log
initial_tail_bytes = 10485760
[accounts]
mysql = /usr/bin/mysql
[site:wp1]
type = wordpress
root = %(tmp)s/www/site1
db = wp_site1
prefix = wp_
[site:ojs]
type = ojs
root = %(tmp)s/www/ojs
db = ojs
[integrity]
mode = off
[notify]
backend = log
"""


def make_env(tmp, mode="enforce", extra=""):
    """Siapkan pohon web tiruan + config; kembalikan objek Config."""
    from bodyguard.config import config_from_string
    for d in ("state", "www/site1/wp-content/uploads/2026/11", "www/site1/wp-content/plugins",
              "www/site1/wp-content/themes/tema", "www/ojs/public/journals/1"):
        p = os.path.join(tmp, d)
        if not os.path.isdir(p):
            os.makedirs(p)
    write_cloudflare(os.path.join(tmp, "cloudflare-ips.txt"))
    write(os.path.join(tmp, "admin.txt"), "203.0.113.0/24\n")
    return config_from_string(BASE_CONFIG % {"tmp": tmp, "mode": mode} + extra)
