#!/usr/bin/python3 -I
# -*- coding: utf-8 -*-
"""Cetak SQL GRANT siap-tempel untuk user DB Bodyguard berdasarkan [site:*] di bodyguard.conf.

  bodyguard_ro : hanya SELECT pada tabel akun (audit T0)
  bodyguard_t2 : SELECT + UPDATE per-KOLOM yang dibutuhkan aksi T2 (nonaktifkan akun), tidak lebih

Dijalankan oleh admin (root). Tidak menyentuh database: hanya MENCETAK SQL ke stdout.
Dengan --write-cnf, membuat /etc/bodyguard/mysql-ro.cnf & mysql-t2.cnf (root:guard 0640) bila belum ada,
berisi password acak yang sama dengan yang tercetak di SQL.
"""

import argparse
import grp
import os
import secrets
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.realpath(__file__))), "lib"))

from bodyguard.config import load_config  # noqa: E402


def _cnf(path, user, password, group):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o640)
    with os.fdopen(fd, "w") as f:
        f.write("[client]\nuser = %s\npassword = %s\nhost = localhost\n" % (user, password))
    os.chown(path, 0, grp.getgrnam(group).gr_gid)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--config", default="/etc/bodyguard/bodyguard.conf")
    ap.add_argument("--write-cnf", action="store_true")
    ap.add_argument("--etc", default="/etc/bodyguard")
    args = ap.parse_args()
    cfg = load_config(args.config, check_perms=os.geteuid() == 0)
    pw_ro, pw_t2 = secrets.token_urlsafe(24), secrets.token_urlsafe(24)
    ro, t2 = "'bodyguard_ro'@'localhost'", "'bodyguard_t2'@'localhost'"
    out = ["-- Bodyguard HITL: user DB berhak minimum. Jalankan sebagai admin MySQL/MariaDB.",
           "CREATE USER IF NOT EXISTS %s IDENTIFIED BY '%s';" % (ro, pw_ro),
           "CREATE USER IF NOT EXISTS %s IDENTIFIED BY '%s';" % (t2, pw_t2)]
    for s in cfg.sites:
        if not s.db:
            continue
        db = "`%s`" % s.db
        if s.type == "wordpress":
            p = s.prefix
            out += [
                "GRANT SELECT ON %s.`%susers` TO %s;" % (db, p, ro),
                "GRANT SELECT ON %s.`%susermeta` TO %s;" % (db, p, ro),
                "GRANT SELECT (ID, user_login) ON %s.`%susers` TO %s;" % (db, p, t2),
                "GRANT SELECT (user_id, meta_key, meta_value), UPDATE (meta_value) ON %s.`%susermeta` TO %s;" % (db, p, t2),
            ]
        else:
            out += [
                "GRANT SELECT ON %s.`users` TO %s;" % (db, ro),
                "GRANT SELECT ON %s.`user_user_groups` TO %s;" % (db, ro),
                "GRANT SELECT ON %s.`user_groups` TO %s;" % (db, ro),
                "GRANT SELECT (user_id, username, disabled, disabled_reason), UPDATE (disabled, disabled_reason) "
                "ON %s.`users` TO %s;" % (db, t2),
            ]
            if cfg.ojs_logout_sessions:
                out.append("GRANT SELECT (user_id), UPDATE (user_id) ON %s.`sessions` TO %s;" % (db, t2))
    out.append("FLUSH PRIVILEGES;")
    print("\n".join(out))
    if args.write_cnf:
        # mysql-t2.cnf hanya terbaca gatekeeper (guard-approve), BUKAN pemindai (guard).
        for name, user, pw, group in (("mysql-ro.cnf", "bodyguard_ro", pw_ro, "guard"),
                                      ("mysql-t2.cnf", "bodyguard_t2", pw_t2, "guard-approve")):
            path = os.path.join(args.etc, name)
            try:
                _cnf(path, user, pw, group)
                sys.stderr.write("dibuat: %s (root:%s 0640)\n" % (path, group))
            except FileExistsError:
                sys.stderr.write("SUDAH ADA, tidak ditimpa: %s - password di SQL di atas TIDAK cocok; "
                                 "hapus baris CREATE USER atau sesuaikan manual.\n" % path)
    return 0


if __name__ == "__main__":
    sys.exit(main())
