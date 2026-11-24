# -*- coding: utf-8 -*-
"""Pemanggilan pintu root: `sudo -n /usr/local/sbin/bg-root <sub-perintah> ...` (argv list, tanpa shell)."""

import json
import subprocess

from .sanitizer import clean


def call_bg_root(cfg, runner, args, timeout=300):
    """Kembalikan (ok: bool, hasil: dict). sudo -n = tidak pernah menunggu password (gagal cepat)."""
    argv = [cfg.sudo, "-n", cfg.bg_root] + list(args)
    try:
        rc, out, err = runner(argv, timeout=timeout)
    except subprocess.TimeoutExpired:
        return False, {"ok": False, "error": "timeout"}
    except OSError as e:
        return False, {"ok": False, "error": "exec: %s" % e.__class__.__name__}
    res = None
    for line in reversed(out.decode("utf-8", "replace").splitlines()):
        line = line.strip()
        if line.startswith("{"):
            try:
                res = json.loads(line)
                break
            except ValueError:
                continue
    if not isinstance(res, dict):
        msg = clean(err[-300:], 300).strip() if err else ""
        res = {"ok": False, "error": ("bg-root/sudo gagal (rc=%d): %s" % (rc, msg)) if msg else
               "keluaran bg-root tidak valid (rc=%d)" % rc}
    res.setdefault("rc", rc)
    ok = rc == 0 and res.get("ok") is True
    if not ok and err:
        res.setdefault("stderr", clean(err[-300:], 300))
    return ok, res


def planned_argv(cfg, args):
    """Representasi tampilan perintah (untuk log dry-run)."""
    shown = []
    for a in [cfg.sudo, "-n", cfg.bg_root] + list(args):
        shown.append(clean(a if isinstance(a, str) else a.decode("utf-8", "replace"), 300))
    return " ".join(shown)
