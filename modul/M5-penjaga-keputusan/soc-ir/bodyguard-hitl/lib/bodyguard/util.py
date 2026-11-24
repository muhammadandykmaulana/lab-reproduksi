# -*- coding: utf-8 -*-
"""Utilitas umum: eksekusi perintah tanpa shell, cek izin file, logging JSON, lock, waktu."""

import errno
import fcntl
import hashlib
import json
import logging
import os
import re
import secrets
import stat
import subprocess
import sys
import time

SAFE_ENV = {"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LANG": "C", "LC_ALL": "C"}
INCIDENT_RE = re.compile(r"\AINC-\d{8}-\d{6}-[0-9a-f]{4}\Z")
REQUEST_RE = re.compile(r"\AREQ-[0-9a-f]{12}\Z")
_TOKEN_RE = re.compile(r"\d{5,15}:[A-Za-z0-9_-]{30,64}")

LOG = logging.getLogger("bodyguard")


class BodyguardError(Exception):
    """Galat umum Bodyguard."""


class SecurityError(BodyguardError):
    """Asumsi keamanan dilanggar. Pemanggil WAJIB fail-closed (tidak bertindak, cukup alert)."""


def run_argv(argv, timeout=60, input_bytes=None, env=None):
    """Jalankan perintah TANPA shell. argv wajib list; mengembalikan (rc, stdout, stderr) bytes."""
    if not isinstance(argv, (list, tuple)) or not argv:
        raise TypeError("argv harus list yang tidak kosong (shell dilarang)")
    for a in argv:
        if isinstance(a, bytes):
            if b"\x00" in a:
                raise SecurityError("NUL di argumen")
        elif isinstance(a, str):
            if "\x00" in a:
                raise SecurityError("NUL di argumen")
        else:
            raise TypeError("argumen argv harus str/bytes")
    kwargs = {
        "stdout": subprocess.PIPE,
        "stderr": subprocess.PIPE,
        "timeout": timeout,
        "env": dict(SAFE_ENV) if env is None else env,
        "close_fds": True,
        "shell": False,
        "cwd": "/",
    }
    if input_bytes is None:
        kwargs["stdin"] = subprocess.DEVNULL
    else:
        kwargs["input"] = input_bytes
    p = subprocess.run(list(argv), **kwargs)
    return p.returncode, p.stdout, p.stderr


def check_file_secure(path, owner_uid=0, forbid_bits=0o022, allow_missing=False):
    """Pastikan file bukan symlink, file biasa, dimiliki owner_uid, dan tanpa bit izin terlarang."""
    try:
        st = os.lstat(path)
    except FileNotFoundError:
        if allow_missing:
            return None
        raise SecurityError("file tidak ada: %s" % path)
    if stat.S_ISLNK(st.st_mode):
        raise SecurityError("file berupa symlink (ditolak): %s" % path)
    if not stat.S_ISREG(st.st_mode):
        raise SecurityError("bukan file biasa: %s" % path)
    if owner_uid is not None and st.st_uid != owner_uid:
        raise SecurityError("pemilik %s harus uid %d (sekarang %d)" % (path, owner_uid, st.st_uid))
    if st.st_mode & forbid_bits:
        raise SecurityError("izin %s terlalu longgar (mode %04o)" % (path, stat.S_IMODE(st.st_mode)))
    return st


def redact(text):
    """Samarkan pola token bot Telegram dari teks log/galat."""
    return _TOKEN_RE.sub("<TOKEN-DISAMARKAN>", str(text))


def sha256_hex(data):
    return hashlib.sha256(data).hexdigest()


def canonical_json(obj):
    """JSON kanonik (deterministik, ASCII) - dipakai untuk digest yang ditandatangani HMAC."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def tkey(value):
    """Representasi aman-DB untuk target (path bisa berisi byte non-UTF8 via surrogateescape)."""
    if isinstance(value, bytes):
        value = os.fsdecode(value)
    return json.dumps(value, ensure_ascii=True)


def new_incident_id(ts=None):
    ts = time.time() if ts is None else ts
    return "INC-%s-%s" % (time.strftime("%Y%m%d-%H%M%S", time.gmtime(ts)), secrets.token_hex(2))


def new_request_id():
    return "REQ-" + secrets.token_hex(6)


def fmt_local(ts, offset_hours=7, label="WIB"):
    """Format waktu lokal tanpa zoneinfo (Python 3.6 tidak punya zoneinfo)."""
    t = time.gmtime(float(ts) + float(offset_hours) * 3600.0)
    return time.strftime("%Y-%m-%d %H:%M:%S", t) + " " + label


class JsonFormatter(logging.Formatter):
    """Satu event = satu baris JSON ASCII (anti log-injection: newline/kontrol ter-escape)."""

    def format(self, record):
        d = {
            "ts": round(record.created, 3),
            "lvl": record.levelname,
            "mod": record.name,
            "msg": redact(record.getMessage()),
        }
        extra = getattr(record, "bg", None)
        if isinstance(extra, dict):
            for k, v in extra.items():
                if k not in d:
                    d[str(k)] = v
        if record.exc_info:
            d["exc"] = redact(self.formatException(record.exc_info))[-2000:]
        return json.dumps(d, ensure_ascii=True, default=str)


def setup_logging(log_file=None, level=logging.INFO, stderr=True):
    root = logging.getLogger("bodyguard")
    root.setLevel(level)
    for h in list(root.handlers):
        root.removeHandler(h)
    fmt = JsonFormatter()
    if stderr:
        sh = logging.StreamHandler(sys.stderr)
        sh.setFormatter(fmt)
        root.addHandler(sh)
    if log_file:
        try:
            fh = logging.FileHandler(log_file, encoding="utf-8")
            fh.setFormatter(fmt)
            root.addHandler(fh)
        except OSError as e:
            root.warning("log file tidak bisa dibuka (%s); hanya ke stderr/journald", errno.errorcode.get(e.errno, e.errno))
    root.propagate = False
    return root


def log_event(level, msg, **fields):
    LOG.log(level, msg, extra={"bg": fields})


class SingleInstanceLock(object):
    """Lock non-blocking berbasis flock agar siklus pindai tidak tumpang tindih."""

    def __init__(self, path):
        self.path = path
        self.fd = None

    def acquire(self):
        fd = os.open(self.path, os.O_RDWR | os.O_CREAT | getattr(os, "O_CLOEXEC", 0) | os.O_NOFOLLOW, 0o600)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except (BlockingIOError, OSError):
            os.close(fd)
            return False
        self.fd = fd
        return True

    def release(self):
        if self.fd is not None:
            try:
                fcntl.flock(self.fd, fcntl.LOCK_UN)
            finally:
                os.close(self.fd)
                self.fd = None
