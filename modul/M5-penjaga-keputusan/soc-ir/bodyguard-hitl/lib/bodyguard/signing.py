# -*- coding: utf-8 -*-
"""Tanda tangan HMAC-SHA256 untuk tombol Inline Keyboard persetujuan T2.

Batas Telegram: callback_data maksimal 64 byte. Format (54 byte):

    1.<D>.<nonce16>.<ts10>.<sig22>
    |  |   |         |      +-- HMAC-SHA256 dipotong 128 bit, base64url tanpa padding
    |  |   |         +--------- unix timestamp saat pesan diterbitkan (10 digit)
    |  |   +------------------- nonce acak 96 bit (base64url), sekali pakai
    |  +----------------------- keputusan: A = Setujui, R = Tolak
    +-------------------------- versi format

Pesan yang di-MAC mengikat: domain, keputusan, nonce, ts, request_id, SHA256 aksi kanonik, chat_id.
Artinya tombol tidak bisa dipindah ke permintaan/aksi/chat lain, keputusan A<->R tidak bisa ditukar,
dan isi aksi di DB yang diubah setelah pesan terbit akan membuat tanda tangan gagal.

Anti-replay: nonce dikonsumsi atomik di DB (status PENDING -> keputusan). TTL 30 menit; kedaluwarsa
= TOLAK. Pemotongan HMAC ke 128 bit sesuai RFC 2104 (>= setengah panjang keluaran).
"""

import base64
import collections
import hashlib
import hmac
import os
import re

VERSION = "1"
DOMAIN = b"bodyguard-hitl/t2-approval/v1"
DECISIONS = ("A", "R")
CALLBACK_RE = re.compile(r"\A1\.([AR])\.([A-Za-z0-9_-]{16})\.(\d{10})\.([A-Za-z0-9_-]{22})\Z")
MAX_CALLBACK_BYTES = 64
DEFAULT_TTL = 1800
DEFAULT_SKEW = 60
MIN_KEY_BYTES = 32

Parsed = collections.namedtuple("Parsed", "decision nonce ts sig")
VerifyResult = collections.namedtuple("VerifyResult", "ok status reason")


def b64u(raw):
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def new_nonce():
    return b64u(os.urandom(12))


def parse_key(hex_key):
    """Kunci HMAC dari env BG_HMAC_KEY (hex). Minimal 32 byte (64 karakter hex)."""
    s = (hex_key or "").strip()
    if not re.match(r"\A[0-9a-fA-F]+\Z", s) or len(s) % 2:
        raise ValueError("BG_HMAC_KEY harus heksadesimal")
    key = bytes.fromhex(s)
    if len(key) < MIN_KEY_BYTES:
        raise ValueError("BG_HMAC_KEY minimal %d byte (%d hex)" % (MIN_KEY_BYTES, MIN_KEY_BYTES * 2))
    return key


def parse_callback(data):
    """Parse ketat; None bila format tidak valid."""
    if not isinstance(data, str) or len(data.encode("utf-8", "replace")) > MAX_CALLBACK_BYTES:
        return None
    m = CALLBACK_RE.match(data)
    if not m:
        return None
    return Parsed(m.group(1), m.group(2), int(m.group(3)), m.group(4))


class Signer(object):
    def __init__(self, key):
        if not isinstance(key, (bytes, bytearray)) or len(key) < MIN_KEY_BYTES:
            raise ValueError("kunci HMAC minimal %d byte" % MIN_KEY_BYTES)
        self._key = bytes(key)

    def _mac(self, decision, nonce, ts, request_id, action_sha256, chat_id):
        msg = b"\n".join((
            DOMAIN,
            decision.encode("ascii"),
            nonce.encode("ascii"),
            ("%010d" % int(ts)).encode("ascii"),
            str(request_id).encode("ascii"),
            str(action_sha256).encode("ascii"),
            str(int(chat_id)).encode("ascii"),
        ))
        return b64u(hmac.new(self._key, msg, hashlib.sha256).digest()[:16])

    def make_callback(self, decision, nonce, ts, request_id, action_sha256, chat_id):
        if decision not in DECISIONS:
            raise ValueError("keputusan harus A/R")
        if not re.match(r"\A[A-Za-z0-9_-]{16}\Z", nonce):
            raise ValueError("nonce tidak valid")
        data = "%s.%s.%s.%010d.%s" % (VERSION, decision, nonce, int(ts),
                                      self._mac(decision, nonce, ts, request_id, action_sha256, chat_id))
        if len(data.encode("ascii")) > MAX_CALLBACK_BYTES:
            raise ValueError("callback_data melebihi 64 byte")
        return data

    def verify(self, parsed, request_id, action_sha256, chat_id, issued_ts, now, ttl=DEFAULT_TTL, skew=DEFAULT_SKEW):
        """Urutan: tanda tangan dulu (waktu konstan), baru waktu. Kedaluwarsa = TOLAK."""
        if parsed is None:
            return VerifyResult(False, "MALFORMED", "format callback tidak valid")
        expected = self._mac(parsed.decision, parsed.nonce, parsed.ts, request_id, action_sha256, chat_id)
        if not hmac.compare_digest(expected.encode("ascii"), parsed.sig.encode("ascii")):
            return VerifyResult(False, "BAD_SIG", "tanda tangan HMAC tidak cocok")
        if issued_ts is None or int(parsed.ts) != int(issued_ts):
            return VerifyResult(False, "TS_MISMATCH", "timestamp tidak sesuai catatan server")
        if parsed.ts > now + skew:
            return VerifyResult(False, "FUTURE_TS", "timestamp di masa depan")
        if now - parsed.ts > ttl:
            return VerifyResult(False, "EXPIRED", "kedaluwarsa (> %d menit) - dianggap DITOLAK" % (ttl // 60))
        return VerifyResult(True, "OK", "valid")
