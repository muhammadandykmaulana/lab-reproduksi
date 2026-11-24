# -*- coding: utf-8 -*-
"""Sanitizer & lapisan anti prompt-injection.

SEMUA data yang berasal dari penyerang (nama file, isi webshell, header/URI log, EXIF, username,
nama plugin) WAJIB lewat modul ini sebelum:
  * dikirim ke notifikasi Telegram / notify-run.sh,
  * ditulis ke brief analisis untuk LLM penasihat,
  * ditampilkan di pesan persetujuan T2.

Prinsip:
  1. Data penyerang hanya pernah DITAMPILKAN, tidak pernah dievaluasi (tidak ada eval/shell/format
     string perintah). Modul ini tidak punya fungsi yang "menjalankan" apa pun.
  2. Karakter kontrol C0/C1, ESC (ANSI), DEL, karakter format Unicode (bidi override "Trojan Source",
     zero-width, BOM), surrogate, private-use, dan unassigned diganti penanda yang TERLIHAT
     (mis. \\x1b, <U+202E>) - analis tetap tahu ada trik, tapi trik itu tidak bekerja.
  3. Panjang dipotong dengan penanda eksplisit.
  4. Untuk LLM, data dibungkus blok netral dengan token batas acak per-brief sehingga penyerang
     tidak bisa "menutup" blok lebih awal dan menyisipkan instruksi.
"""

import html
import re
import secrets
import unicodedata

DEFAULT_MAX = 200
_SURR_RE = re.compile("[\ud800-\udfff]")
_BAD_CATEGORIES = frozenset(("Cf", "Cs", "Co", "Cn", "Zl", "Zp"))
_URL_SCHEME_RE = re.compile(r"(?i)\b(h)(tt)(ps?)(://)")
_ALLOWED_KINDS = frozenset((
    "filename", "path", "snippet", "uri", "user_agent", "username", "email",
    "plugin", "exif", "log_line", "text",
))


def to_text(value):
    """Ubah nilai apa pun menjadi str yang aman di-encode UTF-8."""
    if value is None:
        return ""
    if isinstance(value, (bytes, bytearray)):
        return bytes(value).decode("utf-8", errors="replace")
    if not isinstance(value, str):
        value = str(value)
    try:
        value.encode("utf-8")
        return value
    except UnicodeEncodeError:
        pass
    try:
        # Nama file non-UTF8 dari os.fsdecode() memakai surrogateescape.
        return value.encode("utf-8", "surrogateescape").decode("utf-8", "replace")
    except UnicodeEncodeError:
        return _SURR_RE.sub("\ufffd", value)


def truncate(text, max_len):
    if max_len is None or max_len <= 0 or len(text) <= max_len:
        return text
    return text[:max_len] + "\u2026[+%d karakter]" % (len(text) - max_len)


def clean(value, max_len=DEFAULT_MAX, keep_newlines=False):
    """Netralisasi string tak tepercaya menjadi teks satu baris (atau multi-baris bila keep_newlines)."""
    s = to_text(value)
    out = []
    for ch in s:
        cp = ord(ch)
        if ch == "\n":
            out.append("\n" if keep_newlines else "\u23ce")
            continue
        if ch == "\t":
            out.append(" ")
            continue
        if cp < 0x20 or cp == 0x7F or 0x80 <= cp <= 0x9F:
            out.append("\\x%02x" % cp)
            continue
        if unicodedata.category(ch) in _BAD_CATEGORIES:
            out.append("<U+%04X>" % cp)
            continue
        out.append(ch)
    s = "".join(out)
    # Netralkan penanda batas blok data agar tidak bisa dipalsukan dari dalam data.
    s = s.replace("<<<", "\u2039\u2039\u2039").replace(">>>", "\u203a\u203a\u203a")
    return truncate(s, max_len)


def defang(text):
    """Untuk kanal teks polos: matikan auto-link URL (http -> hxxp)."""
    return _URL_SCHEME_RE.sub(lambda m: "hxx" + m.group(3) + "[://]", text)


def tg(value, max_len=DEFAULT_MAX):
    """Teks tak tepercaya -> fragmen aman untuk Telegram parse_mode=HTML."""
    return html.escape(clean(value, max_len), quote=False)


def tg_code(value, max_len=DEFAULT_MAX):
    """Dibungkus <code>: Telegram tidak membuat tautan/entitas di dalamnya."""
    return "<code>%s</code>" % tg(value, max_len)


def tg_pre(value, max_len=600):
    return "<pre>%s</pre>" % html.escape(clean(value, max_len, keep_newlines=True), quote=False)


def html_to_plain(html_text):
    """Ubah pesan HTML buatan kita menjadi teks polos (untuk notify-run.sh)."""
    no_tags = re.sub(r"<[^>]{1,40}>", "", html_text)
    text = defang(html.unescape(no_tags))
    # Data penyerang sempat di-escape untuk HTML; setelah di-unescape jangan biarkan jadi markup lagi bila
    # skrip notifikasi meneruskannya ke Telegram dengan parse_mode HTML.
    return text.replace("<", "\u2039").replace(">", "\u203a")


def snippet(data, start, end, context=40, max_len=160):
    """Cuplikan tersanitasi di sekitar match IOC (data: bytes)."""
    a = max(0, int(start) - context)
    b = min(len(data), int(end) + context)
    return clean(data[a:b], max_len)


def new_boundary():
    return secrets.token_hex(8)


def untrusted_block(kind, value, boundary, max_len=2000):
    """Bungkus data penyerang untuk LLM: diberi label, dibatasi token acak, dan disanitasi."""
    if kind not in _ALLOWED_KINDS:
        kind = "text"
    if not re.match(r"\A[0-9a-f]{16}\Z", boundary or ""):
        raise ValueError("boundary harus 16 hex acak dari new_boundary()")
    body = clean(value, max_len, keep_newlines=True)
    return "<<<DATA_TIDAK_TEPERCAYA id=%s jenis=%s>>>\n%s\n<<<AKHIR_DATA id=%s>>>" % (boundary, kind, body, boundary)
