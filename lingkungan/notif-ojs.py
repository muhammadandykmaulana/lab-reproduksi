#!/usr/bin/env python3
"""notif-ojs.py - kirim notifikasi Telegram untuk setiap pendaftaran akun baru di OJS (HANYA SELECT).

Bagian dari lapisan 2 (CAPTCHA OJS dan verifikasi pendaftaran): akun yang lolos CAPTCHA tetap terlihat oleh admin,
dan pola penanda (surel .internal, nama acak panjang, banyak pendaftar dari domain surel yang sama) diberi tanda.
Pakai (root, dari timer tiap 5 menit):  python3 notif-ojs.py            sekali jalan
                                         python3 notif-ojs.py --awal     catat user_id terakhir tanpa mengirim
Konfigurasi di /etc/web-integrity.env: TELEGRAM_BOT_TOKEN, TELEGRAM_CHAT_ID, OJS_DB (nama database OJS).
Hanya pustaka standar Python 3; koneksi database memakai klien mariadb (root lewat unix socket).
"""
import os
import re
import shutil
import subprocess
import sys

ENV = "/etc/web-integrity.env"
STATE = "/var/lib/notif-ojs/last_user_id"


def baca_env(path):
    env = {}
    try:
        for line in open(path, encoding="utf-8"):
            m = re.match(r'^\s*(?:export\s+)?([A-Z_]+)\s*=\s*"?([^"\n]*)"?\s*$', line)
            if m:
                env[m.group(1)] = m.group(2)
    except OSError:
        pass
    return env


def sql(db, query):
    biner = shutil.which("mariadb") or shutil.which("mysql")
    if not biner:
        sys.exit("klien mariadb/mysql tidak ada")
    r = subprocess.run([biner, "-N", "-B", db, "-e", query], capture_output=True, text=True, timeout=60)
    if r.returncode != 0:
        sys.exit("query gagal: " + r.stderr.strip()[:200])
    return [ln.split("\t") for ln in r.stdout.splitlines() if ln]


def kirim(env, teks):
    """Satu pengirim Telegram untuk semua modul: notify-run.sh --pesan (token dibaca dari /etc/web-integrity.env)."""
    nr = os.environ.get("NOTIFY_RUN", os.path.join(os.path.dirname(os.path.abspath(__file__)), "notify-run.sh"))
    try:
        r = subprocess.run([nr, "--pesan"], input=teks[:3800].encode(), stdout=subprocess.DEVNULL,
                           stderr=subprocess.PIPE, timeout=60)
        if r.returncode != 0:
            print(teks)
            print("Telegram gagal:", r.stderr.decode(errors="replace")[:200])
    except OSError as e:
        print(teks)
        print("notify-run.sh tidak bisa dijalankan:", type(e).__name__)


def main():
    env = baca_env(ENV)
    env.update({k: v for k, v in os.environ.items() if k in ("TELEGRAM_BOT_TOKEN", "TELEGRAM_CHAT_ID", "OJS_DB")})
    db = env.get("OJS_DB")
    if not db:
        sys.exit("OJS_DB belum diisi di %s" % ENV)
    os.makedirs(os.path.dirname(STATE), mode=0o700, exist_ok=True)
    try:
        last = int(open(STATE).read().strip() or 0)
    except (OSError, ValueError):
        last = -1
    maks = int((sql(db, "SELECT IFNULL(MAX(user_id),0) FROM users") or [["0"]])[0][0])
    if last < 0 or "--awal" in sys.argv:
        open(STATE, "w").write(str(maks))
        print("titik awal dicatat: user_id", maks)
        return
    if maks <= last:
        return
    rows = sql(db, "SELECT user_id, username, email, IFNULL(date_registered,'') FROM users WHERE user_id > %d "
                   "ORDER BY user_id LIMIT 200" % last)
    domain = {}
    for _, _, em, _ in rows:
        d = em.rsplit("@", 1)[-1].lower()
        domain[d] = domain.get(d, 0) + 1
    baris = []
    for uid, user, em, tgl in rows:
        tanda = []
        if em.lower().endswith(".internal"):
            tanda.append("surel .internal")
        if re.fullmatch(r"[a-z0-9]{12,}", user) and re.search(r"\d", user) and re.search(r"[a-z]", user):
            tanda.append("nama acak")
        if domain[em.rsplit("@", 1)[-1].lower()] >= 5:
            tanda.append("domain sama >= 5")
        nama, _, dom = em.partition("@")
        baris.append("#%s %s <%s***@%s> %s%s" % (uid, user, nama[:2], dom, tgl[:16], ("  [!] " + ", ".join(tanda)) if tanda else ""))
    kirim(env, "Pendaftar OJS baru (%d):\n%s\nVerifikasi di menu Users & Roles sebelum diberi peran." % (len(rows), "\n".join(baris)))
    open(STATE, "w").write(str(max(int(r[0]) for r in rows)))


if __name__ == "__main__":
    main()
