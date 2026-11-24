#!/usr/bin/env python3
"""
backup_vps.py  (versi hardening, 2026-11-06)

Alur:
  config sistem -> config + dump DB Supabase (+ storage ke GDrive) -> salin /var/opt
  -> zip -> push GitLab -> kirim Telegram (urut prioritas) -> bersih-bersih -> ringkasan.

Konfigurasi (di /etc/cek-disk.env, chmod 600), semua opsional kecuali token:
  TELEGRAM_BOT_TOKEN=...
  TELEGRAM_API_BASE=http://127.0.0.1:8081     # Bot API lokal (default). JANGAN lewat Cloudflare.
  BACKUP_CHAT_ID=-100xxxxxxxxxx              # bawaan: TELEGRAM_CHAT_ID
  BACKUP_VPS_DIR=/var/opt/BACKUP/vps          # folder staging + repo git tingkat 2
  BIND_ZONE_FILE=                             # opsional, mis. /etc/bind/zones/db.kampus.ac.id
  SUPABASE_DB_CONTAINER=supabase-db
  SUPABASE_PG_USER=supabase_admin
  RCLONE_REMOTE_SUPABASE=gdrive:Backup_Supabase
  EPRINTS_RCLONE_REMOTE=eprints:              # sumber dokumen EPrints
  EPRINTS_RCLONE_EXTRA=                       # flag rclone tambahan, mis. --drive-acknowledge-abuse --tpslimit 5
  EPRINTS_TOLERATE_FILES=0                    # jumlah file yang boleh gagal disalin tanpa menandai tahap GAGAL
  EPRINTS_MIN_FREE_GB=5                       # tahap EPrints dilewati bila ruang kosong kurang dari ini
  EPRINTS_LOG_DIR=/var/log/backup_vps         # log rclone per hari (disimpan 14 hari)
"""
import datetime
import fcntl
import glob
import gzip
import os
import re
import shlex
import shutil
import subprocess
import sys
import tempfile
import time
import traceback
import zipfile
from pathlib import Path

import requests

# --------------------------------------------------------------------------- #
# Konfigurasi
# --------------------------------------------------------------------------- #
ENV_FILE = "/etc/cek-disk.env"


def read_env(path):
    """Baca file KEY=VALUE (toleran terhadap 'export' dan tanda kutip)."""
    env = {}
    try:
        with open(path) as fh:
            for line in fh:
                line = line.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                if line.startswith("export "):
                    line = line[7:]
                key, value = line.split("=", 1)
                env[key.strip()] = value.strip().strip('"').strip("'")
    except OSError:
        pass
    return env


ENV = read_env(ENV_FILE)


def cfg(key, default=None):
    return os.environ.get(key) or ENV.get(key) or default


TOKEN = cfg("TELEGRAM_BOT_TOKEN")
if not TOKEN:
    sys.exit(f"TELEGRAM_BOT_TOKEN tidak ditemukan di {ENV_FILE}")
CHAT_ID = cfg("BACKUP_CHAT_ID") or cfg("TELEGRAM_CHAT_ID", "")
API_BASE = cfg("TELEGRAM_API_BASE", "https://api.telegram.org").rstrip("/")
OFFICIAL_API = "https://api.telegram.org"
# Bot API resmi menerima berkas sampai 50 MB; Bot API lokal (127.0.0.1:8081) sampai 2000 MB.
MAX_BYTES = (1900 if "127.0.0.1" in API_BASE or "localhost" in API_BASE else 49) * 1024 * 1024
RESP_FILE = "/tmp/backup_vps_tg_resp.json"

SUPABASE_DIR = Path("/var/opt/supabase-project")
SUPABASE_DB_CONTAINER = cfg("SUPABASE_DB_CONTAINER", "supabase-db")
SUPABASE_PG_USER = cfg("SUPABASE_PG_USER", "supabase_admin")
RCLONE_REMOTE_SUPABASE = cfg("RCLONE_REMOTE_SUPABASE", "gdrive:Backup_Supabase")
EPRINTS_REMOTE = cfg("EPRINTS_RCLONE_REMOTE", "eprints:")
EPRINTS_MIRROR = Path("/var/backup/eprints-documents")


def cfg_num(key, default, cast=float):
    """Angka dari konfigurasi; nilai rusak -> pakai default (jangan sampai skrip mati saat import)."""
    try:
        return cast(cfg(key, default))
    except (TypeError, ValueError):
        return cast(default)


EPRINTS_LOG_DIR = Path(cfg("EPRINTS_LOG_DIR", "/var/log/backup_vps"))
EPRINTS_EXTRA = shlex.split(cfg("EPRINTS_RCLONE_EXTRA", "") or "")
EPRINTS_TOLERATE_FILES = cfg_num("EPRINTS_TOLERATE_FILES", 0, int)
EPRINTS_MIN_FREE_GB = cfg_num("EPRINTS_MIN_FREE_GB", 5, float)
EPRINTS_LOG_KEEP_DAYS = 14
SUPABASE_DUMP_KEEP_DAYS = 14  # retensi dump di GDrive

backup_dir = Path(cfg("BACKUP_VPS_DIR", "/var/opt/BACKUP/vps"))
nginx_backup_dir = backup_dir / "nginx_config"
fail2ban_backup_dir = backup_dir / "fail2ban_config"
var_opt_backup_dir = backup_dir / "var_opt"
named_backup_dir = backup_dir / "etc_named"
rclone_backup_dir = backup_dir / "rclone_config"
supabase_cfg_dir = backup_dir / "supabase_config"
misc_backup_dir = backup_dir / "misc"
php_backup_dir = backup_dir / "php_config"
today_str = os.environ.get("BACKUP_DATE") or datetime.datetime.now().strftime("%Y_%m_%d")

backup_web_dir = Path("/var/opt/BACKUP/web")
backup_db_dir = Path("/var/opt/BACKUP/DB")
LOCK_FILE = "/var/run/backup_vps.lock"

nginx_files = {
    "nginx.conf": "/etc/nginx/nginx.conf",
    "sites-available": "/etc/nginx/sites-available",
    "cloudflare.conf": "/etc/nginx/cloudflare.conf",  # (titik koma di versi lama dihapus)
}
fail2ban_files = {
    "jail.conf": "/etc/fail2ban/jail.conf",
    "jail.local": "/etc/fail2ban/jail.local",
    "filter.d": "/etc/fail2ban/filter.d",
}
named_files = {
    "rndc.key": "/etc/bind/rndc.key",
    "named.conf.local": "/etc/bind/named.conf.local",
}
if cfg("BIND_ZONE_FILE"):
    named_files["zone_" + os.path.basename(cfg("BIND_ZONE_FILE"))] = cfg("BIND_ZONE_FILE")
rclone_files = {"rclone.conf": "/root/.config/rclone/rclone.conf"}

# Jangan salin ke staging /var/opt:
#  - BACKUP/web & BACKUP/DB : sudah dikirim terpisah
#  - supabase-project       : data Postgres hidup (tidak konsisten & sangat besar).
#                             Dibackup dengan benar lewat dump_supabase_db() + sync storage.
#  - supabase               : clone repo github supabase/supabase (bisa diunduh ulang).
VAR_OPT_SKIP = (
    "/var/opt/BACKUP/web",
    "/var/opt/BACKUP/DB",
    "/var/opt/supabase-project",
    "/var/opt/supabase",
)

# Folder Supabase yang TIDAK ikut di backup config (data, bukan config)
SUPABASE_CFG_EXCLUDE = {
    SUPABASE_DIR / "volumes" / "db" / "data",
    SUPABASE_DIR / "volumes" / "storage",
    SUPABASE_DIR / ".git",
}

SENT, FAILED, SKIPPED, WARNINGS = [], [], [], []


# --------------------------------------------------------------------------- #
# Telegram
# --------------------------------------------------------------------------- #
NOTIFY_RUN = os.environ.get("NOTIFY_RUN", str(Path(__file__).resolve().parent / "notify-run.sh"))
BACKUP_VERIFY = os.environ.get("BACKUP_VERIFY", str(Path(__file__).resolve().parent / "backup-verify.sh"))


def send_message(text):
    """Pesan teks lewat satu pengirim bersama (notify-run.sh --pesan). Unggah BERKAS ke Telegram (tingkat 2)
    tetap di script ini karena itu jalur penyimpanan backup, bukan notifikasi. Tidak pernah melempar error."""
    env = dict(os.environ, TELEGRAM_BOT_TOKEN=TOKEN or "", TELEGRAM_CHAT_ID=str(CHAT_ID or ""),
               TELEGRAM_API_BASE=API_BASE)
    try:
        r = subprocess.run([NOTIFY_RUN, "--pesan", "--env", "-"], input=text[:3800].encode(), env=env,
                           stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, timeout=60)
        if r.returncode == 0:
            return True
        print("notify-run gagal:", r.stderr.decode(errors="replace")[:200], flush=True)
    except (OSError, subprocess.SubprocessError) as exc:
        print(f"notify-run tidak bisa dijalankan: {exc.__class__.__name__}", flush=True)
    return False


def lolos_verifikasi(path):
    """M4: zip VPS harus utuh sebelum dikirim ke tingkat 2 (Gambar 3.3)."""
    try:
        r = subprocess.run([BACKUP_VERIFY, "--berkas", str(path)], stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                           timeout=3600)
        print(r.stdout.decode(errors="replace").strip(), flush=True)
        return r.returncode == 0
    except (OSError, subprocess.SubprocessError) as exc:
        print(f"backup-verify tidak bisa dijalankan: {exc.__class__.__name__}", flush=True)
        return False


def curl_upload(path, retries=3):
    """Upload streaming via curl (tidak memuat file ke RAM). Token tidak muncul di `ps`."""
    path = Path(path)
    url = f"{API_BASE}/bot{TOKEN}/sendDocument"
    for attempt in range(1, retries + 1):
        code, err = "", ""
        try:
            r = subprocess.run(
                ["curl", "-sS", "-m", "1800", "-o", RESP_FILE, "-w", "%{http_code}",
                 "-F", f"chat_id={CHAT_ID}", "-F", f"document=@{path}", "--config", "-"],
                input=f'url = "{url}"\n', capture_output=True, text=True, timeout=1900)
            code, err = r.stdout.strip(), r.stderr.strip()[:200]
        except subprocess.TimeoutExpired:
            code = "timeout"
        if code == "200":
            print(f"Terkirim: {path.name}", flush=True)
            SENT.append(path.name)
            return True
        try:
            body = Path(RESP_FILE).read_text()[:200]
        except OSError:
            body = ""
        print(f"Kirim {path.name} percobaan {attempt}/{retries}: HTTP {code} {err} {body}", flush=True)
        time.sleep(5 * attempt)
    FAILED.append(path.name)
    return False


def send_file(path, allow_split=False):
    path = Path(path)
    size = path.stat().st_size
    if size <= MAX_BYTES:
        return curl_upload(path)
    if not allow_split:
        SKIPPED.append(f"{path.name} ({size / 1024 ** 3:.2f} GB)")
        print(f"Dilewati (melebihi batas Telegram): {path.name}", flush=True)
        return False
    tmp = backup_dir / "_split_tmp"
    shutil.rmtree(tmp, ignore_errors=True)
    tmp.mkdir(parents=True)
    try:
        subprocess.run(["split", "-b", "1900m", "-d", "-a", "2", str(path),
                        str(tmp / (path.name + ".part"))], check=True, timeout=3600)
        ok = True
        for part in sorted(tmp.iterdir()):
            ok = curl_upload(part) and ok
        return ok
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


# --------------------------------------------------------------------------- #
# Backup config sistem
# --------------------------------------------------------------------------- #
def create_backup_dirs():
    for d in (backup_dir, nginx_backup_dir, fail2ban_backup_dir, named_backup_dir,
              rclone_backup_dir, misc_backup_dir, php_backup_dir):
        d.mkdir(parents=True, exist_ok=True)
    # Staging /var/opt SELALU dibuat ulang agar sisa lama (mis. supabase 9 GB) tidak menumpuk.
    shutil.rmtree(var_opt_backup_dir, ignore_errors=True)
    var_opt_backup_dir.mkdir(parents=True)


def copy_item(src, dst):
    src, dst = Path(src), Path(dst)
    dst.parent.mkdir(parents=True, exist_ok=True)
    if src.is_file():
        shutil.copy2(src, dst)
    elif src.is_dir():
        shutil.copytree(src, dst, dirs_exist_ok=True)
    else:
        print(f"PERINGATAN: {src} tidak ada, dilewati", flush=True)
        return False
    return True


def php_versions():
    """Semua versi PHP-FPM yang terpasang (terbaru dulu). Tidak ada versi yang di-hardcode."""
    found = []
    for ini in glob.glob("/etc/php/*/fpm/php.ini"):
        ver = Path(ini).parts[3]  # /etc/php/<ver>/fpm/php.ini
        try:
            key = tuple(int(x) for x in ver.split("."))
        except ValueError:
            key = (0,)
        found.append((key, ver))
    return [ver for _key, ver in sorted(found, reverse=True)]


def backup_php():
    versions = php_versions()
    if not versions:
        WARNINGS.append("PHP-FPM tidak ditemukan di /etc/php/*/fpm")
        return
    print(f"PHP-FPM terpasang: {', '.join(versions)} (terbaru: {versions[0]})", flush=True)
    for ver in versions:
        base = Path(f"/etc/php/{ver}/fpm")
        for name in ("php.ini", "php-fpm.conf", "pool.d"):
            if (base / name).exists():
                copy_item(base / name, php_backup_dir / ver / name)


def backup_files():
    # (root config, tujuan, daftar item, wajib?)  Wajib hilang -> tahap GAGAL; opsional -> hanya peringatan.
    groups = (
        ("/etc/nginx", nginx_backup_dir, nginx_files, True),
        ("/etc/fail2ban", fail2ban_backup_dir, fail2ban_files, False),
        ("/etc/bind", named_backup_dir, named_files, False),
        ("/root/.config/rclone", rclone_backup_dir, rclone_files, True),
    )
    errors = []
    for root, dest, items, required in groups:
        bucket = errors if required else WARNINGS
        if not Path(root).exists():
            if required:
                bucket.append(f"{root} tidak ada, dilewati")
            continue  # grup opsional (mis. /etc/bind) yang tidak ada: abaikan tanpa peringatan
        for name, path in items.items():
            if not copy_item(path, dest / name):
                bucket.append(f"{path} tidak ada")
    backup_php()
    # crontab root
    r = subprocess.run(["crontab", "-l"], capture_output=True, text=True, timeout=30)
    if r.returncode == 0:
        (misc_backup_dir / "crontab_root.txt").write_text(r.stdout)
    if errors:
        raise RuntimeError("config WAJIB tidak ditemukan: " + ", ".join(errors))


def backup_var_opt():
    for root, _dirs, files in os.walk("/var/opt"):
        if any(root.startswith(s) for s in VAR_OPT_SKIP):
            continue
        for name in files:
            src = Path(root) / name
            if src.is_symlink() or not src.is_file():  # lewati socket/fifo/symlink
                continue
            dst = var_opt_backup_dir / src.relative_to("/var/opt")
            dst.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(src, dst)


def copy_sql_backups():
    src_dir = Path("/var/opt/sql-backup")
    dst_dir = backup_dir / "sql-backup"
    dst_dir.mkdir(parents=True, exist_ok=True)
    for f in src_dir.glob("*.sql"):
        shutil.copy2(f, dst_dir / f.name)


# --------------------------------------------------------------------------- #
# Supabase (self-hosted, docker compose)
# --------------------------------------------------------------------------- #
def read_supabase_env():
    return read_env(str(SUPABASE_DIR / ".env"))


def backup_supabase_config():
    """Config saja: .env, docker-compose.yml, volumes/api, functions, dst. TANPA data Postgres & storage."""
    if not SUPABASE_DIR.is_dir():
        raise RuntimeError(f"{SUPABASE_DIR} tidak ada")

    def ignore(dirpath, names):
        return [n for n in names if Path(dirpath, n) in SUPABASE_CFG_EXCLUDE]

    shutil.rmtree(supabase_cfg_dir, ignore_errors=True)
    shutil.copytree(SUPABASE_DIR, supabase_cfg_dir, ignore=ignore, symlinks=True)


def dump_supabase_db():
    """pg_dumpall dari container Postgres -> /var/opt/BACKUP/DB/<tgl>-supabase_pg.sql.gz
    (otomatis ikut dikirim Telegram dan ikut retensi DB). Ditulis .partial lalu rename atomik."""
    backup_db_dir.mkdir(parents=True, exist_ok=True)
    final = backup_db_dir / f"{today_str}-supabase_pg.sql.gz"
    partial = final.with_suffix(final.suffix + ".partial")
    env = dict(os.environ)
    password = read_supabase_env().get("POSTGRES_PASSWORD")
    if password:
        env["PGPASSWORD"] = password  # lewat environment, tidak tampil di `ps`
    cmd = ["docker", "exec", "-e", "PGPASSWORD", SUPABASE_DB_CONTAINER,
           "pg_dumpall", "-h", "127.0.0.1", "-U", SUPABASE_PG_USER, "--clean", "--if-exists"]
    with tempfile.TemporaryFile() as errf, gzip.open(partial, "wb", compresslevel=6) as out:
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=errf, env=env)
        shutil.copyfileobj(proc.stdout, out, 1024 * 1024)
        rc = proc.wait(timeout=3600)
        errf.seek(0)
        err = errf.read().decode(errors="replace")[-300:]
    if rc != 0 or partial.stat().st_size < 1024:
        partial.unlink(missing_ok=True)
        raise RuntimeError(f"pg_dumpall gagal (rc={rc}): {err}")
    subprocess.run(["gzip", "-t", str(partial)], check=True, timeout=600)
    os.replace(partial, final)
    return final


def upload_supabase_dump(dump_path):
    if not dump_path:
        raise RuntimeError("dump Supabase tidak ada, upload dilewati")
    subprocess.run(["rclone", "copy", str(dump_path), f"{RCLONE_REMOTE_SUPABASE}/db"],
                   check=True, timeout=1800)
    subprocess.run(["rclone", "delete", f"{RCLONE_REMOTE_SUPABASE}/db",
                    "--min-age", f"{SUPABASE_DUMP_KEEP_DAYS}d"], check=False, timeout=600)


def sync_supabase_storage():
    """File upload Supabase Storage -> GDrive (inkremental, tidak menghapus apa pun di tujuan)."""
    storage = SUPABASE_DIR / "volumes" / "storage"
    if not storage.is_dir():
        print("Tidak ada volumes/storage, dilewati", flush=True)
        return
    subprocess.run(["rclone", "copy", str(storage), f"{RCLONE_REMOTE_SUPABASE}/storage",
                    "--update", "--transfers", "4", "--log-level", "ERROR"],
                   check=True, timeout=3 * 3600)


# Petunjuk otomatis: pola galat rclone yang sering muncul -> kalimat singkat untuk laporan Telegram.
RCLONE_HINTS = (
    (re.compile(r"invalid_grant|token expired|Failed to configure token|couldn't find root directory", re.I),
     "token Google kedaluwarsa/dicabut: jalankan 'rclone config reconnect eprints:'"),
    (re.compile(r"didn't find section in config file|not found in config", re.I),
     "remote tidak ada di rclone.conf (cek 'rclone listremotes')"),
    (re.compile(r"downloadQuotaExceeded", re.I),
     "kuota unduh file Drive habis (biasanya pulih dalam 24 jam)"),
    (re.compile(r"cannotDownloadAbusiveFile|malware or spam", re.I),
     "Drive menandai file sebagai spam/malware: periksa dulu, lalu opsi --drive-acknowledge-abuse"),
    (re.compile(r"rateLimitExceeded|userRateLimitExceeded|Too Many Requests", re.I),
     "kena batas laju API Drive: coba --tpslimit 5"),
    (re.compile(r"exportSizeLimitExceeded|no export format|can't export", re.I),
     "file Google Docs terlalu besar untuk diekspor: opsi --drive-skip-gdocs"),
    (re.compile(r"shortcut", re.I),
     "ada pintasan Drive rusak: opsi --drive-skip-shortcuts"),
    (re.compile(r"no space left on device", re.I), "disk penuh"),
)
_RC_LOG_LINE = re.compile(r"^\d{4}/\d\d/\d\d \d\d:\d\d:\d\d\s+(?:(ERROR|CRITICAL|NOTICE)\s*:\s*)?(.*)$")
_RC_SUMMARY = re.compile(r"^(Attempt \d+/\d+ failed|Failed to (copy|sync|move|check))")
# Galat yang memang bersifat per-file dan permanen: hanya jenis inilah yang boleh ditoleransi (EPRINTS_TOLERATE_FILES).
_RC_PER_FILE_OK = re.compile(r"downloadQuotaExceeded|cannotDownloadAbusiveFile|malware or spam|exportSizeLimitExceeded"
                             r"|no export format|can't export|shortcut|notFound|object not found|File not found", re.I)


def summarize_rclone_log(log_path, top=3):
    """Ringkas log rclone (hanya baca). Kembalikan dict:
    files = jumlah file berbeda yang gagal disalin, other = galat bukan per-file (konfigurasi, login, disk),
    top = [(jumlah, pesan)], hints = daftar petunjuk."""
    objs, kinds, ringkasan, other, tak_aman, dirs = set(), {}, {}, 0, False, {}
    try:
        fh = open(log_path, encoding="utf-8", errors="replace")
    except OSError:
        return {"files": 0, "other": 0, "top": [], "hints": [], "dirs": [], "toleransi_ok": False}

    def bersihkan(teks):
        # Buang pembungkus rclone yang tidak informatif supaya penyebabnya muat di laporan:
        # "Failed to copy: failed to open source object: open file failed: use the --x flag to download this file: googleapi: ..."
        for pembungkus in (r"Attempt \d+/\d+ failed with \d+ errors? and: ",
                           r"Failed to (?:copy|sync|move|check)(?: with \d+ errors?: last error was)?: ",
                           r"failed to open source object: ",
                           r"open file failed: ",
                           r"use the --[a-z-]+ flag to download this file: "):
            teks = re.sub("^" + pembungkus, "", teks)
        # "googleapi: Error 403: <kalimat panjang>, downloadQuotaExceeded" -> "googleapi 403 downloadQuotaExceeded"
        teks = re.sub(r"googleapi: Error (\d{3}): .*?,\s*([A-Za-z]+)\s*$", r"googleapi \1 \2", teks)
        teks = re.sub(r"\b(?=[0-9A-Za-z_-]*\d)[0-9A-Za-z_-]{24,}\b", "<id>", teks)  # ID file Drive (mengandung angka)
        return re.sub(r"\b\d{5,}\b", "N", teks)[:200]

    with fh:
        for line in fh:
            m = _RC_LOG_LINE.match(line.rstrip("\n"))
            if not m:
                continue
            level, msg = m.groups()
            if level is None and not msg.startswith("Failed to"):
                continue
            if level == "NOTICE" and "Failed" not in msg:
                continue
            obj, sep, rest = msg.partition(": Failed to ")
            if sep:  # galat untuk satu file
                objs.add(obj)
                if "/" in obj:  # hanya FOLDER yang dilaporkan (nama file bisa memuat nama orang)
                    d = bersihkan(obj.rsplit("/", 1)[0])[:60]
                    dirs[d] = dirs.get(d, 0) + 1
                core = bersihkan("Failed to " + rest)
                kinds[core] = kinds.get(core, 0) + 1
                if not _RC_PER_FILE_OK.search(rest):
                    tak_aman = True
            elif _RC_SUMMARY.match(msg):  # baris rangkuman rclone ("Attempt 5/5 failed...", "Failed to copy...")
                core = bersihkan(msg)
                ringkasan[core] = ringkasan.get(core, 0) + 1
            else:  # galat lain: login, konfigurasi, disk, dll.
                other += 1
                core = bersihkan(msg)
                kinds[core] = kinds.get(core, 0) + 1
    if not kinds:  # tidak ada galat rinci: pakai baris rangkuman sebagai penjelasan
        kinds = ringkasan
    ranked = sorted(kinds.items(), key=lambda kv: -kv[1])
    # petunjuk dicari di SEMUA pesan (termasuk rangkuman), bukan hanya 3 teratas
    blob = " ".join(list(kinds) + list(ringkasan))
    hints = [h for rx, h in RCLONE_HINTS if rx.search(blob)]
    return {"files": len(objs), "other": other, "top": [(n, t) for t, n in ranked[:top]], "hints": hints,
            "dirs": [d for d, _n in sorted(dirs.items(), key=lambda kv: -kv[1])[:3]],
            "toleransi_ok": bool(objs) and not tak_aman and other == 0}


_EP_DIR = re.compile(r"^disk\d+/(\d\d)/(\d\d)/(\d\d)/(\d\d)(?:/\d\d)?$")


def _eprints_label(folder):
    """Tata letak dokumen EPrints: disk0/00/00/02/21/01 = rekaman #221, dokumen ke-01 (empat tingkat angka = nomor rekaman)."""
    m = _EP_DIR.match(folder)
    return f"{folder} (EPrints #{int(''.join(m.groups()))})" if m else folder


def prune_old_logs():
    cutoff = time.time() - EPRINTS_LOG_KEEP_DAYS * 86400
    for old in EPRINTS_LOG_DIR.glob("rclone-eprints-*.log"):
        try:
            if old.stat().st_mtime < cutoff:
                old.unlink()
        except OSError:
            pass


def backup_eprints_docs():
    """Dokumen EPrints (GDrive/rclone) -> salinan lokal (rclone copy) -> zip bertanggal di BACKUP/web.
    Pakai copy (bukan sync): file yang terhapus di GDrive tidak ikut terhapus di salinan.
    Versi tahan gagal: galat rclone dicatat ke log dan diringkas ke laporan, dan zip TETAP dibuat dari
    salinan terakhir (berisi _STATUS_SALINAN.txt) supaya satu file bermasalah tidak menghilangkan backup hari itu.
    Tahap tetap ditandai GAGAL bila ada file yang tidak tersalin (kecuali dalam batas EPRINTS_TOLERATE_FILES)."""
    EPRINTS_MIRROR.mkdir(parents=True, exist_ok=True)
    free_gb = shutil.disk_usage(EPRINTS_MIRROR).free / 1024 ** 3
    if free_gb < EPRINTS_MIN_FREE_GB:
        raise RuntimeError(f"ruang kosong {free_gb:.1f} GB < {EPRINTS_MIN_FREE_GB:g} GB di {EPRINTS_MIRROR}: "
                           "tahap EPrints dilewati agar disk tidak penuh")
    EPRINTS_LOG_DIR.mkdir(parents=True, exist_ok=True, mode=0o700)
    log_path = EPRINTS_LOG_DIR / f"rclone-eprints-{today_str}.log"
    log_path.unlink(missing_ok=True)  # run ulang di hari yang sama: log dimulai bersih
    cmd = ["rclone", "copy", EPRINTS_REMOTE, str(EPRINTS_MIRROR), "--transfers", "4",
           "--retries", "5", "--low-level-retries", "10", "--log-level", "ERROR",
           "--log-file", str(log_path), *EPRINTS_EXTRA]
    try:
        rc = subprocess.run(cmd, timeout=3600, stdin=subprocess.DEVNULL).returncode
    except subprocess.TimeoutExpired:
        rc = None  # lewat batas waktu 60 menit
    info = (summarize_rclone_log(log_path) if rc != 0
            else {"files": 0, "other": 0, "top": [], "hints": [], "dirs": [], "toleransi_ok": False})

    backup_web_dir.mkdir(parents=True, exist_ok=True)
    final = backup_web_dir / f"{today_str}-eprints-documents-web.zip"
    partial = final.with_suffix(".zip.partial")
    kode = "timeout 60 menit" if rc is None else str(rc)
    catatan = (f"rclone copy {EPRINTS_REMOTE} selesai dengan kode {kode} pada "
               f"{datetime.datetime.now():%Y-%m-%d %H:%M}.\n"
               + ("Salinan lengkap.\n" if rc == 0 else
                  "Salinan MUNGKIN TIDAK LENGKAP: zip ini dibuat dari salinan lokal terakhir. Lihat log: "
                  f"{log_path}\n"))
    with zipfile.ZipFile(partial, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("_STATUS_SALINAN.txt", catatan)
        for root, _dirs, files in os.walk(EPRINTS_MIRROR):
            for name in files:
                fp = Path(root) / name
                if fp.is_symlink() or not fp.is_file():
                    continue
                zf.write(fp, fp.relative_to(EPRINTS_MIRROR))
    os.replace(partial, final)
    prune_old_logs()
    if rc == 0:
        return final

    parts = ["rclone melewati batas waktu 60 menit" if rc is None else f"rclone keluar dengan kode {rc}"]
    if info["files"]:
        parts.append(f"{info['files']} file gagal disalin")
    if info["dirs"]:
        parts.append("folder: " + ", ".join(_eprints_label(d) for d in info["dirs"]))
    parts += [f"{n}x {text[:90]}" for n, text in info["top"]]
    parts += info["hints"][:2]
    detail = "; ".join(parts)
    # Hanya galat per-file jenis permanen (kuota, spam, ekspor, pintasan, file hilang) dalam batas toleransi
    # yang dianggap peringatan; galat login/konfigurasi/disk/jaringan tidak pernah ditoleransi.
    if rc == 1 and info["toleransi_ok"] and info["files"] <= EPRINTS_TOLERATE_FILES:
        WARNINGS.append(f"EPrints: {detail} (diizinkan sampai {EPRINTS_TOLERATE_FILES} file)")
        return final
    raise RuntimeError(f"{detail}. Zip tetap dibuat dari salinan terakhir. Log: {log_path}")


# --------------------------------------------------------------------------- #
# Zip, Git, kirim
# --------------------------------------------------------------------------- #
def create_zip():
    zip_filename = backup_dir / f"{today_str}-backup_vps.zip"
    partial = zip_filename.with_suffix(".zip.partial")
    with zipfile.ZipFile(partial, "w", zipfile.ZIP_DEFLATED) as zf:
        for sub in (nginx_backup_dir, fail2ban_backup_dir, var_opt_backup_dir,
                    named_backup_dir, supabase_cfg_dir, misc_backup_dir, php_backup_dir):
            for root, _dirs, files in os.walk(sub):
                for name in files:
                    fp = Path(root) / name
                    if fp.is_symlink() or not fp.is_file():
                        continue
                    zf.write(fp, fp.relative_to(backup_dir))
    os.replace(partial, zip_filename)
    return zip_filename


def git(*args, timeout=900, check=True):
    r = subprocess.run(["git", *args], cwd=backup_dir, capture_output=True, text=True,
                       timeout=timeout)
    if check and r.returncode != 0:
        tail = (r.stderr or r.stdout or "").strip()[-800:]
        raise RuntimeError(f"git {' '.join(args)} gagal: {tail}")
    return r


def push_to_gitlab():
    """Commit + push sederhana dengan timeout. Tidak lagi memakai filter-repo / force push."""
    if not (backup_dir / ".git").is_dir():
        raise RuntimeError(f"{backup_dir} bukan repo git")
    exclude = backup_dir / ".git" / "info" / "exclude"
    rules = ["*.zip", "*.zip.partial", "_split_tmp/"]
    for p in backup_dir.rglob("*"):  # file >95 MB ditolak GitLab -> kecualikan
        if ".git" in p.parts or not p.is_file():
            continue
        if p.stat().st_size > 95 * 1024 * 1024:
            rel = str(p.relative_to(backup_dir))
            rules.append("/" + rel)
            git("rm", "--cached", "-q", "--ignore-unmatch", rel, check=False)
    exclude.write_text("\n".join(sorted(set(rules))) + "\n")

    git("add", "-A")
    if git("diff", "--cached", "--quiet", check=False).returncode == 0:
        print("Git: tidak ada perubahan", flush=True)
        return
    git("commit", "-q", "-m", f"Backup on {today_str}")
    if git("push", "origin", "main", check=False).returncode == 0:
        return
    # remote lebih baru: rebase (tanpa merge, tanpa force). Bila konflik, kembalikan repo ke keadaan
    # sebelum rebase supaya job berikutnya tidak macet di tengah rebase; commit lokal tetap ada.
    if git("pull", "--rebase", "origin", "main", check=False).returncode != 0:
        git("rebase", "--abort", check=False)
        raise RuntimeError("push Git ditunda: konflik dengan remote, selesaikan manual (commit lokal aman, tidak ada force push)")
    git("push", "origin", "main")


def send_backups_in_priority(main_zip):
    # Gambar 3.3: hanya salinan yang lolos verifikasi M4 yang keluar dari server.
    # 1. Backup utama (jika >1.9 GB dipecah otomatis)
    if lolos_verifikasi(main_zip):
        send_file(main_zip, allow_split=True)
    else:
        send_message(f"⚠️ backup_vps {os.uname().nodename}: zip VPS GAGAL verifikasi M4, tidak dikirim ke tingkat 2.")
    try:
        harian_ok = subprocess.run([BACKUP_VERIFY, "--lolos-hari-ini"], timeout=60).returncode == 0
    except (OSError, subprocess.SubprocessError):
        harian_ok = False
    if not harian_ok:
        send_message(f"⚠️ backup_vps {os.uname().nodename}: verifikasi harian dump/zip situs belum PASS, "
                     "salinan DB dan web TIDAK dikirim ke tingkat 2.")
        return
    # 2. Database hari ini
    if backup_db_dir.exists():
        for f in sorted(backup_db_dir.iterdir()):
            if today_str in f.name and f.name.endswith(".gz"):
                send_file(f)
    # 3. Web zip hari ini, terkecil dulu (yang >1.9 GB dilewati + dilaporkan)
    if backup_web_dir.exists():
        webs = sorted((f for f in backup_web_dir.iterdir()
                       if today_str in f.name and f.name.endswith(".zip")),
                      key=lambda f: f.stat().st_size)
        for f in webs:
            send_file(f)


def finalize_zip(zip_file):
    """Jadikan backup_vps.zip (dipakai cek-disk.py), hapus sisa zip bertanggal lama."""
    os.replace(zip_file, backup_dir / "backup_vps.zip")
    for old in backup_dir.glob("*-backup_vps.zip*"):
        if today_str not in old.name:
            old.unlink(missing_ok=True)
            print(f"Sisa lama dihapus: {old.name}", flush=True)


# --------------------------------------------------------------------------- #
# Orkestrasi
# --------------------------------------------------------------------------- #
RESULTS = []


def stage(name, fn, *args):
    """Jalankan satu tahap; kegagalan satu tahap tidak menghentikan tahap lain."""
    t0 = time.time()
    print(f"==> {name}", flush=True)
    try:
        value = fn(*args)
        RESULTS.append((name, True, "", time.time() - t0))
        return value
    except Exception as exc:  # noqa: BLE001
        traceback.print_exc()
        RESULTS.append((name, False, " ".join(str(exc).split())[:450], time.time() - t0))
        return None


def eprints_aktif():
    """Tahap EPrints hanya jalan bila remote rclone-nya memang ada (kampus lain mungkin tidak punya EPrints)."""
    if not shutil.which("rclone"):
        return False
    r = subprocess.run(["rclone", "listremotes"], capture_output=True, text=True)
    return EPRINTS_REMOTE.rstrip(":") + ":" in r.stdout.split()


def main():
    lock = open(LOCK_FILE, "w")
    try:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        send_message("⚠️ backup_vps.py: run sebelumnya masih berjalan, run ini dibatalkan.")
        return 1

    started = time.time()
    stage("siapkan folder", create_backup_dirs)
    stage("config sistem", backup_files)
    if SUPABASE_DIR.is_dir():
        stage("supabase config", backup_supabase_config)
        dump = stage("supabase dump DB", dump_supabase_db)
        stage("supabase dump -> GDrive", upload_supabase_dump, dump)
        stage("supabase storage -> GDrive", sync_supabase_storage)
    else:
        WARNINGS.append("Supabase dilewati (folder %s tidak ada)" % SUPABASE_DIR)
    stage("salin /var/opt", backup_var_opt)
    stage("salin sql-backup", copy_sql_backups)
    if eprints_aktif():
        stage("eprints dokumen -> lokal + zip", backup_eprints_docs)
    zip_file = stage("zip backup VPS", create_zip)
    if zip_file:
        stage("kirim Telegram", send_backups_in_priority, zip_file)
        stage("finalisasi zip", finalize_zip, zip_file)
    if (backup_dir / ".git").exists():
        stage("push GitLab", push_to_gitlab)  # terakhir: tidak boleh menghalangi pengiriman
    else:
        WARNINGS.append("push Git dilewati: %s belum repo git (lihat README bagian tingkat 2)" % backup_dir)

    failed = [r for r in RESULTS if not r[1]]
    lines = [f"{'✅' if ok else '❌'} {name} ({dur:.0f}s){(' - ' + msg) if msg else ''}"
             for name, ok, msg, dur in RESULTS]
    header = "❌ Backup VPS SELESAI DENGAN ERROR" if failed else "✅ Backup VPS selesai"
    summary = [f"{header} {today_str} ({(time.time() - started) / 60:.1f} menit)", *lines,
               f"Terkirim: {len(SENT)} file"]
    if FAILED:
        summary.append("Gagal kirim: " + ", ".join(FAILED))
    if SKIPPED:
        summary.append("Dilewati (>1.9 GB, tidak muat di Telegram): " + ", ".join(SKIPPED))
    if WARNINGS:
        summary.append("⚠️ Peringatan: " + "; ".join(WARNINGS))
    send_message("\n".join(summary))
    print("\n".join(summary), flush=True)
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
