# -*- coding: utf-8 -*-
"""T3 (manual admin only): sistem HANYA mencetak checklist Markdown. Tidak ada yang dieksekusi."""

import os
import time

from .sanitizer import clean
from .util import fmt_local

COMMON_FIRST = [
    "Amankan bukti: salin `/var/lib/bodyguard-evidence/{inc}/` ke media terpisah (read-only), catat SHA256-nya.",
    "Jangan menghapus file/akun penyerang sebelum bukti diamankan dan dicatat.",
    "Periksa hasil T1/T2 yang sudah berjalan: `sudo -u guard /opt/bodyguard/bin/bodyguard status`.",
]
ROTATE = [
    "Ganti password DB di `wp-config.php` tiap situs; buat user DB baru dengan hak minimum, cabut user lama.",
    "Ganti 8 konstanta AUTH_KEY/SALT WordPress (semua sesi otomatis terputus).",
    "OJS: ganti `salt`, `api_key_secret`, dan password DB di `config.inc.php`.",
    "Reset password semua akun admin WordPress/OJS; aktifkan 2FA bila tersedia.",
    "Ganti kunci SSH, akun FTP/panel, dan token bot Telegram yang mungkin terekspos (termasuk milik notify-run.sh).",
    "Bila server diduga disusupi sampai level root: ganti juga `BG_HMAC_KEY` dan kedua token bot Bodyguard.",
]
PER_KIND = {
    "PHP_IN_DATA_DIR": ("Webshell / PHP liar di folder data", [
        "Telusuri log akses +-48 jam di sekitar mtime file untuk mencari IP pengunggah dan vektornya.",
        "Cari salinan berhash sama di situs lain (`grep` SHA256 di laporan Bodyguard).",
        "Pastikan nginx menolak eksekusi PHP di folder data, mis. `location ~* /wp-content/uploads/.*\\.php$ { deny all; }`.",
        "Identifikasi & tambal/hapus plugin/form unggah yang menjadi pintu masuk.",
    ]),
    "POLYGLOT_FILE": ("File polyglot (PHP tersembunyi di gambar/EXIF)", [
        "Periksa apakah ada include/LFI yang bisa mengeksekusi file gambar (cari `include`/`require` dengan input pengguna).",
        "Telusuri siapa yang mengunggah file (log akses + tabel media WordPress/OJS).",
    ]),
    "SYMLINK_IN_DATA_DIR": ("Symlink di folder data", [
        "Periksa target symlink (bisa dipakai membaca file sensitif lewat web); hapus manual setelah dicatat.",
    ]),
    "IOC_IN_CODE": ("IOC di file kode (tema/plugin/core)", [
        "Bandingkan dengan sumber resmi (`wp core verify-checksums`, paket plugin asli); ganti file dari sumber bersih.",
        "Jangan 'mengedit keluar' webshell dari file kode; pasang ulang komponen secara utuh.",
    ]),
    "SUSPICIOUS_PLUGIN": ("Plugin samaran", [
        "Periksa `wp_options` (active_plugins, opsi autoload, cron) untuk sisa tanaman plugin.",
        "Setelah forensik, hapus folder plugin `.bg-disabled-*` secara manual.",
    ]),
    "WP_ADMIN_IOC": ("Akun admin WordPress berbahaya", [
        "Audit aktivitas akun: post/halaman baru, user baru, perubahan `siteurl`/`home`, opsi berisi skrip.",
        "Cek `wp_usermeta` untuk role/kapabilitas kustom; hapus akun setelah forensik.",
    ]),
    "OJS_PRIV_IOC": ("Akun istimewa OJS berbahaya", [
        "Audit submission, file, dan pengaturan jurnal (email, plugin OJS) yang diubah akun tersebut.",
    ]),
}
MIGRATION = [
    "JANGAN memigrasikan kode dari server ini; ambil kode bersih dari sumber resmi.",
    "Migrasikan hanya data: DB setelah audit akun, uploads setelah pindai IOC ulang di server baru.",
    "Rotasi SEMUA rahasia setelah cutover (anggap kredensial lama bocor).",
    "Pasang Bodyguard di server baru dengan baseline baru, mulai dari mode dry-run.",
]
DB_RESET = [
    "Sebelum reset/restore apa pun: dump forensik (`mysqldump --single-transaction`) dan simpan terpisah.",
    "Pilih backup sebelum waktu kompromi pertama (lihat mtime webshell tertua di bukti).",
    "Tidak ada DROP/TRUNCATE tanpa persetujuan tertulis pimpinan dan bukti sudah aman.",
]


def _md(text, n=160):
    return clean(text, n).replace("|", "\\|").replace("`", "'")


def build_checklist(cfg, incident_id, findings, now=None):
    now = time.time() if now is None else now
    out = ["# Checklist T3 - %s" % incident_id, "",
           "Dibuat %s. **Dokumen ini hanya daftar periksa: Bodyguard tidak menjalankan satu pun langkah di bawah.**"
           % fmt_local(now, cfg.tz_offset, cfg.tz_label), "", "## Ringkasan temuan", "",
           "| Jenis | Severity | Contoh target |", "|---|---|---|"]
    seen = {}
    for f in findings:
        if f.severity == "info":
            continue
        key = (f.kind, f.severity)
        if key not in seen:
            seen[key] = f.target
    for (kind, sev), target in sorted(seen.items()):
        out.append("| %s | %s | `%s` |" % (kind, sev, _md(target)))
    out += ["", "## Langkah pertama"] + ["- [ ] " + s.format(inc=incident_id) for s in COMMON_FIRST]
    out += ["", "## Rotasi rahasia"] + ["- [ ] " + s for s in ROTATE]
    kinds = set(f.kind for f in findings)
    for kind in sorted(PER_KIND):
        if kind in kinds:
            title, steps = PER_KIND[kind]
            out += ["", "## " + title] + ["- [ ] " + s for s in steps]
    out += ["", "## Migrasi (server sedang menunggu jadwal migrasi)"] + ["- [ ] " + s for s in MIGRATION]
    out += ["", "## Reset / restore database"] + ["- [ ] " + s for s in DB_RESET]
    out += ["", "_Teks target di atas berasal dari data penyerang dan sudah disanitasi; jangan disalin ke shell._", ""]
    return "\n".join(out)


def write_checklist(cfg, incident_id, findings, now=None):
    d = os.path.join(cfg.state_dir, "checklists")
    if not os.path.isdir(d):
        os.makedirs(d, 0o700)
    path = os.path.join(d, "%s.md" % incident_id)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        f.write(build_checklist(cfg, incident_id, findings, now))
    return path
