#!/usr/bin/env bash
# cek-rahasia.sh - periksa folder lab sebelum diunggah ke GitHub. HANYA MEMBACA.
# Pakai: bash cek-rahasia.sh [FOLDER]      (bawaan: folder tempat script ini berada)
# Kode keluar 0 = bersih, 1 = ada temuan (jangan push sebelum diperbaiki). Isi rahasia tidak pernah dicetak,
# hanya nama berkas dan nomor barisnya, supaya keluaran aman ditempel ke chat.
# Yang dicari: token Telegram, token/kunci Cloudflare-Google-AbuseIPDB, kunci privat, kata sandi tertulis langsung,
# chat id grup sungguhan, serta berkas yang seharusnya tidak ada di repositori (env, dump, backup, log).
set -uo pipefail
DIR=${1:-$(dirname "$(readlink -f "$0")")}
cd "$DIR" || exit 2
temuan=0
lapor() { echo "[FAIL] $*"; temuan=1; }

# 1. berkas yang tidak boleh ada
while IFS= read -r f; do lapor "berkas tidak boleh diunggah: $f"; done < <(
  find . -path ./.git -prune -o -type f \( -name '*.env' -o -name '.env' -o -name '*.sql' -o -name '*.sql.gz' -o -name '*.dump' \
    -o -name '*.zip' -o -name '*.tar.gz' -o -name '*.log' -o -name '*.pem' -o -name '*.key' -o -name 'rclone.conf' -o -name '*.bak-*' \) -print)

# 2. pola rahasia di dalam isi berkas (contoh dokumentasi dikecualikan)
POLA='[0-9]{8,10}:AA[A-Za-z0-9_-]{30,}|cfut_[A-Za-z0-9_-]{10,}|AIza[0-9A-Za-z_-]{30,}|-----BEGIN [A-Z ]*PRIVATE KEY-----|\b[a-f0-9]{80}\b|-100[0-9]{10}'
while IFS= read -r baris; do
  case "$baris" in *-1001234567890*) continue;; esac
  lapor "pola rahasia di $(echo "$baris" | cut -d: -f1,2) (isi tidak ditampilkan)"
done < <(grep -rnIE "$POLA" . --exclude-dir=.git --exclude=cek-rahasia.sh 2>/dev/null)

# 3. kata sandi tertulis langsung (nilai bukan kosong dan bukan variabel)
while IFS= read -r baris; do
  lapor "kata sandi tertulis langsung di $(echo "$baris" | cut -d: -f1,2) (isi tidak ditampilkan)"
done < <(grep -rnIiE "(password|passwd|DB_PASSWORD|pass)[\"' ]*[:=][ ]*[\"'][^\"'\$<{ ]{4,}[\"']" . --exclude-dir=.git --exclude=cek-rahasia.sh 2>/dev/null \
         | grep -viE "example|contoh|xxxx|changeme|isi[-_ ]|placeholder")

# 4. nilai khusus server yang seharusnya sudah diganti variabel
while IFS= read -r baris; do
  lapor "nilai khusus server: $(echo "$baris" | cut -c1-120)"
done < <(grep -rnIE "/home/[a-z_][a-z0-9_]+/|safe\.directory '\*'" . --exclude-dir=.git --exclude=cek-rahasia.sh 2>/dev/null \
         | grep -vE "/home/(user|nama|USER)/")

if [ $temuan -eq 0 ]; then echo "[ OK ] tidak ditemukan rahasia atau berkas terlarang di $DIR"; exit 0; fi
echo; echo "Perbaiki temuan di atas sebelum git push."; exit 1
