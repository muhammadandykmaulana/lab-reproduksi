#!/usr/bin/env bash
# demo-lab.sh - simulasi AMAN untuk melihat lab bekerja tanpa menyentuh situs, database, atau firewall.
# Semua terjadi di /var/tmp/lab-demo. "Webshell" yang dipakai hanya teks penanda tidak berbahaya (tidak bisa dijalankan).
#   sudo bash demo-lab.sh              jalankan demo
#   sudo bash demo-lab.sh --bersihkan  hapus folder demo
# Bila token Telegram sudah diisi, alert demo ikut dikirim ke Telegram (supaya terlihat notifikasinya).
set -uo pipefail
DIR="$(cd "$(dirname "$0")/.." && pwd)"
. "$DIR/lib/umum.sh"
perlu_root
DEMO=/var/tmp/lab-demo
sumber() { find "$DIR/modul" "$DIR/lingkungan" -name "$1" -type f | head -1; }   # script dicari di folder modul
if [ "${1:-}" = "--bersihkan" ]; then
  case "$DEMO" in /var/tmp/lab-demo) rm -rf --one-file-system "$DEMO"; sukses "folder demo dihapus";; esac; exit 0
fi
langkah() { printf '\n%s--- Langkah %s ---%s\n' "$B" "$*" "$N"; }
jeda() { [ -t 0 ] && [ "$OTOMATIS" != 1 ] && read -r -t 30 -p "   (Enter untuk lanjut) " _ ; echo; }

rm -rf --one-file-system "$DEMO"; mkdir -p "$DEMO"/{www,bin,run,baseline,bukti,backup/web,backup/DB,pulih}; chmod 700 "$DEMO"
# klien database tiruan: demo tidak pernah menyentuh database sungguhan
printf '#!/bin/sh\nexit 1\n' > "$DEMO/bin/mariadb"; cp "$DEMO/bin/mariadb" "$DEMO/bin/mysql"; chmod 755 "$DEMO"/bin/*
# konfigurasi demo: token Telegram (bila ada) dipakai, jalur lain diarahkan ke folder demo
{ echo "TELEGRAM_BOT_TOKEN=\"$(get_kv "$ENV_WI" TELEGRAM_BOT_TOKEN)\""; echo "TELEGRAM_CHAT_ID=\"$(get_kv "$ENV_WI" TELEGRAM_CHAT_ID)\""; echo "TELEGRAM_API_BASE=\"$(get_kv "$ENV_WI" TELEGRAM_API_BASE)\""
  echo "WEBROOT=\"$DEMO/www\""; echo "HASHDB_DIR=\"$DEMO/baseline\""; echo "BUKTI_DIR=\"$DEMO/bukti\""; echo "OJS_DB=\"lab_demo_tidak_ada\""
  echo "BACKUP_WEB_DIR=\"$DEMO/backup/web\""; echo "BACKUP_DB_DIR=\"$DEMO/backup/DB\""; echo "BACKUP_VPS_DIR=\"$DEMO/backup/vps\""; } > "$DEMO/env"
chmod 600 "$DEMO/env"
salin() { sed "s#/etc/web-integrity.env#$DEMO/env#g" "$(sumber "$1")" > "$DEMO/$1"; chmod 700 "$DEMO/$1"; }
salin web-integrity-cek.sh; salin backup-verify.sh; salin webscan-wp.sh; salin notify-run.sh
export PATH="$DEMO/bin:$PATH" WI_LOCK="$DEMO/run/wi.lock" TMPDIR="$DEMO/run" BV_STATE_DIR="$DEMO/run/bv"

langkah "1. Membuat dua situs tiruan (pola WordPress) di $DEMO/www"
for s in kampus.ac.id lppm.kampus.ac.id; do
  mkdir -p "$DEMO/www/$s"/{wp-includes,wp-admin,wp-content/plugins/akismet,wp-content/uploads/2026/11}
  echo '<?php /* inti WordPress tiruan */ echo "halo";' > "$DEMO/www/$s/index.php"
  echo '<?php $wp_version = "6.8";' > "$DEMO/www/$s/wp-includes/version.php"
  echo '<?php /* plugin sah */' > "$DEMO/www/$s/wp-content/plugins/akismet/akismet.php"
  echo 'gambar' > "$DEMO/www/$s/wp-content/uploads/2026/11/poster.jpg"
done
find "$DEMO/www" -type f | sed "s#$DEMO/www/#    #"
jeda

langkah "2. Membuat BASELINE (sidik jari SHA-256 tiap berkas kode) saat situs masih bersih"
bash "$DEMO/web-integrity-cek.sh" --rebuild
jeda

langkah "3. Simulasi serangan judol (penanda tidak berbahaya, tidak bisa dijalankan)"
S="$DEMO/www/lppm.kampus.ac.id"
printf '%s\n' '<?php /* LAB-DEMO: penanda webshell <<S>> - teks saja, tidak berbahaya */ ?>' > "$S/wp-content/uploads/2026/11/cache.php"
mkdir -p "$S/wp-content/plugins/security-headers-manager-289fd9"
printf '%s\n' '<?php /* LAB-DEMO: plugin samaran baru */' > "$S/wp-content/plugins/security-headers-manager-289fd9/index.php"
echo '<?php $wp_version = "6.8"; /* diubah penyerang */' > "$DEMO/www/kampus.ac.id/wp-includes/version.php"
echo "   + berkas PHP di folder unggahan (wp-content/uploads/2026/11/cache.php) berisi penanda webshell"
echo "   + folder plugin baru berpola samaran (security-headers-manager-289fd9)"
echo "   ~ berkas inti diubah (wp-includes/version.php)"
jeda

langkah "4. Deteksi: web-integrity-cek.sh membandingkan dengan baseline (alert ikut ke Telegram bila token terisi)"
bash "$DEMO/web-integrity-cek.sh" 2>&1 | sed 's/^/   /' | head -30
jeda

langkah "4b. Menerima baseline baru DITOLAK selama masih ada IOC (opsi --accept --yes, dipakai gerbang T2)"
bash "$DEMO/web-integrity-cek.sh" --accept --yes 2>&1 | tail -2 | sed 's/^/   /'
echo "   kode keluar 3 = baseline tidak diubah; manusia harus menyelidiki dulu (collect3_evidence.sh)."
jeda

langkah "5. Masalah di lapangan: backup malam ini IKUT menyimpan berkas yang sudah disusupi"
TGL=$(date +%Y_%m_%d); KMRN=$(date -d yesterday +%Y_%m_%d)
( cd "$DEMO/www" && zip -qr "$DEMO/backup/web/${KMRN}-lppm.kampus.ac.id-web.zip" lppm.kampus.ac.id && zip -qr "$DEMO/backup/web/${TGL}-lppm.kampus.ac.id-web.zip" lppm.kampus.ac.id )
touch -d yesterday "$DEMO/backup/web/${KMRN}-lppm.kampus.ac.id-web.zip"
printf -- '-- MariaDB dump tiruan\nCREATE TABLE t (id int);\n-- Dump completed on %s\n' "$(date '+%F %T')" | gzip > "$DEMO/backup/DB/${TGL}-wp_kampus.sql.gz"
gzip -c < /dev/null > "$DEMO/backup/DB/${TGL}-wp_lppm.sql.gz"     # dump KOSONG (20 byte) seperti kasus lapangan
chmod 600 "$DEMO"/backup/*/*
echo "   Tim TI biasanya hanya memastikan berkas backup ADA. backup-verify.sh memeriksa apakah backup BISA DIPAKAI:"
bash "$DEMO/backup-verify.sh" 2>&1 | sed 's/^/   /'
bash "$DEMO/backup-verify.sh" --lolos-hari-ini && echo "   penanda lolos ada" \
  || echo "   Penanda lolos TIDAK dibuat: pengiriman ke Google Drive/Telegram dan rotasi backup lama DITAHAN (Gambar 3.3)."
jeda

langkah "6. Sebelum restore: periksa ISI backup (jangan memulihkan berkas yang sudah disusupi)"
unzip -q "$DEMO/backup/web/${TGL}-lppm.kampus.ac.id-web.zip" -d "$DEMO/pulih"
bash "$DEMO/webscan-wp.sh" -p "$DEMO/pulih" 2>/dev/null | grep -E 'IOC|PHP-DI-FOLDER-DATA|SAMARAN|NAMA-ACAK|\[(WARN|FAIL)\]' | sed 's/^/   /' | head -15
echo "   Kesimpulan: backup ini mengandung webshell. Pulihkan dari backup SEBELUM tanggal penyusupan, lalu bersihkan."
jeda

langkah "Selesai"
echo "   Demo hanya memakai $DEMO. Hapus dengan: sudo bash $DIR/lab.sh demo-bersihkan"
echo "   Untuk server sungguhan: lab.sh baseline -> lab.sh cek -> lab.sh jadwal-pasang"
