#!/usr/bin/env bash
# arsip-log.sh - salin log akses Nginx yang sudah dirotasi ke arsip bertanggal, supaya data baseline dan evaluasi
# tidak ikut terhapus oleh logrotate (retensi log server hanya 14-28 hari).
# Hasil: /var/opt/arsip-log/nginx/<nama-log>-YYYY-MM-DD.log.gz (root, izin 600). Aman dijalankan berulang.
# Jadwal: 40 0 * * * root /var/opt/script/tools/arsip-log.sh
set -uo pipefail
SUMBER=${ARSIP_SUMBER:-/var/log/nginx}
A=${ARSIP_DIR:-/var/opt/arsip-log/nginx}
mkdir -p "$A"; chmod 700 "$(dirname "$A")" "$A"
n=0
for f in "$SUMBER"/*access.log.[0-9]*; do
  [ -f "$f" ] || continue
  # tanggal isi = hari sebelum berkas dirotasi (waktu ubah terakhir dikurangi 1 jam)
  d=$(date -d @$(( $(stat -c %Y "$f") - 3600 )) +%F)
  b=$(basename "$f" | sed -E 's/\.log\.[0-9]+(\.gz)?$//')
  t="$A/$b-$d.log.gz"
  [ -e "$t" ] && continue
  case "$f" in *.gz) cp -p "$f" "$t";; *) gzip -c "$f" > "$t";; esac
  chmod 600 "$t"; n=$((n+1))
done
echo "arsip-log: $n berkas baru di $A ($(ls "$A" | wc -l) berkas total)"
