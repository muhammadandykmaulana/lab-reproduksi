#!/usr/bin/env bash
# backup-verify.sh - Modul M4: memastikan backup benar-benar BISA DIPAKAI, bukan sekadar ada.
# v2: dump PostgreSQL dikenali; izin berkas backup dirapikan otomatis ke 600; uji pulih hanya memakai dump MariaDB yang utuh
# Rancangan: Skripsi Bab III bagian D.8 dan Gambar 3.3 (verifikasi sebelum pengiriman dan rotasi).
# Pemeriksaan per kelompok berkas (nama tanpa tanggal, mis. "jurnal-web.zip", "wp_utama.sql.gz"):
#   umur berkas terbaru < MAX_JAM (30); keutuhan (gzip -t, tar -tzf, unzip -tq, penutup "Dump completed" pada dump SQL);
#   rasio ukuran terhadap rata-rata 7 backup sebelumnya (< 50% = mencurigakan); izin berkas; ruang disk partisi (>= 90%).
# Pakai (root):
#   backup-verify.sh                    verifikasi harian
#   backup-verify.sh --restore-test     + pulihkan dump SQL terbaru ke database sementara zz_restore_test_PID,
#                                         hitung tabel, catat waktu (RTO tingkat 1), lalu hapus database sementara itu
#   RESTORE_DUMP=/path/x.sql.gz backup-verify.sh --restore-test    pilih dump tertentu
#   backup-verify.sh --berkas F         periksa satu berkas saja (dipakai backup_vps.py sebelum mengirim zip VPS)
#   backup-verify.sh --lolos-hari-ini   kode 0 bila verifikasi harian hari ini PASS (syarat rclone dan rotasi)
# Bila verifikasi harian tanpa FAIL, dibuat penanda $STATE_DIR/lolos-YYYY-MM-DD. Pengiriman ke tingkat 2/3
# dan rotasi oleh cek-disk.py hanya berjalan bila penanda hari ini ada (Gambar 3.3).
# Folder: BACKUP_WEB_DIR (bawaan /var/opt/BACKUP/web), BACKUP_DB_DIR (/var/opt/BACKUP/DB), BACKUP_VPS_DIR (/var/opt/BACKUP/vps)
# Keluaran [ OK ]/[WARN]/[FAIL]; kode keluar 1 bila ada FAIL. Kirim ke Telegram lewat notify-run.sh.
set -uo pipefail
export LC_ALL=C
[ -f /etc/web-integrity.env ] && . /etc/web-integrity.env
WEB=${BACKUP_WEB_DIR:-/var/opt/BACKUP/web}
DB=${BACKUP_DB_DIR:-/var/opt/BACKUP/DB}
VPS=${BACKUP_VPS_DIR:-/var/opt/BACKUP/vps}
MAX_JAM=${MAX_JAM:-30}
STATE_DIR=${BV_STATE_DIR:-/var/lib/backup-verify}
RESTORE=0
case "${1:-}" in
  --restore-test) RESTORE=1;;
  --lolos-hari-ini) [ -e "$STATE_DIR/lolos-$(date +%F)" ]; exit $?;;
  --berkas) f=${2:?berkas}; [ -f "$f" ] || { echo "[FAIL] $f tidak ada"; exit 1; }
            BERKAS_MODE=1;;
  "") ;;
  *) echo "opsi tidak dikenal: $1"; exit 2;;
esac
NF=0; NW=0
ok()   { echo "[ OK ] $*"; }
warn() { echo "[WARN] $*"; NW=$((NW+1)); }
fail() { echo "[FAIL] $*"; NF=$((NF+1)); }
human() { numfmt --to=iec --suffix=B "$1" 2>/dev/null || echo "${1}B"; }

cek_isi() {  # $1 = berkas; cetak alasan bila rusak, kode 0 bila utuh
  case "$1" in
    *.sql.gz) gzip -t "$1" 2>/dev/null || { echo "gzip rusak"; return 1; }
              zcat "$1" 2>/dev/null | tail -c 400 | grep -qE 'Dump completed|PostgreSQL database dump complete' || { echo "dump terpotong atau KOSONG (tidak ada baris penutup)"; return 1; };;
    *.tar.gz|*.tgz) tar -tzf "$1" >/dev/null 2>&1 || { echo "tar.gz rusak"; return 1; };;
    *.gz)     gzip -t "$1" 2>/dev/null || { echo "gzip rusak"; return 1; };;
    *.zip)    unzip -tq "$1" >/dev/null 2>&1 || { echo "zip rusak (unzip -t gagal)"; return 1; };;
    *.sql)    tail -c 400 "$1" | grep -qE 'Dump completed|PostgreSQL database dump complete' || { echo "tidak ada penutup 'Dump completed'"; return 1; };;
  esac
  return 0
}

if [ "${BERKAS_MODE:-0}" = 1 ]; then
  if alasan=$(cek_isi "$f"); then
    sz=$(stat -c %s "$f"); [ "$sz" -gt 1024 ] || { fail "$(basename "$f") hanya ${sz} byte"; exit 1; }
    ok "$(basename "$f") $(human "$sz") utuh"; exit 0
  fi
  fail "$(basename "$f") $alasan"; exit 1
fi
echo "== backup-verify $(hostname) $(date '+%F %T') | batas umur ${MAX_JAM} jam =="
for dir in "$WEB" "$DB" "$VPS"; do
  [ -d "$dir" ] || { [ "$dir" = "$VPS" ] || warn "folder backup $dir tidak ada"; continue; }
  echo "-- $dir"
  nb=$(find "$dir" -maxdepth 1 -type f -perm /077 | wc -l); [ "$nb" -gt 0 ] && find "$dir" -maxdepth 1 -type f -perm /077 -exec chmod 600 {} + && echo "[INFO] izin $nb berkas di $dir dirapikan menjadi 600 (hanya root)"
  # kelompok = nama berkas tanpa awalan tanggal YYYY_MM_DD- / YYYY-MM-DD-
  find "$dir" -maxdepth 1 -type f \( -name '*.zip' -o -name '*.gz' -o -name '*.tgz' -o -name '*.sql' \) ! -name '*.partial' -printf '%T@\t%s\t%m\t%p\n' \
    | awk -F'\t' '{ n=$4; sub(/.*\//,"",n); g=n; sub(/^[0-9]{4}[_-][0-9]{2}[_-][0-9]{2}[-_]/,"",g); print g"\t"$0 }' \
    | sort -t$'\t' -k1,1 -k2,2nr > /run/bv.$$ 2>/dev/null || { warn "tidak bisa membaca $dir"; continue; }
  [ -s /run/bv.$$ ] || { if [ "$dir" = "$VPS" ]; then echo "[INFO] $dir kosong (backup VPS tingkat 2 belum diarahkan ke sini)"; else warn "$dir kosong (belum ada backup)"; fi; continue; }
  for g in $(cut -f1 /run/bv.$$ | sort -u); do
    mapfile -t baris < <(awk -F'\t' -v g="$g" '$1==g' /run/bv.$$)
    IFS=$'\t' read -r _ t sz mode f <<< "${baris[0]}"
    umur=$(( ( $(date +%s) - ${t%.*} ) / 3600 ))
    masalah=""
    [ "$umur" -ge "$MAX_JAM" ] && { fail "$g: backup terbaru berumur ${umur} jam (> ${MAX_JAM}) -> $(basename "$f")"; masalah=1; }
    alasan=$(cek_isi "$f") || { fail "$(basename "$f"): $alasan"; masalah=1; }
    # rasio ukuran terhadap rata-rata hingga 7 backup sebelumnya
    if [ "${#baris[@]}" -gt 1 ]; then
      rata=$(printf '%s\n' "${baris[@]:1:7}" | awk -F'\t' '{s+=$3; n++} END{if(n) printf "%d", s/n; else print 0}')
      if [ "$rata" -gt 0 ] && [ $(( sz * 100 / rata )) -lt 50 ]; then
        warn "$g: ukuran $(human "$sz") hanya $(( sz * 100 / rata ))% dari rata-rata $(human "$rata") (mencurigakan: isi hilang?)"; masalah=1
      fi
    fi
    case "$mode" in *[1-7]) warn "$g: $(basename "$f") bisa dibaca pengguna lain (izin $mode, sebaiknya 600/640)"; masalah=1;; esac
    [ -z "$masalah" ] && ok "$g: $(basename "$f") $(human "$sz"), ${umur} jam, utuh"
  done
  rm -f /run/bv.$$
  pakai=$(df -P "$dir" | awk 'NR==2{gsub("%","",$5); print $5}')
  [ "${pakai:-0}" -ge 90 ] && warn "partisi $dir terpakai ${pakai}% (>= 90%)"
done

if [ "$RESTORE" -eq 1 ]; then
  echo "-- uji pulih (restore drill) tingkat 1"
  MYSQL=$(command -v mariadb || command -v mysql) || { fail "klien mariadb/mysql tidak ada, uji pulih dilewati"; MYSQL=""; }
  dump=${RESTORE_DUMP:-$(for d in $(ls -t "$DB"/*.sql.gz 2>/dev/null); do zcat "$d" 2>/dev/null | head -c 3000 | grep -q PostgreSQL && continue; cek_isi "$d" >/dev/null && { echo "$d"; break; }; done)}  # dump MariaDB utuh terbaru; dump PostgreSQL dilewati
  if [ -n "$MYSQL" ] && [ -n "$dump" ] && [ -f "$dump" ]; then
    if zcat "$dump" | grep -m1 -qiE '^(CREATE DATABASE|USE `|GRANT |SET GLOBAL)'; then
      fail "$(basename "$dump") memuat CREATE DATABASE/USE/GRANT/SET GLOBAL: TIDAK dipulihkan supaya tidak menimpa database produksi"
    else
      TMPDB="zz_restore_test_$$"
      trap '"$MYSQL" -e "DROP DATABASE IF EXISTS \`'"$TMPDB"'\`" 2>/dev/null' EXIT INT TERM
      mulai=$(date +%s.%N)
      if "$MYSQL" -e "CREATE DATABASE \`$TMPDB\`" && zcat "$dump" | "$MYSQL" "$TMPDB"; then
        selesai=$(date +%s.%N)
        n=$("$MYSQL" -N -B -e "SELECT COUNT(*) FROM information_schema.tables WHERE table_schema='$TMPDB'")
        dtk=$(awk -v a="$mulai" -v b="$selesai" 'BEGIN{printf "%.1f", b-a}')
        if [ "${n:-0}" -gt 0 ]; then ok "uji pulih $(basename "$dump"): $n tabel dalam ${dtk} detik (RTO tingkat 1 untuk dump ini)"
        else fail "uji pulih $(basename "$dump"): selesai tetapi 0 tabel (dump kosong?)"; fi
      else
        fail "uji pulih $(basename "$dump") GAGAL (lihat galat MariaDB di atas)"
      fi
      "$MYSQL" -e "DROP DATABASE IF EXISTS \`$TMPDB\`"; trap - EXIT INT TERM
    fi
  elif [ -n "$MYSQL" ]; then fail "tidak ada dump .sql.gz di $DB untuk uji pulih"; fi
fi

echo
echo "Ringkasan: FAIL=$NF WARN=$NW"
if [ "$RESTORE" -eq 0 ]; then
  mkdir -p "$STATE_DIR"; chmod 700 "$STATE_DIR"
  if [ "$NF" -eq 0 ]; then date '+%F %T' > "$STATE_DIR/lolos-$(date +%F)"; echo "Penanda lolos dibuat: pengiriman ke luar server dan rotasi diizinkan."
  else rm -f "$STATE_DIR/lolos-$(date +%F)"; echo "Ada FAIL: pengiriman ke luar server dan rotasi DITAHAN."; fi
  find "$STATE_DIR" -name 'lolos-*' -mtime +30 -delete 2>/dev/null
fi
exit $([ "$NF" -gt 0 ] && echo 1 || echo 0)
