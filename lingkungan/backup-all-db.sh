#!/usr/bin/env bash
# backup-all-db.sh - backup tingkat 1: dump tiap database ke $BACKUP_DB_DIR/YYYY_MM_DD-<db>.sql.gz (izin 600).
# Dijalankan cron harian 00:10. Kegagalan mysqldump TIDAK lagi menghasilkan berkas gzip kosong (20 byte):
# dump ditulis ke .partial, kode keluar dicek lewat pipefail, lalu penutup "Dump completed" diperiksa sebelum diganti nama.
# Konfigurasi (opsional) di /etc/web-integrity.env: BACKUP_DB_DIR, SKIP_DBS="test", DB_DEFAULTS=/root/.my.cnf
set -uo pipefail
[ -f /etc/web-integrity.env ] && . /etc/web-integrity.env
OUT=${BACKUP_DB_DIR:-/var/opt/BACKUP/DB}
SKIP=" ${SKIP_DBS:-} information_schema performance_schema mysql sys "
TGL=$(date +%Y_%m_%d)
NOTIFY_RUN=${NOTIFY_RUN:-$(dirname "$(readlink -f "$0")")/notify-run.sh}
kirim() { [ -x "$NOTIFY_RUN" ] && printf '%s' "$1" | "$NOTIFY_RUN" --pesan > /dev/null 2>&1; return 0; }   # satu pengirim Telegram
MYSQL=$(command -v mariadb || command -v mysql) || { echo "[FAIL] klien mariadb/mysql tidak ada"; exit 2; }
DUMP=$(command -v mariadb-dump || command -v mysqldump) || { echo "[FAIL] mariadb-dump/mysqldump tidak ada"; exit 2; }
OPT=(); [ -n "${DB_DEFAULTS:-}" ] && OPT=(--defaults-extra-file="$DB_DEFAULTS")
mkdir -p "$OUT"; chmod 700 "$OUT"
gagal=()
for db in $("$MYSQL" "${OPT[@]}" -N -B -e "SHOW DATABASES"); do
  case "$SKIP" in *" $db "*) continue;; esac
  f="$OUT/${TGL}-${db}.sql.gz"
  if "$DUMP" "${OPT[@]}" --single-transaction --quick --routines --triggers --events "$db" 2>"/run/dump.$$" | gzip -c > "$f.partial" \
     && zcat "$f.partial" | tail -c 400 | grep -q 'Dump completed'; then
    mv "$f.partial" "$f"; chmod 600 "$f"; echo "[ OK ] $db -> $(basename "$f") ($(du -h "$f" | cut -f1))"
  else
    echo "[FAIL] $db: dump gagal: $(head -c 300 "/run/dump.$$" | tr '\n' ' ')"; rm -f "$f.partial"; gagal+=("$db")
  fi
  rm -f "/run/dump.$$"
done
[ ${#gagal[@]} -gt 0 ] && kirim "❌ backup-all-db: dump gagal untuk ${gagal[*]} (lihat /var/log/backup_db.log)"
exit $([ ${#gagal[@]} -gt 0 ] && echo 1 || echo 0)
