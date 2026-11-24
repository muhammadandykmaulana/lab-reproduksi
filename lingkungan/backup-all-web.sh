#!/usr/bin/env bash
# backup-all-web.sh - backup tingkat 1: zip tiap situs di webroot + (opsional) Git per situs (tingkat 2).
# Keluaran: $BACKUP_WEB_DIR/YYYY_MM_DD-<situs>-web.zip (izin 600). Dijalankan cron harian 00:10.
# Konfigurasi di /etc/web-integrity.env (semua opsional):
#   WEBROOT=/var/www/html  BACKUP_WEB_DIR=/var/opt/BACKUP/web
#   SKIP_SITES="html default"          folder yang tidak dibackup (pisah spasi)
#   GIT_BACKUP=0|1                     1 = commit + push tiap situs yang sudah menjadi repo git
#   GIT_REMOTE_BASE=git@gitlab.com:grup  dipakai bila situs belum punya remote (repo dibuat PRIVATE di GitLab)
# Perbaikan dari versi lapangan: situs yang foldernya tidak ada dilewati (reverse proxy), ".git" berupa berkas
# penunjuk (gitdir) dikenali, "tidak ada perubahan" tidak dilaporkan sebagai gagal, push diberi batas waktu.
set -uo pipefail
[ -f /etc/web-integrity.env ] && . /etc/web-integrity.env
WEBROOT=${WEBROOT:-/var/www/html}
OUT=${BACKUP_WEB_DIR:-/var/opt/BACKUP/web}
SKIP=" ${SKIP_SITES:-html default} "
TGL=$(date +%Y_%m_%d)
NOTIFY_RUN=${NOTIFY_RUN:-$(dirname "$(readlink -f "$0")")/notify-run.sh}
kirim() { [ -x "$NOTIFY_RUN" ] && printf '%s' "$1" | "$NOTIFY_RUN" --pesan > /dev/null 2>&1; return 0; }   # satu pengirim Telegram
command -v zip >/dev/null || { echo "[FAIL] perintah zip tidak ada (apt install zip)"; exit 2; }
mkdir -p "$OUT"; chmod 700 "$OUT"
gagal=()
for d in "$WEBROOT"/*/; do
  site=$(basename "$d")
  case "$SKIP" in *" $site "*) continue;; esac
  [ -d "$d" ] || continue
  z="$OUT/${TGL}-${site}-web.zip"
  ( cd "$WEBROOT" && nice -n 10 zip -qr -y "$z.partial" "$site" -x "$site/.git/*" "$site/wp-content/cache/*" "$site/cache/t_compile/*" "$site/node_modules/*" )
  rc=$?
  if [ $rc -le 1 ] && unzip -tq "$z.partial" >/dev/null 2>&1; then   # rc 1 zip = peringatan (berkas berubah saat dibaca)
    mv "$z.partial" "$z"; chmod 600 "$z"; echo "[ OK ] $site -> $(basename "$z") ($(du -h "$z" | cut -f1))"
  else
    rm -f "$z.partial"; echo "[FAIL] $site: zip gagal (kode $rc)"; gagal+=("$site")
  fi
  # ---- tingkat 2: Git per situs (opsional)
  [ "${GIT_BACKUP:-0}" = 1 ] || continue
  if [ ! -e "$d/.git" ]; then
    [ -n "${GIT_REMOTE_BASE:-}" ] || { echo "[INFO] $site bukan repo git dan GIT_REMOTE_BASE kosong: Git dilewati"; continue; }
    git -C "$d" init -q -b main && git -C "$d" remote add origin "${GIT_REMOTE_BASE%/}/${site}.git"
  fi
  git -C "$d" add -A
  if git -C "$d" diff --cached --quiet; then echo "[ OK ] Git $site: tidak ada perubahan"; continue; fi
  git -C "$d" commit -q -m "Backup on $TGL"
  if timeout 1800 git -C "$d" push -q -u origin HEAD 2>"/run/gitpush.$$"; then
    echo "[ OK ] Git $site: push berhasil"
  else
    err=$(tail -3 "/run/gitpush.$$" | tr '\n' ' ' | sed -E 's#://[^@ ]+@#://***@#g' | cut -c1-300)
    echo "[FAIL] Git $site: push gagal: $err"; kirim "❌ Git backup gagal: $site - $err"
  fi
  rm -f "/run/gitpush.$$"
done
[ ${#gagal[@]} -gt 0 ] && kirim "❌ backup-all-web: zip gagal untuk ${gagal[*]}"
exit $([ ${#gagal[@]} -gt 0 ] && echo 1 || echo 0)
