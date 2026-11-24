#!/usr/bin/env bash
# cek-all.sh v2 - pemeriksaan kesehatan server + RINGKASAN modul M1-M4 (HANYA MEMBACA, tidak mencetak token)
# Pakai: sudo bash cek-all.sh [-q] [-o laporan.txt] [--jalankan]
#   -q          hanya tampilkan WARN/FAIL
#   --jalankan  jalankan modul M1-M4 sekarang (mode baca saja) alih-alih membaca hasil run terakhirnya
# Lingkungan pendukung, BUKAN modul yang dievaluasi. Versi 1 memuat ulang pemeriksaan WordPress, OJS, backdoor,
# persistence, dan backup yang sudah dimiliki modul; di versi 2 semuanya dihapus dan diganti ringkasan hasil modul,
# sehingga satu temuan tidak dilaporkan dua kali. Ringkasan modul ditulis sebagai [INFO], bukan [WARN]/[FAIL],
# supaya notify-run.sh tidak mengirim ulang temuan yang sudah dikirim modulnya sendiri.
# Yang tetap diperiksa di sini (tidak dimiliki modul mana pun): izin berkas env dan token tercecer, layanan,
# versi PHP-FPM per vhost, galat fatal 24 jam, izin folder script, dan www-data di cron.deny/at.deny.
# Kode keluar 1 bila ada FAIL milik cek-all sendiri.
set -uo pipefail
[ -f /etc/web-integrity.env ] && . /etc/web-integrity.env
SCRIPTDIR="${SCRIPTDIR:-/var/opt/script}"
TOOLS="${TOOLS:-$SCRIPTDIR/tools}"
BUKTI_DIR="${BUKTI_DIR:-/var/opt/bukti}"
STATE=/var/lib/audit-run; LOGDIR=/var/log/audit-run
OUT=""; QUIET=0; JALANKAN=0
for a in "$@"; do case "$a" in -q) QUIET=1;; --jalankan) JALANKAN=1;; -o) :;; *) [ "${prev:-}" = -o ] && OUT=$a;; esac; prev=$a; done
[ -n "$OUT" ] && exec > >(tee "$OUT") 2>&1
[ "$(id -u)" -eq 0 ] || { echo "Jalankan dengan sudo."; exit 2; }

NOK=0; NWARN=0; NFAIL=0
ok()   { NOK=$((NOK+1));     [ $QUIET -eq 1 ] || echo "  [ OK ] $*"; }
warn() { NWARN=$((NWARN+1)); echo "  [WARN] $*"; }
fail() { NFAIL=$((NFAIL+1)); echo "  [FAIL] $*"; }
info() { [ $QUIET -eq 1 ] || echo "  [INFO] $*"; }
sec()  { echo; echo "== $* =="; }
echo "Audit $(hostname) - $(date '+%F %T')"

NGINX_T=$(nginx -T 2>/dev/null)
PHP_INSTALLED=$(systemctl list-unit-files 'php*-fpm.service' --no-legend 2>/dev/null | awk '{print $1}' | sed 's/\.service$//' | sort -u)
PHP_USED=$(echo "$NGINX_T" | grep -oE 'php[0-9]+\.[0-9]+-fpm\.sock' | sed 's/\.sock$//' | sort -u)

# ---------------------------------------------------------------- 1. rahasia
sec "1. Berkas rahasia dan token tercecer"
for f in /etc/web-integrity.env /etc/cek-disk.env /etc/bodyguard/*.env; do
  [ -f "$f" ] || continue
  perm=$(stat -c '%a %U' "$f")
  case "$perm" in "600 root"|"640 root") ok "$f izin $perm";; *) fail "$f izin $perm (harus 600 milik root)";; esac
done
TOKRE='[0-9]{8,10}:AA[A-Za-z0-9_-]{30,}'
left=$(grep -rlE "$TOKRE" "$SCRIPTDIR" /root /usr/local 2>/dev/null | grep -vE '\.bash_history|__pycache__' | head -20)
[ -n "$left" ] && { fail "token Telegram literal ditemukan di:"; echo "$left" | sed 's/^/         /'; } || ok "tidak ada token literal di folder script, /root, /usr/local"

# ---------------------------------------------------------------- 2. layanan
sec "2. Layanan"
for s in nginx mariadb; do systemctl is-active --quiet "$s" && ok "$s aktif" || fail "$s TIDAK aktif"; done
for s in fail2ban cek-disk lab-cek-disk telegram-bot-api; do
  systemctl list-unit-files "$s.service" --no-legend 2>/dev/null | grep -q . || continue
  systemctl is-active --quiet "$s" && ok "$s aktif" || warn "$s terpasang tetapi tidak aktif"
done
for t in web-integrity lab-web-integrity persistence-killer bodyguard-scan; do
  systemctl list-unit-files "$t.timer" --no-legend 2>/dev/null | grep -q . || continue
  systemctl is-active --quiet "$t.timer" && ok "timer $t aktif" || warn "timer $t tidak aktif"
done
for u in $PHP_USED; do
  echo "$PHP_INSTALLED" | grep -qx "$u" || { fail "nginx memakai $u tetapi paketnya tidak terpasang"; continue; }
  systemctl is-active --quiet "$u" && ok "$u aktif (dipakai nginx)" || fail "$u TIDAK aktif padahal dipakai nginx"
done
for u in $PHP_INSTALLED; do
  echo "$PHP_USED" | grep -qx "$u" && continue
  systemctl is-active --quiet "$u" && warn "$u aktif tetapi tidak dipakai nginx (systemctl disable --now $u)"
done
nginx -t >/dev/null 2>&1 && ok "nginx -t sukses" || fail "nginx -t GAGAL"

# ---------------------------------------------------------------- 3. PHP per vhost
sec "3. Versi PHP-FPM per vhost"
echo "$NGINX_T" | awk '/^[ \t]*server_name/ {gsub(/;/,""); sn=$2} /^[ \t]*fastcgi_pass/ {gsub(/;/,""); print sn, $2}' | sort -u | while read -r sn sock; do
  v=$(echo "$sock" | grep -oE 'php[0-9]+\.[0-9]+-fpm' | head -1)
  [ -n "$v" ] && [ $QUIET -eq 0 ] && printf '  [%5s] %s\n' "${v#php}" "$sn" | sed 's/-fpm//'
done
latest=$(echo "$PHP_INSTALLED" | sed 's/php//; s/-fpm//' | sort -V | tail -1)
[ -n "$latest" ] && info "versi PHP-FPM terbaru terpasang: $latest"

# ---------------------------------------------------------------- 4. galat fatal 24 jam
sec "4. Galat fatal 24 jam terakhir"
found=0; y=$(date -d '-1 day' '+%Y/%m/%d %H:%M')
for lg in /var/log/nginx/*error.log; do
  [ -s "$lg" ] || continue
  n=$(tail -n 5000 "$lg" | awk -v y="$y" '($1" "substr($2,1,5)) >= y' | grep -ciE 'PHP Fatal|Uncaught|Parse error|Primary script unknown|upstream prematurely')
  [ "$n" -gt 0 ] && { warn "$(basename "$lg"): $n baris fatal/upstream error"; found=1; }
done
[ $found -eq 0 ] && ok "tidak ada galat fatal"
for u in $PHP_USED; do
  lf="/var/log/$u.log"; [ -f "$lf" ] || continue
  mc=$(grep -c "$(date +%d-%b-%Y).*max_children" "$lf" 2>/dev/null)
  [ "${mc:-0}" -gt 0 ] && warn "$u: pm.max_children tercapai $mc kali hari ini" || ok "$u: pm.max_children tidak tercapai hari ini"
done

# ---------------------------------------------------------------- 5. izin
sec "5. Izin folder script dan larangan jadwal www-data"
for d in "$SCRIPTDIR" "$TOOLS" "$BUKTI_DIR"; do
  [ -e "$d" ] || continue
  m=$(stat -c '%a' "$d"); o=$(stat -c '%U' "$d")
  [ "${m: -1}" = "0" ] && [ "$o" = root ] && ok "$d $m $o" || warn "$d izin $m pemilik $o (other harus 0, pemilik root)"
done
find "$SCRIPTDIR" \( -user www-data -o -group www-data \) 2>/dev/null | grep -q . && fail "ada berkas di $SCRIPTDIR milik www-data" || ok "$SCRIPTDIR tidak dimiliki www-data"
for f in /etc/cron.deny /etc/at.deny; do
  grep -qx www-data "$f" 2>/dev/null && ok "www-data tercantum di $f" || warn "www-data belum tercantum di $f (persistence-killer.sh --harden)"
done
grep -hoE '/var/opt/script/[A-Za-z0-9_./-]+\.(sh|py)' /etc/cron.d/* /etc/systemd/system/*.service 2>/dev/null | sort -u | while read -r p; do
  [ -f "$p" ] || echo "  [FAIL] cron/systemd memanggil script yang TIDAK ADA: $p"
done

# ---------------------------------------------------------------- 6. ringkasan modul (tidak dihitung ulang)
sec "6. Ringkasan modul M1-M4 (rinci ada di notifikasi dan log masing-masing modul)"
ringkas() {  # $1 label, $2 nama notify-run, sisanya perintah
  local label=$1 nama=$2 log rc f w; shift 2
  if [ $JALANKAN -eq 1 ]; then
    log=$(mktemp); NOTIFY_RUN_WRAPPED=1 "$@" > "$log" 2>&1; rc=$?
  else
    log=$(ls -t "$LOGDIR/$nama"-*.log 2>/dev/null | head -1)
    [ -n "$log" ] || { echo "  [INFO] $label: belum ada hasil run (jadwal belum terpasang?)"; return; }
    rc=$(cat "$STATE/$nama.rc" 2>/dev/null || echo "?")
  fi
  f=$(grep -cE '\[FAIL\]|IOC:' "$log"); w=$(grep -c '\[WARN\]' "$log")
  echo "  [INFO] $label: FAIL=$f WARN=$w kode=$rc ($( [ $JALANKAN -eq 1 ] && echo 'dijalankan sekarang' || echo "run $(stat -c '%y' "$log" | cut -c1-16)" ))"
  [ $JALANKAN -eq 1 ] && rm -f "$log"
}
ringkas "M1 berkas"            web-integrity  "$TOOLS/web-integrity-cek.sh"
ringkas "M2 database dan akun" db-integrity   "$TOOLS/db-integrity-cek.sh"
ringkas "M3 proses"            persistence    "$TOOLS/persistence-killer.sh" --dry-run
ringkas "M4 verifikasi backup" backup-verify  "$TOOLS/backup-verify.sh"
if [ -x "$TOOLS/penjaga.sh" ]; then info "M5: $("$TOOLS/penjaga.sh" status 2>/dev/null)"; fi
use=$(df / | awk 'NR==2{gsub("%","",$5);print $5}')
[ "$use" -lt 50 ] && ok "disk root ${use}%" || warn "disk root ${use}% (batas peringatan 50%)"

echo; echo "=============================================="
echo "RINGKASAN: OK=$NOK  WARN=$NWARN  FAIL=$NFAIL"
[ $NFAIL -gt 0 ] && exit 1
exit 0
