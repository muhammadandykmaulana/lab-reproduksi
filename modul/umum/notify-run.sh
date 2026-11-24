#!/usr/bin/env bash
# notify-run.sh - SATU-SATUNYA pengirim pesan Telegram untuk semua modul (utilitas bersama).
#
# Mode 1, pembungkus audit: jalankan script, simpan log, kirim HANYA temuan BARU (dipakai cron/timer)
#   notify-run.sh NAMA perintah [argumen...]
#   contoh: notify-run.sh db-integrity /var/opt/script/tools/db-integrity-cek.sh
#   - log lengkap: /var/log/audit-run/NAMA-YYYY-MM-DD.log (disimpan 120 hari)
#   - temuan = baris [WARN]/[FAIL]/SUSPECT/IOC:/dst., dibandingkan dengan run sebelumnya; yang sama tidak dikirim ulang
#   - kode keluar script disimpan di /var/lib/audit-run/NAMA.rc; notify-run sendiri keluar dengan kode yang sama
#   - setiap Senin dikirim heartbeat supaya script yang berhenti berjalan ketahuan
#
# Mode 2, kirim satu pesan (dipakai modul lain, termasuk script Python dan SOC-IR):
#   printf '%s' "teks" | notify-run.sh --pesan [--chat ID] [--env BERKAS] [--token-var NAMA] [--chat-var NAMA]
#   - teks dibaca dari STDIN (tidak pernah dari argumen, supaya tidak ditafsirkan shell), dipotong 3.800 karakter
#   - token dan chat dibaca dari BERKAS env (bawaan /etc/web-integrity.env); --env - = pakai variabel lingkungan saja
#   - token tidak muncul di daftar proses: URL dikirim ke curl lewat berkas konfigurasi sementara (-K)
#   - TELEGRAM_API_BASE (opsional) untuk Bot API lokal; bawaan https://api.telegram.org
#
# Pengecualian yang disengaja: tombol persetujuan T2 (SOC-IR) dan unggah berkas backup tingkat 2
# tidak lewat script ini, karena keduanya bukan notifikasi teks.
set -uo pipefail
umask 077

kirim() {  # $1 teks, $2 chat (opsional). Butuh TOKEN dan CHAT terisi.
  local teks=$1 chat=${2:-$CHAT} base=${TELEGRAM_API_BASE:-https://api.telegram.org} r
  [ -n "$TOKEN" ] && [ -n "$chat" ] || { echo "notify-run: token/chat Telegram kosong, pesan tidak dikirim" >&2; return 1; }
  r=$(curl -s -m 20 -K <(printf 'url = "%s/bot%s/sendMessage"\n' "${base%/}" "$TOKEN") \
        -d chat_id="$chat" -d disable_web_page_preview=true \
        --data-urlencode "text=$(printf '%s' "$teks" | head -c 3800)")
  case "$r" in *'"ok":true'*) return 0;; esac
  echo "notify-run: KIRIM TELEGRAM GAGAL: $(printf '%s' "$r" | grep -oE '"description":"[^"]+"' | head -1)" >&2
  return 1
}

baca_env() {  # $1 berkas; hanya baris KUNCI=nilai, tidak dieksekusi sebagai script
  local f=$1 k v
  [ "$f" = "-" ] && return 0
  [ -r "$f" ] || return 0
  while IFS='=' read -r k v; do
    [[ $k =~ ^[A-Z_][A-Z0-9_]*$ ]] || continue
    v=${v%\"}; v=${v#\"}; v=${v%\'}; v=${v#\'}
    printf -v "ENV_$k" '%s' "$v"
  done < <(grep -E '^[[:space:]]*[A-Z_][A-Z0-9_]*=' "$f" | sed -E 's/^[[:space:]]+//; s/[[:space:]]+#.*$//')
}

# ------------------------------------------------------------------ mode 2: --pesan
if [ "${1:-}" = "--pesan" ]; then
  shift; ENVF=/etc/web-integrity.env; TVAR=TELEGRAM_BOT_TOKEN; CVAR=TELEGRAM_CHAT_ID; KE=""
  while [ $# -gt 0 ]; do case "$1" in
    --chat) KE=${2:-}; shift 2;; --env) ENVF=${2:-}; shift 2;;
    --token-var) TVAR=${2:-}; shift 2;; --chat-var) CVAR=${2:-}; shift 2;;
    *) echo "opsi tidak dikenal: $1" >&2; exit 2;; esac; done
  [[ $TVAR =~ ^[A-Z_][A-Z0-9_]*$ && $CVAR =~ ^[A-Z_][A-Z0-9_]*$ ]] || { echo "nama variabel tidak valid" >&2; exit 2; }
  baca_env "$ENVF"
  t="ENV_$TVAR"; c="ENV_$CVAR"
  TOKEN=${!TVAR:-${!t:-}}; CHAT=${!CVAR:-${!c:-}}
  [ -z "${TELEGRAM_API_BASE:-}" ] && [ -n "${ENV_TELEGRAM_API_BASE:-}" ] && TELEGRAM_API_BASE=$ENV_TELEGRAM_API_BASE
  teks=$(cat); [ -n "$teks" ] || exit 0
  kirim "$teks" "${KE:-$CHAT}"; exit $?
fi

# ------------------------------------------------------------------ mode 1: pembungkus audit
NAME=${1:?nama}; shift
[[ $NAME =~ ^[A-Za-z0-9._-]{1,60}$ ]] || { echo "nama tidak valid"; exit 2; }
[ $# -ge 1 ] || { echo "perintah kosong"; exit 2; }
LOGDIR=/var/log/audit-run; STATE=/var/lib/audit-run
mkdir -p "$LOGDIR" "$STATE"; chmod 700 "$LOGDIR" "$STATE"
LOG="$LOGDIR/$NAME-$(date +%F).log"
baca_env /etc/web-integrity.env
TOKEN=${TELEGRAM_BOT_TOKEN:-${ENV_TELEGRAM_BOT_TOKEN:-}}; CHAT=${TELEGRAM_CHAT_ID:-${ENV_TELEGRAM_CHAT_ID:-}}
[ -z "${TELEGRAM_API_BASE:-}" ] && [ -n "${ENV_TELEGRAM_API_BASE:-}" ] && TELEGRAM_API_BASE=$ENV_TELEGRAM_API_BASE

NOTIFY_RUN_WRAPPED=1 "$@" > "$LOG" 2>&1; RC=$?
chmod 600 "$LOG"; echo "$RC" > "$STATE/$NAME.rc"

FIND_RE='\[(WARN|FAIL)\]|SUSPECT|IOC:|NAMA-ACAK-HEX|AUTHOR-PALSU|PHP-DI-FOLDER-DATA|MU-PLUGIN:|PREPEND-HANDLER|WORLD-WRITABLE|\[LONGGAR\]|^  ADMIN '
# normalisasi: buang angka yang berubah-ubah (jumlah request, persen disk, waktu) agar tidak dianggap temuan baru
grep -E "$FIND_RE" "$LOG" | sed -E 's/[0-9]{4}-[0-9]{2}-[0-9]{2}[ T][0-9:]+//g; s/[0-9]+%/N%/g; s/ pid=[0-9]+//g' | sort -u > "$STATE/$NAME.now"
touch "$STATE/$NAME.last"
NEW=$(comm -13 "$STATE/$NAME.last" "$STATE/$NAME.now")
HAS_FAIL=$(grep -c '\[FAIL\]' "$STATE/$NAME.now" || true)
# rapikan: temuan dikelompokkan (GAGAL/PERINGATAN/lain), satu poin per baris, maks 12 per kelompok
rapikan() { awk 'function tulis(j,a,n,  i){ if(!n) return; printf "\n%s (%d)\n", j, n; for(i=1;i<=n&&i<=12;i++) printf "• %s\n", a[i]; if(n>12) printf "• ... dan %d lainnya, lihat log\n", n-12 }
  /\[FAIL\]/ { sub(/^ *\[FAIL\] */,""); f[++nf]=$0; next }
  /\[WARN\]/ { sub(/^ *\[WARN\] */,""); w[++nw]=$0; next }
  NF { sub(/^ +/,""); l[++nl]=$0 }
  END { tulis("❌ GAGAL", f, nf); tulis("⚠️ PERINGATAN", w, nw); tulis("ℹ️ TEMUAN LAIN", l, nl) }'; }

if [ -n "$NEW" ]; then
  kirim "⚠️ [$NAME] $(hostname)
$(echo "$NEW" | grep -c .) temuan baru · FAIL total: $HAS_FAIL
$(printf '%s\n' "$NEW" | rapikan)

Log: $LOG" 2>> "$LOG"
elif [ "$(date +%u)" = "1" ] && [ ! -e "$STATE/$NAME.hb-$(date +%F)" ]; then
  kirim "✅ [$NAME] $(hostname) berjalan. $(grep -E '^RINGKASAN|^Ringkasan' "$LOG" | head -1) Temuan terbuka: $(grep -c . "$STATE/$NAME.now")" 2>> "$LOG" \
    && touch "$STATE/$NAME.hb-$(date +%F)"
fi
cp "$STATE/$NAME.now" "$STATE/$NAME.last"
find "$LOGDIR" -name "$NAME-*.log" -mtime +120 -delete 2>/dev/null
find "$STATE" -name "$NAME.hb-*" -mtime +30 -delete 2>/dev/null
exit "$RC"
