#!/usr/bin/env bash
# penjaga.sh - SATU tombol FREEZE untuk semua tindakan otomatis (utilitas bersama).
#
# Satu berkas: /var/lib/penjaga/FREEZE (bisa diganti lewat PENJAGA_FREEZE). Bila berkas ada:
#   - M3 persistence-killer.sh --auto/--kill  : tidak bertindak
#   - M5 cf-guard.py (run --apply, block, approve): tidak mengubah Cloudflare
#   - M5 SOC-IR: tindakan T1 dan eksekusi T2 berhenti (pemindaian T0 dan peringatan tetap jalan)
# Membekukan boleh dari jauh (/freeze di Telegram, oleh approver); mencairkan HANYA dari konsol server.
#
# Pakai (root):  penjaga.sh status | freeze ALASAN | unfreeze ALASAN | siapkan
#   siapkan : buat folder /var/lib/penjaga (root:penjaga 2775) supaya pengguna guard dan guard-approve bisa membekukan
# Sebagai pustaka bash:  . penjaga.sh; penjaga_beku && echo "sedang beku"
PENJAGA_FREEZE=${PENJAGA_FREEZE:-/var/lib/penjaga/FREEZE}

penjaga_beku() { [ -e "$PENJAGA_FREEZE" ]; }

penjaga_alasan() { [ -r "$PENJAGA_FREEZE" ] && head -c 300 "$PENJAGA_FREEZE"; }

penjaga_freeze() {  # $1 alasan
  mkdir -p "$(dirname "$PENJAGA_FREEZE")" 2>/dev/null
  [ -e "$PENJAGA_FREEZE" ] || printf '%s oleh %s: %s\n' "$(date '+%F %T')" "$(id -un)" "${1:-tanpa alasan}" > "$PENJAGA_FREEZE"
}

if [ "${BASH_SOURCE[0]}" = "$0" ]; then
  set -uo pipefail
  case "${1:-status}" in
    status)
      if penjaga_beku; then echo "FREEZE AKTIF: $(penjaga_alasan)"; exit 1; else echo "FREEZE tidak aktif"; fi;;
    freeze)
      penjaga_freeze "${2:-konsol}" && echo "FREEZE aktif ($PENJAGA_FREEZE). Tindakan otomatis berhenti; pemindaian tetap jalan.";;
    unfreeze)
      [ "$(id -u)" -eq 0 ] || { echo "unfreeze hanya dari konsol sebagai root"; exit 2; }
      [ -t 0 ] || { echo "unfreeze hanya dari konsol interaktif (bukan dari script/bot)"; exit 2; }
      [ -n "${2:-}" ] || { echo "sertakan alasan: penjaga.sh unfreeze \"alasan\""; exit 2; }
      if penjaga_beku; then
        printf '%s unfreeze oleh %s: %s (sebelumnya: %s)\n' "$(date '+%F %T')" "$(id -un)" "$2" "$(penjaga_alasan | tr -d '\n')" \
          >> "$(dirname "$PENJAGA_FREEZE")/riwayat.log"
        rm -f "$PENJAGA_FREEZE"; echo "FREEZE dicabut."
      else echo "FREEZE memang tidak aktif."; fi;;
    siapkan)
      [ "$(id -u)" -eq 0 ] || { echo "perlu root"; exit 2; }
      getent group penjaga >/dev/null || groupadd --system penjaga
      for u in guard guard-approve; do id "$u" >/dev/null 2>&1 && usermod -aG penjaga "$u"; done
      d=$(dirname "$PENJAGA_FREEZE"); mkdir -p "$d"; chown root:penjaga "$d"; chmod 2775 "$d"
      echo "siap: $d (root:penjaga 2775)";;
    *) sed -n '2,14p' "$0"; exit 2;;
  esac
fi
