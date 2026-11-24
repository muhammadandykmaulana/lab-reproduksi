#!/usr/bin/env bash
# freeze.sh - satu tombol untuk MENGHENTIKAN semua tindakan otomatis (dipakai bersama oleh semua modul).
#
# Caranya cukup satu berkas: /var/lib/freeze/FREEZE (bisa diganti lewat FREEZE_FILE). Selama berkas itu ada:
#   - M3 persistence-killer.sh --auto/--kill  : tidak mematikan proses apa pun
#   - M5 cf-guard.py (run --apply, block, approve): tidak mengubah Cloudflare
#   - M5 SOC-IR: tindakan T1 dan eksekusi T2 berhenti (pemindaian dan peringatan tetap jalan)
# Menyalakan freeze boleh dari jauh (/freeze di Telegram); mematikannya HANYA dari konsol server.
#
# Pakai (root):
#   freeze.sh status          cek sedang freeze atau tidak
#   freeze.sh on  "alasan"    hentikan semua tindakan otomatis
#   freeze.sh off "alasan"    jalankan lagi (hanya dari konsol, bukan dari skrip/bot)
#   freeze.sh siapkan         buat folder /var/lib/freeze (root:freeze 2775) supaya user SOC-IR bisa menyalakan freeze
# Sebagai pustaka bash:  . freeze.sh; freeze_aktif && echo "sedang freeze"
FREEZE_FILE=${FREEZE_FILE:-/var/lib/freeze/FREEZE}

freeze_aktif() { [ -e "$FREEZE_FILE" ]; }
freeze_alasan() { [ -r "$FREEZE_FILE" ] && head -c 300 "$FREEZE_FILE"; }
freeze_nyalakan() {  # $1 alasan
  mkdir -p "$(dirname "$FREEZE_FILE")" 2>/dev/null
  [ -e "$FREEZE_FILE" ] || printf '%s oleh %s: %s\n' "$(date '+%F %T')" "$(id -un)" "${1:-tanpa alasan}" > "$FREEZE_FILE"
}
if [ "${BASH_SOURCE[0]}" = "$0" ]; then
  set -uo pipefail
  case "${1:-status}" in
    status)
      if freeze_aktif; then echo "FREEZE AKTIF: $(freeze_alasan)"; exit 1; else echo "FREEZE tidak aktif"; fi;;
    on)
      freeze_nyalakan "${2:-konsol}" && echo "FREEZE aktif ($FREEZE_FILE). Tindakan otomatis berhenti; pemeriksaan tetap jalan.";;
    off)
      [ "$(id -u)" -eq 0 ] || { echo "freeze.sh off hanya dari konsol sebagai root"; exit 2; }
      [ -t 0 ] || { echo "freeze.sh off hanya dari konsol (bukan dari skrip atau bot)"; exit 2; }
      [ -n "${2:-}" ] || { echo "sertakan alasan: freeze.sh off \"alasan\""; exit 2; }
      if freeze_aktif; then
        printf '%s off oleh %s: %s (sebelumnya: %s)\n' "$(date '+%F %T')" "$(id -un)" "$2" "$(freeze_alasan | tr -d '\n')" \
          >> "$(dirname "$FREEZE_FILE")/riwayat.log"
        rm -f "$FREEZE_FILE"; echo "FREEZE dimatikan."
      else echo "FREEZE memang tidak aktif."; fi;;
    siapkan)
      [ "$(id -u)" -eq 0 ] || { echo "perlu root"; exit 2; }
      getent group freeze >/dev/null || groupadd --system freeze
      for u in guard guard-approve; do id "$u" >/dev/null 2>&1 && usermod -aG freeze "$u"; done
      d=$(dirname "$FREEZE_FILE"); mkdir -p "$d"; chown root:freeze "$d"; chmod 2775 "$d"
      echo "siap: $d (root:freeze 2775)";;
    *) sed -n '2,15p' "$0"; exit 2;;
  esac
fi
