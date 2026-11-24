#!/usr/bin/env bash
# ip-kantor-sync.sh - IP admin yang sah = IP kantor TETAP + IP rumah DINAMIS (dibaca dari nama DDNS).
# Hasil gabungan ditulis ke IP_KANTOR (/etc/web-integrity.env; dipakai M1 dan ip-report) dan
# CG_OFFICE_IPS (/etc/bodyguard/cloudflare.env; dipakai cf-guard). Hanya menulis bila berubah.
# Isi sekali di /etc/web-integrity.env:
#   IP_KANTOR_TETAP="203.0.113.10"              (boleh lebih dari satu, pisahkan spasi)
#   IP_KANTOR_DDNS="admin-rumah.duckdns.org"    (boleh lebih dari satu, pisahkan spasi)
# Jadwal: */10 * * * * root /var/opt/script/tools/ip-kantor-sync.sh
# Bila DDNS gagal di-resolve, IP lama dipertahankan (admin tidak tiba-tiba ikut terblokir).
set -uo pipefail
LIB=${LIB:-/var/opt/script/tools/skripsi-lab/lib/umum.sh}
[ -f "$LIB" ] || LIB=/var/opt/script/tools/lab-reproduksi/lib/umum.sh
# shellcheck source=/dev/null
. "$LIB"
WI=/etc/web-integrity.env; CF=/etc/bodyguard/cloudflare.env
tetap=$(get_kv "$WI" IP_KANTOR_TETAP); ddns=$(get_kv "$WI" IP_KANTOR_DDNS); lama=$(get_kv "$WI" IP_KANTOR)
[ -n "$tetap$ddns" ] || { echo "IP_KANTOR_TETAP dan IP_KANTOR_DDNS belum diisi di $WI"; exit 1; }
dinamis=""
for h in $ddns; do
  ip=$(getent ahostsv4 "$h" | awk '{print $1; exit}')
  if [ -z "$ip" ]; then
    # gagal resolve: pertahankan IP lama yang bukan IP tetap
    ip=$(for x in $lama; do [[ " $tetap " == *" $x "* ]] || echo "$x"; done | paste -sd' ' -)
    echo "[WARN] $h tidak bisa di-resolve; memakai IP lama: ${ip:--}"
  fi
  dinamis="$dinamis $ip"
done
baru=$(printf '%s\n' $tetap $dinamis | grep -E '^[0-9a-fA-F:.]+(/[0-9]+)?$' | sort -u | paste -sd' ' -)
[ "$baru" = "$(printf '%s\n' $lama | sort -u | paste -sd' ' -)" ] && exit 0
set_kv "$WI" IP_KANTOR "$baru"
[ -f "$CF" ] && set_kv "$CF" CG_OFFICE_IPS "$baru"
# situs salinan uji (salin-uji.py): daftar IP yang boleh membuka ikut diperbarui
IZ=/etc/nginx/conf.d/uji-izin.conf
if [ -f "$IZ" ]; then
  cp -p "$IZ" "$IZ.lama"
  { echo "# dibuat oleh salin-uji.py / ip-kantor-sync.sh: IP yang boleh membuka situs salinan uji-*."
    echo 'map $http_cf_connecting_ip $uji_boleh {'; echo '    default 0;'
    for x in $baru; do echo "    $x 1;"; done; echo '}'; } > "$IZ"
  if nginx -t >/dev/null 2>&1; then systemctl reload nginx; rm -f "$IZ.lama"; else mv "$IZ.lama" "$IZ"; echo "[WARN] nginx -t gagal, uji-izin.conf dikembalikan"; fi
fi
echo "IP admin berubah: ${lama:--} -> $baru"
N=/var/opt/script/tools/notify-run.sh
[ -x "$N" ] && printf 'ℹ️ IP admin yang dikecualikan berubah\nlama: %s\nbaru: %s' "${lama:--}" "$baru" | "$N" --pesan >/dev/null 2>&1
exit 0
