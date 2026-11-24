#!/usr/bin/env bash
# img-scan.sh DIR [DIR...]  - deteksi backdoor di gambar: kode di isi/EXIF, data setelah penanda akhir, tipe tak cocok
# Pakai: sudo bash img-scan.sh /var/www/html/jurnal.kampus.ac.id/public /var/www/html/jurnal.kampus.ac.id/files
set -uo pipefail
[ $# -ge 1 ] || { echo "pakai: $0 DIR..."; exit 2; }
command -v exiftool >/dev/null || { echo "apt install libimage-exiftool-perl"; exit 2; }
OUT=/root/img-scan-$(date +%F-%H%M).txt
CODE='<\?php|<script|base64_decode|gzinflate|gzuncompress|str_rot13|shell_exec|passthru|\$_(GET|POST|REQUEST|COOKIE)|<!--#exec'
n=0; bad=0
while IFS= read -r -d '' f; do
  n=$((n+1)); flag=""
  # 1. kode di mana pun di dalam file
  grep -aqE "$CODE" "$f" && flag+="[KODE-DI-ISI] "
  # 2. tipe sebenarnya vs ekstensi
  ext="${f##*.}"; ext="${ext,,}"; mt=$(file -b --mime-type "$f")
  case "$ext" in
    jpg|jpeg) [ "$mt" = image/jpeg ] || flag+="[TIPE=$mt] ";;
    png)      [ "$mt" = image/png ]  || flag+="[TIPE=$mt] ";;
    gif)      [ "$mt" = image/gif ]  || flag+="[TIPE=$mt] ";;
    webp)     [ "$mt" = image/webp ] || flag+="[TIPE=$mt] ";;
    ico)      case "$mt" in image/*) ;; *) flag+="[TIPE=$mt] ";; esac;;
  esac
  # 3. data setelah penanda akhir (PNG: IEND, JPEG: FFD9, GIF: 0x3B)
  tail_bytes=$(python3 - "$f" "$ext" <<'PY'
import sys
p,e=sys.argv[1],sys.argv[2]
d=open(p,'rb').read()
if e=='png':
    i=d.rfind(b'IEND'); print(-1 if i<0 else len(d)-(i+8))
elif e in('jpg','jpeg'):
    i=d.rfind(b'\xff\xd9'); print(-1 if i<0 else len(d)-(i+2))
elif e=='gif':
    print(len(d)-(d.rfind(b';')+1))
else: print(0)
PY
)
  case "$ext" in
    png) [ "$tail_bytes" -gt 0 ] 2>/dev/null && flag+="[SISA-SETELAH-IEND=${tail_bytes}B] "; [ "$tail_bytes" = -1 ] && flag+="[PNG-TANPA-IEND] ";;
    jpg|jpeg) [ "$tail_bytes" -gt 16 ] 2>/dev/null && flag+="[SISA-SETELAH-EOI=${tail_bytes}B] ";;
  esac
  # 4. metadata teks yang mengandung kode
  meta=$(exiftool -a -s -G1 -ee "$f" 2>/dev/null | grep -aE "$CODE" | head -2 | cut -c1-160)
  [ -n "$meta" ] && flag+="[META-BERKODE] "
  if [ -n "$flag" ]; then
    bad=$((bad+1)); { echo "$flag $f ($(stat -c '%y %U' "$f" | cut -c1-19,36-))"; [ -n "$meta" ] && echo "    $meta"; } | tee -a "$OUT"
  fi
done < <(find "$@" -type f \( -iname '*.jpg' -o -iname '*.jpeg' -o -iname '*.png' -o -iname '*.gif' -o -iname '*.webp' -o -iname '*.ico' \) -print0)
echo "Selesai: $n gambar diperiksa, $bad mencurigakan. Laporan: $OUT"
