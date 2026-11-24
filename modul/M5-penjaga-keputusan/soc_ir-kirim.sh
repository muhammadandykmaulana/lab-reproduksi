#!/usr/bin/env bash
# soc_ir-kirim.sh v4 - kirim laporan soc_ir terbaru ke chat SOC (maks 3300 byte). Dipanggil systemd sebagai root.
# Perbaikan v3:
#  - baris perapian tidak lagi memakai escape salah (\&\&) yang membuat awk error dan pesan terkirim KOSONG
#  - bila perapian gagal atau hasilnya kosong, yang dikirim tetap teks asli laporan (pesan tidak pernah kosong)
#  - potongan byte UTF-8 di ujung (akibat head -c) dibuang supaya Telegram tidak menolak teksnya
# v5: juga mengenali judul format laporan baru (bahasa sehari-hari); baris kosong ganda dirapatkan (cat -s)
# v4: pengiriman lewat notify-run.sh --pesan (satu pengirim Telegram untuk semua modul; token tidak pernah dicetak)
set -uo pipefail
ENVF=${SOC_ENVF:-/etc/web-integrity.env}
LAPDIR=${SOC_LAPDIR:-/var/log/soc_ir}
NOTIFY_RUN=${NOTIFY_RUN:-$(dirname "$(readlink -f "$0")")/notify-run.sh}
F=$(ls -t "$LAPDIR"/laporan-*.txt 2>/dev/null | head -1)
[ -n "$F" ] && [ -s "$F" ] || exit 0

# 1) ambil 3300 byte pertama, buang byte UTF-8 yang terpotong di ujung
ASLI=$(head -c 3300 "$F" | iconv -c -f UTF-8 -t UTF-8 2>/dev/null)
[ -n "$ASLI" ] || ASLI=$(head -c 3300 "$F")

# 2) rapikan: baris kosong sebelum tiap judul bagian, dan "- -" menjadi "- (tidak ada)"
RAPI=$(printf '%s\n' "$ASLI" \
  | awk 'NR>1 && /^(STATUS|TOP IP|SUKSES\/KRITIS BARU|TREN|CEK-ALL BARU|INJEKSI|SARAN|Ringkasan|Perlu tindakan|IP paling|Dibanding|Kesehatan server)/ {print ""} {print}' 2>/dev/null \
  | sed -E 's/^- -$/- (tidak ada)/' 2>/dev/null | cat -s)
[ -n "$RAPI" ] || RAPI=$ASLI        # cadangan: perapian gagal -> kirim teks asli apa adanya

TXT=$(printf 'soc_ir %s\n\n%s' "$(hostname)" "$RAPI")

# 3) kirim lewat satu pengirim bersama
if printf '%s' "$TXT" | "$NOTIFY_RUN" --pesan --env "$ENVF"; then echo "terkirim"
else echo "Telegram tidak menerima pesan (lihat galat notify-run di atas)" >&2; fi
exit 0
