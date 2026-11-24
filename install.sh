#!/usr/bin/env bash
# install.sh - pemasang lab reproduksi skripsi "Mengamankan Website Kampus dengan Sumber Daya Terbatas"
#
#   sudo bash install.sh              semi-otomatis: paket dipasang otomatis, pertanyaan (token, IP kantor) interaktif;
#                                     tiap pertanyaan ditunggu 60 detik, lewat = dilewati dan bisa diisi nanti
#   sudo bash install.sh --otomatis   tanpa pertanyaan sama sekali (token dan jadwal diisi nanti lewat lab.sh)
#   sudo bash install.sh --tanpa-paket   lewati apt (bila paket sudah terpasang atau server tanpa internet)
#
# Lingkungan yang didukung: Ubuntu Server 22.04 LTS / 24.04 LTS, akses root. Distro lain ditolak.
# Aman dijalankan berulang (idempoten). Tidak ada rahasia yang disimpan di folder lab; semua rahasia di /etc/*.env (600).
set -uo pipefail
SUMBER="$(cd "$(dirname "$0")" && pwd)"
TANPA_PAKET=0
for a in "$@"; do case "$a" in
  --otomatis) export OTOMATIS=1;; --tanpa-paket) TANPA_PAKET=1;;
  -h|--help) sed -n '2,12p' "$0"; exit 0;; *) echo "opsi tidak dikenal: $a"; exit 2;; esac; done
. "$SUMBER/lib/umum.sh"

echo "${B}Lab Reproduksi - Pertahanan Berlapis dan Backup untuk Website Kampus${N}"
echo "Sumber: $SUMBER  ->  dipasang ke: $LAB_TUJUAN"
perlu_root
cek_os

# ------------------------------------------------------------------ 1. paket
judul "1. Paket sistem"
PAKET=(curl ca-certificates jq zip unzip git gzip tar python3 python3-requests mariadb-client openssl acl util-linux coreutils)
PAKET_OPSIONAL=(rclone fail2ban)
kurang=(); for p in "${PAKET[@]}"; do dpkg -s "$p" >/dev/null 2>&1 || kurang+=("$p"); done
if [ ${#kurang[@]} -eq 0 ]; then sukses "semua paket wajib sudah terpasang"
elif [ "$TANPA_PAKET" = 1 ]; then peringatan "paket belum ada (dilewati karena --tanpa-paket): ${kurang[*]}"
else
  info "memasang: ${kurang[*]}"
  if DEBIAN_FRONTEND=noninteractive apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq "${kurang[@]}" >/dev/null; then
    sukses "paket wajib terpasang"
  else
    peringatan "apt gagal (internet/repo?). Pasang manual: apt-get install ${kurang[*]}"
  fi
fi
for p in "${PAKET_OPSIONAL[@]}"; do dpkg -s "$p" >/dev/null 2>&1 && sukses "opsional $p terpasang" || info "opsional $p belum ada (perlu untuk: $(case $p in rclone) echo 'backup tingkat 3 Google Drive';; fail2ban) echo 'fw.sh, hanya untuk SSH';; esac)). Pasang: apt-get install $p"; done
if ! command -v wp >/dev/null; then
  if ya_tidak "Pasang wp-cli (pemeriksaan checksum WordPress pada webscan-wp.sh)?" n; then
    curl -fsSL -o /usr/local/bin/wp https://raw.githubusercontent.com/wp-cli/builds/gh-pages/phar/wp-cli.phar && chmod 755 /usr/local/bin/wp \
      && sukses "wp-cli terpasang" || peringatan "wp-cli gagal diunduh (opsional)"
  else info "wp-cli dilewati (opsional)"; fi
fi

# ------------------------------------------------------------------ 2. salin lab dan skrip
judul "2. Folder proyek"
mkdir -p "$TOOLS"; chmod 750 "$TOOLS"
if [ "$SUMBER" != "$LAB_TUJUAN" ]; then
  mkdir -p "$LAB_TUJUAN"; cp -a "$SUMBER"/. "$LAB_TUJUAN"/; sukses "lab disalin ke $LAB_TUJUAN"
fi
chown -R root:root "$LAB_TUJUAN"; chmod -R go-w "$LAB_TUJUAN"; chmod 750 "$LAB_TUJUAN"
TS=$(date +%Y%m%d-%H%M%S); dilewati=()
# skrip dari folder modul (M1-M5 dan utilitas bersama), pencegahan, pendukung, dan alat uji dipasang ke $TOOLS,
# karena cron, timer, dan root.conf SOC-IR memanggilnya dengan jalur tetap /var/opt/script/tools/<nama>.
for f in "$LAB_TUJUAN"/modul/*/*.sh "$LAB_TUJUAN"/modul/*/*.py "$LAB_TUJUAN"/pencegahan/*.sh "$LAB_TUJUAN"/pendukung/*.sh "$LAB_TUJUAN"/pendukung/*.py "$LAB_TUJUAN"/uji/*.py; do
  n=$(basename "$f"); t="$TOOLS/$n"
  if [ -f "$t" ] && ! cmp -s "$f" "$t"; then
    if ya_tidak "  $n sudah ada di $TOOLS dan berbeda. Timpa dengan versi lab (cadangan dibuat)?" n; then
      cp -a "$t" "$t.bak-lab-$TS"; install -m 750 -o root -g root "$f" "$t"; info "  $n ditimpa (cadangan $n.bak-lab-$TS)"
    else dilewati+=("$n"); fi
  else install -m 750 -o root -g root "$f" "$t"; fi
done
sukses "skrip dipasang di $TOOLS"
singkirkan_nama_lama "$TOOLS/.sebelum-sinkron/install-$TS"
[ ${#dilewati[@]} -gt 0 ] && info "versi server dipertahankan untuk: ${dilewati[*]}"
for d in /var/opt/filehash-web-all /var/opt/db-integrity /var/opt/bukti /var/opt/BACKUP/web /var/opt/BACKUP/DB /var/opt/BACKUP/vps \
         /var/log/audit-run /var/lib/audit-run /var/lib/backup-verify /var/log/backup_vps "$ETC_LAB"; do mkdir -p "$d"; chmod 700 "$d"; done
sukses "folder data, bukti (satu folder untuk semua modul), backup, dan log disiapkan (izin 700)"
bash "$TOOLS/freeze.sh" siapkan >/dev/null && sukses "freeze disiapkan: /var/lib/freeze (freeze.sh status | on \"alasan\" | off \"alasan\")"

# ------------------------------------------------------------------ 2b. www-data dilarang memakai cron dan at
judul "2b. Larang pengguna web (www-data) memasang jadwal cron/at"
for f in /etc/cron.deny /etc/at.deny; do touch "$f"; chmod 640 "$f"; grep -qx www-data "$f" || echo www-data >> "$f"; done
[ -f /etc/cron.allow ] && ! grep -qx www-data /etc/cron.allow && info "/etc/cron.allow ada: www-data otomatis tidak diizinkan"
if crontab -u www-data -l >/dev/null 2>&1; then
  crontab -u www-data -l > "/var/opt/bukti/crontab-www-data-$TS.txt" 2>/dev/null; crontab -u www-data -r
  peringatan "crontab www-data DITEMUKAN dan dihapus (salinan: /var/opt/bukti/crontab-www-data-$TS.txt). Periksa isinya: tanda penyusupan."
fi
sukses "www-data tercatat di /etc/cron.deny dan /etc/at.deny"

# ------------------------------------------------------------------ 3. konfigurasi dasar (tanpa rahasia)
judul "3. Konfigurasi dasar"
[ -f "$ENV_WI" ] || { install -m 600 -o root -g root "$LAB_TUJUAN/config/web-integrity.env.example" "$ENV_WI"; sukses "dibuat $ENV_WI dari contoh"; }
[ -f "$ENV_CD" ] || { install -m 600 -o root -g root "$LAB_TUJUAN/config/cek-disk.env.example" "$ENV_CD"; sukses "dibuat $ENV_CD dari contoh"; }
chmod 600 "$ENV_WI" "$ENV_CD"
ipk=$(get_kv "$ENV_WI" IP_KANTOR)
tanya ipk "IP publik kantor yang sah (pisahkan spasi; dikecualikan dari blokir)" "$ipk"; set_kv "$ENV_WI" IP_KANTOR "$ipk"
ojs=$(get_kv "$ENV_WI" OJS_DB)
tanya ojs "Nama database OJS (kosongkan bila tidak memakai OJS)" "$ojs"; set_kv "$ENV_WI" OJS_DB "$ojs"
ojss=$(get_kv "$ENV_WI" OJS_SITE)
tanya ojss "Nama folder/vhost OJS di webroot, mis. jurnal.kampus.ac.id" "$ojss"; set_kv "$ENV_WI" OJS_SITE "$ojss"
for f in known_admins.txt; do [ -f "/var/opt/script/$f" ] || install -m 600 "$LAB_TUJUAN/config/$f.example" "/var/opt/script/$f"; done
[ -f /var/opt/db-integrity/trusted_ips.txt ] || install -m 600 "$LAB_TUJUAN/config/trusted_ips.txt.example" /var/opt/db-integrity/trusted_ips.txt
sukses "konfigurasi dasar tersimpan (tanpa rahasia)"

# ------------------------------------------------------------------ 4. token (interaktif, boleh dilewati)
judul "4. Token Telegram dan Cloudflare"
if [ "$OTOMATIS" = 1 ]; then info "mode --otomatis: token dilewati. Isi nanti: sudo bash $LAB_TUJUAN/atur-token.sh"
else bash "$LAB_TUJUAN/atur-token.sh" semua; fi

# ------------------------------------------------------------------ 5. jadwal
judul "5. Jadwal otomatis"
if ya_tidak "Pasang jadwal otomatis sekarang (cron + timer)? Disarankan SETELAH baseline dibuat (lab.sh menu 3)" n; then
  bash "$LAB_TUJUAN/lab.sh" pasang-cron
else info "jadwal belum dipasang. Pasang nanti: sudo bash $LAB_TUJUAN/lab.sh pasang-cron"; status_set JADWAL belum; fi

status_set TERPASANG "$(date '+%F %T')"
judul "Selesai"
bash "$LAB_TUJUAN/lab.sh" status
cat <<EOF

Langkah berikutnya:
  1) Coba demo aman (tidak menyentuh situs):   sudo bash $LAB_TUJUAN/lab.sh demo
  2) Buat baseline saat situs bersih:          sudo bash $LAB_TUJUAN/lab.sh baseline
  3) Jalankan pemeriksaan:                     sudo bash $LAB_TUJUAN/lab.sh cek
  4) Menu lengkap:                             sudo bash $LAB_TUJUAN/lab.sh
EOF
