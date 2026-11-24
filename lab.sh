#!/usr/bin/env bash
# lab.sh - menu lab reproduksi. Tanpa argumen = menu interaktif; atau langsung: lab.sh <perintah>
#   status | sinkron [--pasang] [--hanya a,b] | ip-admin | ojs-db | demo | demo-bersihkan | baseline | cek | token | pasang-cron | lepas-cron | soc-ir | uji | uninstall
set -uo pipefail
DIR="$(cd "$(dirname "$0")" && pwd)"
. "$DIR/lib/umum.sh"
perlu_root

daftar_skrip() { ls "$DIR"/modul/*/*.sh "$DIR"/modul/*/*.py "$DIR"/pencegahan/*.sh "$DIR"/pendukung/*.sh "$DIR"/pendukung/*.py "$DIR"/uji/*.py 2>/dev/null; }

status() {
  judul "Status lab ($(hostname))"
  printf '  %-28s %s\n' "Sistem" "$(. /etc/os-release; echo "$PRETTY_NAME")"
  printf '  %-28s %s\n' "Folder lab" "$LAB_TUJUAN"
  printf '  %-28s %s\n' "Skrip terpasang di $TOOLS" "$(daftar_skrip | while read -r f; do [ -f "$TOOLS/$(basename "$f")" ] && echo x; done | wc -l) dari $(daftar_skrip | wc -l)"
  printf '  %-28s %s\n' "FREEZE (semua modul)" "$(bash "$TOOLS/freeze.sh" status 2>/dev/null || true)"
  for k in TELEGRAM CLOUDFLARE PERSETUJUAN JADWAL; do printf '  %-28s %s\n' "$k" "$(status_get $k | grep . || echo belum)"; done
  printf '  %-28s %s\n' "Baseline berkas" "$([ -s /var/opt/filehash-web-all/baseline.sha256 ] && echo "ada ($(wc -l < /var/opt/filehash-web-all/baseline.sha256) berkas)" || echo belum)"
  printf '  %-28s %s\n' "Baseline database" "$(ls /var/opt/db-integrity/*.admins >/dev/null 2>&1 && echo ada || echo belum)"
  printf '  %-28s %s\n' "IP admin (IP_KANTOR)" "$(get_kv "$ENV_WI" IP_KANTOR | grep . || echo 'belum diisi -> lab.sh ip-admin')"
  printf '  %-28s %s\n' "  IP tetap / DDNS" "$(get_kv "$ENV_WI" IP_KANTOR_TETAP | grep . || echo -) / $(get_kv "$ENV_WI" IP_KANTOR_DDNS | grep . || echo -)"
  printf '  %-28s %s\n' "Database OJS (OJS_DB)" "$(get_kv "$ENV_WI" OJS_DB | grep . || echo 'belum diisi -> lab.sh ojs-db (skrip memakai nama ojs)')"
  [ "$(status_get TELEGRAM)" = ok ] || echo "  -> isi token Telegram: sudo bash $DIR/atur-token.sh telegram"
}

baseline() {
  judul "Baseline (jalankan HANYA saat situs dipastikan bersih)"
  ya_tidak "Situs sudah diperiksa dan bersih?" n || { info "dibatalkan"; return 0; }
  bash "$TOOLS/web-integrity-cek.sh" --rebuild
  if command -v mariadb >/dev/null || command -v mysql >/dev/null; then bash "$TOOLS/db-integrity-cek.sh" --rebuild
  else peringatan "klien MariaDB tidak ada: baseline database dilewati"; fi
}

cek() {
  judul "Pemeriksaan sekarang (hanya membaca)"
  for c in "web-integrity-cek.sh" "db-integrity-cek.sh" "persistence-killer.sh --dry-run" "backup-verify.sh" "cek-all.sh -q"; do
    echo; echo "${B}>> $c${N}"; NOTIFY_RUN_WRAPPED=1 bash "$TOOLS"/$c 2>&1 | tail -40   # tanpa kirim Telegram
  done
}

jadwal_pasang() {
  judul "Pasang jadwal otomatis (cron dan timer)"
  install -m 644 "$DIR/jadwal/lab-reproduksi.cron" /etc/cron.d/lab-reproduksi
  [ -n "$(get_kv "$ENV_WI" OJS_DB)" ] || sed -i 's|^\(.*notif-ojs.py.*\)$|# \1   (OJS_DB kosong)|' /etc/cron.d/lab-reproduksi
  for u in "$DIR"/jadwal/*.service "$DIR"/jadwal/*.timer; do install -m 644 "$u" /etc/systemd/system/; done
  systemctl daemon-reload
  systemctl enable --now lab-web-integrity.timer lab-cek-disk.service >/dev/null 2>&1 && sukses "timer web-integrity (tiap jam) dan cek-disk aktif" || peringatan "systemctl gagal (bukan systemd?)"
  bash "$TOOLS/pk-systemd-setup.sh" dry >/dev/null 2>&1 && sukses "persistence-killer mode dry (hanya melapor) tiap menit" || peringatan "pk-systemd-setup gagal"
  sukses "cron: /etc/cron.d/lab-reproduksi"; sed -n 's/^\([0-9*].*\)$/    \1/p' /etc/cron.d/lab-reproduksi | cut -c1-110
  status_set JADWAL ok
}

jadwal_lepas() {
  judul "Lepas jadwal otomatis (cron dan timer)"
  rm -f /etc/cron.d/lab-reproduksi /etc/cron.d/lab-ip-admin
  systemctl disable --now lab-web-integrity.timer lab-cek-disk.service >/dev/null 2>&1
  bash "$TOOLS/pk-systemd-setup.sh" off >/dev/null 2>&1
  rm -f /etc/systemd/system/lab-web-integrity.{service,timer} /etc/systemd/system/lab-cek-disk.service; systemctl daemon-reload 2>/dev/null
  sukses "jadwal lab dilepas (skrip, konfigurasi, dan data tetap ada)"; status_set JADWAL belum
}

sinkron() {  # perbarui folder lab di server dari folder ini (hasil unzip), lalu pasang skrip yang berubah ke $TOOLS
  local pasang=0 hanya="" a
  while [ $# -gt 0 ]; do case "$1" in --pasang) pasang=1; shift;; --hanya) hanya=",${2:-},"; shift 2;; *) galat "opsi tidak dikenal: $1"; return 2;; esac; done
  judul "Sinkron lab: $DIR  ->  $LAB_TUJUAN  ->  $TOOLS"
  local LEWATI=$ETC_LAB/sinkron-lewati.txt
  if [ ! -f "$LEWATI" ]; then
    mkdir -p "$ETC_LAB"; chmod 700 "$ETC_LAB"
    printf '%s\n' "# skrip yang TIDAK ditimpa oleh 'lab.sh sinkron --pasang' (versi server dipertahankan); satu nama per baris" \
      "# hapus barisnya bila versi lab memang ingin dipakai, atau pasang satu per satu dengan --hanya NAMA" \
      backup-all-db.sh backup-all-web.sh backup_vps.py > "$LEWATI"; chmod 600 "$LEWATI"
  fi
  if [ "$(readlink -f "$DIR")" != "$(readlink -f "$LAB_TUJUAN")" ]; then
    mkdir -p "$LAB_TUJUAN"
    # --delete: folder lab di server dibuat sama persis dengan paket baru, supaya folder/skrip bernama lama tidak ikut
    # terbaca. Berkas yang terhapus tidak hilang: dipindah ke .sebelum-sinkron/lab-<waktu>. Folder .git tidak disentuh.
    local bak_lab="$TOOLS/.sebelum-sinkron/lab-$(date +%Y%m%d-%H%M%S)"
    rsync -a --delete --backup --backup-dir="$bak_lab" --exclude .git --exclude '__pycache__' "$DIR"/ "$LAB_TUJUAN"/ \
      && sukses "folder lab diperbarui: $LAB_TUJUAN (sama persis dengan paket baru)"
    [ -d "$bak_lab" ] && { chmod 700 "$TOOLS/.sebelum-sinkron" "$bak_lab"; info "berkas lama di folder lab dipindah ke $bak_lab"; }
    chown -R root:root "$LAB_TUJUAN"; chmod -R go-w "$LAB_TUJUAN"; chmod 750 "$LAB_TUJUAN"
  else info "dijalankan dari folder lab di server; langsung membandingkan dengan $TOOLS"; fi
  local f n t sama=0 beda=() baru=() lewat=() TS bak
  while read -r f; do
    n=$(basename "$f"); t="$TOOLS/$n"
    if [ ! -f "$t" ]; then baru+=("$n")
    elif cmp -s "$f" "$t"; then sama=$((sama+1))
    elif grep -qxF "$n" "$LEWATI" && [[ $hanya != *",$n,"* ]]; then lewat+=("$n")
    else beda+=("$n"); fi
  done < <(daftar_skrip_di "$LAB_TUJUAN")
  echo "  sama              : $sama skrip"
  echo "  berbeda           : ${#beda[@]}  ${beda[*]}"
  echo "  baru (belum ada)  : ${#baru[@]}  ${baru[*]}"
  echo "  dipertahankan     : ${#lewat[@]}  ${lewat[*]}  (lihat $LEWATI)"
  [ -n "$hanya" ] && { local x=() y=(); for a in "${beda[@]}"; do [[ $hanya == *",$a,"* ]] && x+=("$a"); done
                       for a in "${baru[@]}"; do [[ $hanya == *",$a,"* ]] && y+=("$a"); done; beda=("${x[@]}"); baru=("${y[@]}")
                       echo "  --hanya           : ${beda[*]} ${baru[*]}"; }
  if [ "$pasang" -ne 1 ]; then
    echo; info "belum ada yang dipasang. Lihat beda satu skrip: diff $TOOLS/NAMA $LAB_TUJUAN/<folder>/NAMA"
    info "pasang: sudo bash $0 sinkron --pasang   (atau --pasang --hanya nama1,nama2)"; return 0
  fi
  [ $((${#beda[@]}+${#baru[@]})) -gt 0 ] || { singkirkan_nama_lama "$TOOLS/.sebelum-sinkron/$(date +%Y%m%d-%H%M%S)"; sukses "tidak ada yang perlu dipasang"; return 0; }
  TS=$(date +%Y%m%d-%H%M%S); bak="$TOOLS/.sebelum-sinkron/$TS"; mkdir -p "$bak"; chmod 700 "$TOOLS/.sebelum-sinkron" "$bak"
  for n in "${beda[@]}" "${baru[@]}"; do
    f=$(daftar_skrip_di "$LAB_TUJUAN" | awk -F/ -v n="$n" '$NF==n' | head -1)
    [ -f "$TOOLS/$n" ] && cp -a "$TOOLS/$n" "$bak/$n"
    install -m 750 -o root -g root "$f" "$TOOLS/$n" && echo "  [ OK ] $n"
  done
  singkirkan_nama_lama "$bak"
  sukses "versi lama disimpan di $bak"
  info "kembalikan satu skrip: sudo install -m 750 $bak/NAMA $TOOLS/NAMA"
  if [ -f /etc/cron.d/lab-reproduksi ] && ! cmp -s "$LAB_TUJUAN/jadwal/lab-reproduksi.cron" /etc/cron.d/lab-reproduksi; then
    peringatan "jadwal di lab berbeda dengan /etc/cron.d/lab-reproduksi (tidak diubah otomatis): diff $LAB_TUJUAN/jadwal/lab-reproduksi.cron /etc/cron.d/lab-reproduksi"
  fi
}

daftar_skrip_di() { ls "$1"/modul/*/*.sh "$1"/modul/*/*.py "$1"/pencegahan/*.sh "$1"/pendukung/*.sh "$1"/pendukung/*.py "$1"/uji/*.py 2>/dev/null; }

ip_admin() {  # IP yang dikecualikan dari laporan/blokir: IP tetap + IP dinamis (dibaca dari nama DDNS tiap 10 menit)
  judul "IP admin (dikecualikan dari laporan IP mencurigakan dan dari blokir cf-guard)"
  local tetap ddns h ip x ssh_ip
  tetap=$(get_kv "$ENV_WI" IP_KANTOR_TETAP); ddns=$(get_kv "$ENV_WI" IP_KANTOR_DDNS)
  info "sekarang: IP_KANTOR=\"$(get_kv "$ENV_WI" IP_KANTOR)\"  TETAP=\"$tetap\"  DDNS=\"$ddns\""
  ssh_ip=$(who 2>/dev/null | grep -oE '\([0-9a-fA-F:.]+\)' | tr -d '()' | sort -u | paste -sd' ' -)
  [ -n "$ssh_ip" ] && info "IP yang sedang login SSH ke server ini: $ssh_ip (bila Anda di kantor, inilah IP kantor saat ini)"
  echo "  IP tetap  : IP yang tidak pernah berubah (internet dedicated). Kosongkan bila tidak yakin."
  echo "  Nama DDNS : untuk IP yang berubah-ubah, mis. kantor.duckdns.org atau xxxx.sn.mynetname.net (IP Cloud MikroTik)."
  if [ $# -ge 1 ]; then tetap=${1#-}; ddns=${2:-}; ddns=${ddns#-}   # langsung: lab.sh ip-admin "IP tetap" "nama DDNS" ('-' = kosong)
  else tanya tetap "IP tetap (pisahkan spasi)" "$tetap"; tanya ddns "Nama DDNS (pisahkan spasi)" "$ddns"; fi
  for x in $tetap; do [[ $x =~ ^[0-9a-fA-F:.]+(/[0-9]+)?$ ]] || { galat "bukan alamat IP: $x"; return 1; }; done
  for h in $ddns; do
    [[ $h =~ ^[A-Za-z0-9.-]+\.[A-Za-z]{2,}$ ]] || { galat "bukan nama domain: $h"; return 1; }
    ip=$(getent ahostsv4 "$h" | awk '{print $1; exit}')
    if [ -n "$ip" ]; then sukses "$h -> $ip"; else peringatan "$h belum bisa di-resolve (pastikan klien DDNS di router/PC sudah jalan)"; fi
  done
  [ -n "$tetap$ddns" ] || { peringatan "dua-duanya kosong: tidak ada IP yang dikecualikan"; return 0; }
  set_kv "$ENV_WI" IP_KANTOR_TETAP "$tetap"; set_kv "$ENV_WI" IP_KANTOR_DDNS "$ddns"
  bash "$TOOLS/ip-kantor-sync.sh" | sed 's/^/  /'
  if [ -n "$ddns" ]; then
    printf '# dipasang oleh lab.sh ip-admin: perbarui IP admin dari nama DDNS\n*/10 * * * * root %s/ip-kantor-sync.sh > /dev/null 2>&1\n' "$TOOLS" > /etc/cron.d/lab-ip-admin
    chmod 644 /etc/cron.d/lab-ip-admin; sukses "IP dinamis diperbarui otomatis tiap 10 menit (/etc/cron.d/lab-ip-admin)"
  else rm -f /etc/cron.d/lab-ip-admin; fi
  sukses "IP_KANTOR sekarang: $(get_kv "$ENV_WI" IP_KANTOR)"
}

ojs_db() {  # nama database OJS dibaca dari config.inc.php ([database] name = ...)
  judul "Database OJS"
  local cfg nama d=""
  for cfg in /var/www/*/config.inc.php /var/www/*/*/config.inc.php; do
    [ -f "$cfg" ] && grep -q '^\[database\]' "$cfg" || continue
    nama=$(awk '/^\[database\]/{f=1;next} /^\[/{f=0} f&&/^[[:space:]]*name[[:space:]]*=/{sub(/^[^=]*=[[:space:]]*/,""); gsub(/["[:space:]]/,""); print; exit}' "$cfg")
    [ -n "$nama" ] && { info "$cfg -> $nama"; d=${d:-$nama}; }
  done
  nama=${1:-}; [ -n "$nama" ] || tanya nama "Nama database OJS" "${d:-$(get_kv "$ENV_WI" OJS_DB)}"
  [[ $nama =~ ^[A-Za-z0-9_]+$ ]] || { galat "nama database tidak valid: $nama"; return 1; }
  if [ "$(mysql -N -B -e "SELECT COUNT(*) FROM information_schema.TABLES WHERE TABLE_SCHEMA='$nama' AND TABLE_NAME='users'" 2>/dev/null)" = 1 ]; then
    set_kv "$ENV_WI" OJS_DB "$nama"; sukses "OJS_DB=\"$nama\" (dipakai web-integrity-cek, ip-report, notif-ojs, L3-trigger-ojs)"
  else galat "database '$nama' tidak ada atau bukan OJS (tabel users tidak ditemukan); tidak disimpan"; return 1; fi
}

soc_ir() {
  judul "SOC-IR (Bodyguard HITL: tingkat aksi T0-T3 dengan persetujuan manusia)"
  local bg="$DIR/modul/M5-blokir-attacker/soc-ir/bodyguard-hitl"
  bash "$bg/tools/install.sh" --plan | tail -25
  ya_tidak "Terapkan rencana di atas (--apply)? Timer TIDAK dinyalakan otomatis" n && bash "$bg/tools/install.sh" --apply
  echo "Langkah lanjut: isi /etc/bodyguard/bodyguard.conf (mode = dry-run), lalu: systemctl enable --now bodyguard-scan.timer"
}

uninstall_lab() {
  judul "Uninstall lab"
  ya_tidak "Lepas jadwal dan hapus skrip lab dari $TOOLS? (konfigurasi /etc, baseline, bukti, dan backup TIDAK dihapus)" n || return 0
  jadwal_lepas
  daftar_skrip | while read -r f; do t="$TOOLS/$(basename "$f")"; cmp -s "$f" "$t" && rm -f "$t"; done
  sukses "skrip lab dilepas (skrip yang berbeda dari versi lab dibiarkan)"
}

menu() {
  while true; do
    cat <<EOF

${B}Lab Reproduksi - menu${N}
  1) Status lab                    6) Pasang jadwal otomatis
  2) Demo aman (simulasi)          7) Lepas jadwal otomatis
  3) Buat baseline                 8) Pasang SOC-IR (Bodyguard)
  4) Jalankan pemeriksaan          9) Alat uji skripsi (uji-skripsi.py)
  5) Atur token Telegram/CF       10) Uninstall lab
 11) IP admin (tetap/DDNS)        12) Database OJS
 13) Sinkron dari folder ini (rencana)
  0) Keluar
EOF
    read -r -p "Pilih: " p || exit 0
    case "$p" in 1) status;; 2) bash "$DIR/demo/demo-lab.sh";; 3) baseline;; 4) cek;; 5) bash "$DIR/atur-token.sh";;
      6) jadwal_pasang;; 7) jadwal_lepas;; 8) soc_ir;; 9) python3 "$TOOLS/uji-skripsi.py";; 10) uninstall_lab;; 11) ip_admin;; 12) ojs_db;; 13) sinkron;; 0) exit 0;; *) echo "?";; esac
  done
}

case "${1:-menu}" in
  status) status;; sinkron) shift; sinkron "$@";; ip-admin) shift; ip_admin "$@";; ojs-db) ojs_db "${2:-}";; demo) bash "$DIR/demo/demo-lab.sh";; demo-bersihkan) bash "$DIR/demo/demo-lab.sh" --bersihkan;;
  baseline) baseline;; cek) cek;; token) bash "$DIR/atur-token.sh";; pasang-cron) jadwal_pasang;; lepas-cron) jadwal_lepas;;
  soc-ir) soc_ir;; uji) python3 "$TOOLS/uji-skripsi.py";; uninstall) uninstall_lab;; menu) menu;;
  *) sed -n '2,3p' "$0"; exit 2;;
esac
