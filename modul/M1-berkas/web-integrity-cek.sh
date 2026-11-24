#!/bin/bash
# web-integrity-cek.sh v3 - Modul M1 (deteksi berkas)
# Pakai (root):
#   web-integrity-cek.sh                 periksa webroot terhadap baseline (dipanggil timer lewat notify-run.sh)
#   web-integrity-cek.sh --rebuild       buat baseline baru (HANYA saat situs dipastikan bersih)
#   web-integrity-cek.sh --accept        terima perubahan SAH (update plugin/WP): ringkasan per situs, pemeriksaan IOC,
#                                        konfirmasi, arsip 6 baseline lama, lalu rebuild
#   web-integrity-cek.sh --accept --yes  sama, tanpa pertanyaan (dipanggil SOC-IR setelah disetujui admin lewat Telegram);
#                                        keluar kode 3 dan baseline TIDAK diubah bila masih ada temuan penghalang
# Perubahan v3: integrity-accept.sh digabung ke opsi --accept; pesan Telegram lewat notify-run.sh.
# Perbaikan bug dari versi server 18 Nov 2026 (logika deteksi TIDAK diubah):
#  - tidak ada lagi "grep | head" di akhir: head menutup pipe, pipefail mengambil status grep (141/2) dan systemd
#    menandai service FAILED. Dipakai awk satu proses; skrip selalu diakhiri "exit 0".
#  - nomor baris IOC memakai "grep -m1" (tanpa pipe).
#  - trap EXIT ikut membersihkan berkas sementara turunan ($CURR.*).
#  - cabang "tanpa IOC" memberi pengingat cara menerima perubahan sah (--accept).
# Perubahan dari v1:
#  - Token Telegram dibaca dari /etc/web-integrity.env (chmod 600), tidak di dalam skrip
#  - cache/ dan vendor/ TIDAK lagi dikecualikan untuk file kode (php, phtml, phar, inc, js, so, htaccess, .user.ini)
#  - Alert langsung bila ada PHP baru di uploads/cache/images, folder plugin baru, atau mu-plugin baru
#  - Cek akun admin palsu (susupan) di semua database WordPress (email .internal, login wpsvc*, admin baru 24 jam)
#  - Deteksi IOC token/webshell (hash_equals+$_GET, marker <<S>>, shell_exec dkk) di file yang berubah
#  - Baseline tidak dibuat otomatis diam-diam: pakai --rebuild (setelah situs dipastikan bersih)
#  - Pesan Telegram plain text (tanpa Markdown) agar tidak gagal kirim karena karakter khusus
#
# Siapkan /etc/web-integrity.env (root, chmod 600):
#   TELEGRAM_BOT_TOKEN="..."   (token BARU, token lama sudah bocor)
#   TELEGRAM_CHAT_ID="-100xxxxxxxxxx"   (lihat README: cara mencari chat id)
#   IP_KANTOR="203.0.113.10"          (IP kantor yang sah, pisahkan spasi)
#   OJS_SITE="jurnal.kampus.ac.id"     (folder & log OJS, kosongkan bila tidak ada OJS)
set -uo pipefail

[ -f /etc/web-integrity.env ] && . /etc/web-integrity.env   # dibaca lebih awal supaya WEBROOT/HASHDB_DIR bisa diatur di sana
WEBROOT="${WEBROOT:-/var/www/html}"
HASHDB_DIR="${HASHDB_DIR:-/var/opt/filehash-web-all}"
HASHDB="${HASHDB_DIR}/baseline.sha256"
CURR="$(mktemp "${TMPDIR:-/run}/wi-curr.XXXXXX")"; DIFF="$(mktemp "${TMPDIR:-/run}/wi-diff.XXXXXX")"
trap 'rm -f "$CURR" "$DIFF" "${CURR}".*' EXIT

# shellcheck disable=SC1091
[ -f /etc/web-integrity.env ] && . /etc/web-integrity.env
: "${TELEGRAM_BOT_TOKEN:=}"; : "${TELEGRAM_CHAT_ID:=}"

# ---- --accept: terima perubahan sah ke baseline (menggantikan integrity-accept.sh) ----
if [ "${1:-}" = "--accept" ]; then
  YES=0; [ "${2:-}" = "--yes" ] && YES=1
  BLOCK_RE='^(\[FAIL\] )?(IOC:|PHP DI FOLDER DATA:|AKUN BARU/(SILUMAN|PALSU)|PLUGIN/MU-PLUGIN BARU:|EKSTENSI GANDA:|PHP DI DALAM GAMBAR:|OJS (ADMIN|UPLOADER|EKSTENSI)|DB OJS|CRONTAB www-data|authorized_keys)'
  [ "$(id -u)" -eq 0 ] || { echo "Jalankan dengan sudo."; exit 2; }
  [ -f "$HASHDB" ] || { echo "Baseline belum ada, jalankan: $0 --rebuild"; exit 1; }
  echo "== Pemeriksaan perubahan terhadap baseline =="
  OUT=$(mktemp "${TMPDIR:-/run}/wi-acc.XXXXXX"); WI_DIFF_MAX=999999999 NOTIFY_RUN_WRAPPED=1 "$0" > "$OUT" 2>&1
  grep -vE '^[<>] [0-9a-f]{64}  ' "$OUT" | head -40
  echo "(daftar lengkap berkas: $HASHDB_DIR/accept-terakhir.txt)"
  grep -E '^[<>] [0-9a-f]{64}  ' "$OUT" > "$HASHDB_DIR/accept-terakhir.txt"; chmod 600 "$HASHDB_DIR/accept-terakhir.txt"
  echo; echo "== Ringkasan perubahan per situs =="; printf '  %-34s %8s %8s %8s\n' situs berubah baru hilang
  grep -E '^[<>] [0-9a-f]{64}  ' "$OUT" | awk -v w="${WEBROOT}/" '{ t=$1; f=substr($0, index($0,$3)); sub("^" w, "", f); s=f; sub("/.*", "", s);
      k=s SUBSEP f; if (t=="<") a[k]=1; else b[k]=1; S[s]=1 }
    END { for (k in a) { split(k, x, SUBSEP); if (k in b) ub[x[1]]++; else hl[x[1]]++ }
          for (k in b) { split(k, x, SUBSEP); if (!(k in a)) br[x[1]]++ }
          for (s in S) printf "  %-34s %8d %8d %8d\n", s, ub[s], br[s], hl[s] }' | sort -k2 -rn
  BLOCKERS=$(grep -cE "$BLOCK_RE" "$OUT" || true); rm -f "$OUT"
  echo
  if [ "$YES" -eq 1 ]; then
    [ "$BLOCKERS" -gt 0 ] && { echo "DITOLAK: $BLOCKERS baris IOC/PHP data/akun/plugin baru masih ada. Baseline TIDAK diubah."; exit 3; }
    echo "Mode --yes: tidak ada temuan penghalang, baseline diterima."
  else
    echo "JANGAN terima bila ada IOC, PHP DI FOLDER DATA, AKUN BARU/PALSU, atau PLUGIN BARU yang tidak Anda pasang sendiri."
    echo "Selidiki dulu dengan kumpulkan-bukti.sh --auto."
    [ "$BLOCKERS" -gt 0 ] && echo "!!! $BLOCKERS baris penghalang terdeteksi pada pemeriksaan barusan."
    read -rp "Terima perubahan di atas ke baseline? [y/N] " a
    [ "$a" = "y" ] || { echo "Dibatalkan, baseline tidak diubah."; exit 0; }
  fi
  cp -p "$HASHDB" "$HASHDB.$(date +%F-%H%M%S)"
  ls -1t "$HASHDB".* 2>/dev/null | tail -n +7 | xargs -r rm -f
  rm -f "$HASHDB_DIR/known_plugin_dirs.txt"       # daftar plugin yang dikenal ikut diperbarui
  "$0" --rebuild && NOTIFY_RUN_WRAPPED=1 "$0" >/dev/null 2>&1
  echo "Selesai. Arsip baseline: $(ls "$HASHDB".* 2>/dev/null | wc -l) salinan."
  exit 0
fi

exec 9>"${WI_LOCK:-/run/web-integrity.lock}"
flock -n 9 || { echo "[!] Proses sebelumnya masih jalan."; exit 0; }

NOTIFY_RUN=${NOTIFY_RUN:-$(dirname "$(readlink -f "$0")")/notify-run.sh}
send_alert() {  # di bawah notify-run.sh (timer) baris [FAIL] sudah dikirim dan dideduplikasi oleh pembungkus
  [ "${NOTIFY_RUN_WRAPPED:-0}" = 1 ] && return 0
  [ -x "$NOTIFY_RUN" ] || { echo "[WARN] notify-run.sh tidak ada, alert hanya ke console"; return 0; }
  printf '%s' "$1" | "$NOTIFY_RUN" --pesan || echo "[WARN] alert Telegram gagal terkirim"
}

CODE_NAMES=( -name '*.php' -o -name '*.phtml' -o -name '*.phar' -o -name '*.php[0-9]' -o -name '*.pht' -o -name '*.inc'
             -o -name '*.js' -o -name '*.so' -o -name '.htaccess' -o -name '.user.ini' -o -name '*.sh' -o -name '*.py' -o -name '*.pl' )
PRUNE=( -path '*/.git/*' -o -path '*/node_modules/*' -o -path '*/wp-content/cache/*/*.js' -o -path '*/storage/framework/*' -o -path '*/storage/logs/*' )

build_list() {
  nice -n 10 ionice -c2 -n7 \
  find "$WEBROOT" \( "${PRUNE[@]}" \) -prune -o -type f \( "${CODE_NAMES[@]}" \) -print0 \
  | xargs -0 -r -P 4 sha256sum | sort -k2 > "$1"
}

if [ "${1:-}" = "--rebuild" ]; then
  mkdir -p "$HASHDB_DIR"; chmod 700 "$HASHDB_DIR"
  build_list "$HASHDB"; chmod 600 "$HASHDB"
  echo "[OK] baseline dibuat ulang: $HASHDB ($(wc -l < "$HASHDB") file)"; exit 0
fi
[ -f "$HASHDB" ] || { echo "[!] Baseline belum ada. Jalankan: $0 --rebuild setelah situs bersih."; send_alert "web-integrity: baseline belum ada di $(hostname)"; exit 1; }

ALERTS=""
add() { ALERTS+="$1"$'\n'; }

# ---- A) Diff hash ----
build_list "$CURR"
diff "$HASHDB" "$CURR" > "$DIFF" || true
CHANGED=$(grep -E '^[<>] [0-9a-f]{64}  /' "$DIFF" | sed -E 's/^[<>] [0-9a-f]{64}  //' | sort -u)
NCHANGED=$(grep -c . <<< "$CHANGED") || NCHANGED=0

IOC='hash_equals[[:space:]]*\([^)]{0,60}\$_GET\[.t.\]|<<S>>|GH_R0_EXEC|SSInjection|wordpress-svc\.internal|(shell_exec|passthru|system|exec|popen|proc_open)[[:space:]]*\([[:space:]]*\$_(GET|POST|REQUEST|COOKIE)|eval[[:space:]]*\([[:space:]]*(base64_decode|gzinflate|str_rot13|\$_(GET|POST|REQUEST|COOKIE))|assert[[:space:]]*\([[:space:]]*\$_|gs-netcat|gsocket|base64_decode\(\$_(GET|POST|REQUEST)|slot gacor|togel'
IOC_MARK='<<S>>|GH_R0_EXEC|SSInjection|wordpress-svc\.internal|gs-netcat|gsocket|slot gacor'
SIG='0xNix Encrypted Code|SPLIT&ENCRYPTed|yoibre\.com|aHR0cHM6Ly95b2li'
IOC="$IOC|$SIG"; IOC_MARK="$IOC_MARK|$SIG"
while IFS= read -r f; do
  [ -f "$f" ] || { continue; }
  case "$f" in
    */wp-content/plugins/*|*/wp-content/themes/*|*/vendor/*) : ;;   # folder bernama cache/upgrade milik plugin, bukan folder data
    */cache/t_compile/*|*/cache/fc-*|*/bootstrap/cache/*) : ;;       # cache OJS (Smarty) dan Laravel yang sah
    */classes/migration/upgrade/*) : ;;                             # migrasi upgrade OJS/PKP (kode inti, bukan folder data)
    *.l10n.php) : ;;
    */uploads/*.php|*/cache/*.php|*/images/*.php|*/upgrade/*.php|*/fonts/*.php|*/languages/*.php|*/files/*.php|*/public/*.php|*/ijazah/*.php)
      [[ "$f" == */index.php ]] || add "PHP DI FOLDER DATA: $f";;
  esac
  # pola fungsi PHP hanya berarti di file PHP; di JS/lainnya cukup penanda khas serangan kita
  case "$f" in
    *.php|*.phtml|*.phar|*.inc|*.pht|*.php[0-9]) re="$IOC" ;;
    *) re="$IOC_MARK" ;;
  esac
  if grep -qiE "$re" "$f" 2>/dev/null; then
    ln=$(grep -niE -m1 "$re" "$f" 2>/dev/null); ln="${ln%%:*}"
    add "IOC: $f (baris ${ln:-?})"
  fi
  # double-extension / menyamar
  [[ "$f" =~ \.(map|css|json|txt|jpe?g|png|gif|ico|svg|webp|dat|log)\.(php|phtml|phar)$ ]] && add "EKSTENSI GANDA: $f"
done <<< "$CHANGED"

# ---- B) Folder plugin / mu-plugin baru (walau isinya tidak mengandung IOC) ----
KNOWN_PLUGINS="$HASHDB_DIR/known_plugin_dirs.txt"
find "$WEBROOT" -maxdepth 5 -type d \( -path '*/wp-content/plugins/*' -o -path '*/wp-content/mu-plugins/*' \) 2>/dev/null \
  | awk -F/ '{n=NF; if ($(n-1)=="plugins" || $(n-1)=="mu-plugins") print}' | sort > "$CURR.pl"
if [ -f "$KNOWN_PLUGINS" ]; then
  comm -13 "$KNOWN_PLUGINS" "$CURR.pl" | while IFS= read -r d; do echo "PLUGIN/MU-PLUGIN BARU: $d"; done > "$CURR.new"
  [ -s "$CURR.new" ] && ALERTS+="$(cat "$CURR.new")"$'\n'
else
  cp "$CURR.pl" "$KNOWN_PLUGINS"
fi
rm -f "$CURR.pl" "$CURR.new"

# ---- C) Akun admin palsu/susupan (WordPress) ----
for db in $(mariadb -N -e "SHOW DATABASES" 2>/dev/null | grep -vE '^(information_schema|performance_schema|mysql|sys)$'); do
  for t in $(mariadb -N -e "SELECT table_name FROM information_schema.columns WHERE table_schema='$db' AND column_name='user_login' AND table_name LIKE '%users'" 2>/dev/null); do
    r=$(mariadb -N -e "SELECT CONCAT(ID,' ',user_login,' ',user_email,' ',user_registered) FROM \`$db\`.\`$t\`
        WHERE user_email LIKE '%.internal' OR user_login REGEXP '^(wpsvc|svc_)' OR user_registered >= DATE_SUB(UTC_TIMESTAMP(), INTERVAL 24 HOUR)" 2>/dev/null)
    [ -n "$r" ] && add "AKUN BARU/PALSU di $db.$t: $r"
  done
done

# ---- D) Web user tidak boleh punya cron / authorized_keys baru ----
[ -s /var/spool/cron/crontabs/www-data ] && add "CRONTAB www-data TIDAK KOSONG"
[ -e /var/www/.ssh/authorized_keys ] && add "authorized_keys ditemukan untuk www-data"

# ---- E) Polyglot: PHP tersembunyi di file gambar (EXIF) ----
IMGDAYS="${IMGDAYS:-2}"
while IFS= read -r -d '' f; do
  add "PHP DI DALAM GAMBAR: $f"
done < <(find "$WEBROOT" -type f \( -iname '*.jpg' -o -iname '*.jpeg' -o -iname '*.png' -o -iname '*.gif' -o -iname '*.webp' -o -iname '*.ico' \) \
  -mtime -"$IMGDAYS" -size -10M -not -path '*/vendor/*' -not -path '*/node_modules/*' -print0 \
  | xargs -0 -r grep -laF -Z '<?php' 2>/dev/null)

# ---- F) OJS: admin tak dikenal, unggahan oleh akun tanpa peran, ekstensi berbahaya ----
OJS_DB="${OJS_DB:-ojs}"; KNOWN_ADM=/var/opt/script/known_admins.txt
oq() { mariadb -N -B "$OJS_DB" 2>/dev/null; }
if mariadb -N -e "USE \`$OJS_DB\`" 2>/dev/null; then
  out=$(oq <<'SQL'
SELECT DISTINCT u.user_id,u.username,u.email,u.date_registered FROM users u
JOIN user_user_groups uug ON uug.user_id=u.user_id JOIN user_groups ug ON ug.user_group_id=uug.user_group_id
WHERE ug.role_id IN (1,16) AND u.disabled=0;
SQL
)
  while IFS=$'\t' read -r id un em dr; do
    [ -n "$id" ] || continue
    grep -qx "$OJS_DB:$un" "$KNOWN_ADM" 2>/dev/null || add "OJS ADMIN TAK DIKENAL: $id $un $em ($dr)"
  done <<< "$out"
  out=$({ echo "SET @d=${OJS_DAYS:-2};"; cat <<'SQL'
SELECT CONCAT('OJS UPLOADER TANPA PERAN: user=',sf.uploader_user_id,' jurnal=',s.context_id,' ',sf.created_at)
FROM submission_files sf JOIN submissions s ON s.submission_id=sf.submission_id
WHERE sf.uploader_user_id IS NOT NULL AND sf.created_at > NOW() - INTERVAL @d DAY
AND NOT EXISTS (SELECT 1 FROM user_user_groups uug JOIN user_groups ug ON ug.user_group_id=uug.user_group_id
  WHERE uug.user_id=sf.uploader_user_id AND (ug.context_id=s.context_id OR ug.role_id=1) AND ug.role_id<>1048576)
UNION
SELECT CONCAT('OJS EKSTENSI BERBAHAYA: ',f.path,' user=',sf.uploader_user_id)
FROM submission_files sf JOIN files f ON f.file_id=sf.file_id
WHERE sf.created_at > NOW() - INTERVAL @d DAY AND f.path REGEXP '\\.(php[0-9]?|phtml|phar|inc|pht|pl|py|sh|cgi)$';
SQL
} | oq)
  while IFS= read -r l; do [ -n "$l" ] && add "$l"; done <<< "$out"
fi

# ---- G) Brute-force login OJS (log nginx hari ini + kemarin) ----
SAFE_IPS=" ${IP_KANTOR:-} "     # IP kantor dari /etc/web-integrity.env
while read -r n ip; do
  [ -n "$ip" ] || continue
  case "$SAFE_IPS" in *" $ip "*) continue;; esac
  add "BRUTE-FORCE LOGIN OJS: $ip ($n percobaan) -> blokir lewat bot SOC: /blok $ip"
done < <(cat "/var/log/nginx/${OJS_SITE:-jurnal}_access.log" "/var/log/nginx/${OJS_SITE:-jurnal}_access.log.1" 2>/dev/null \
         | grep 'login/signIn' | awk '{print $1}' | sort | uniq -c | awk '$1>=20{print $1, $2}')

# ---- H) Integritas DB OJS ----
OJS_DB="${OJS_DB:-ojs}"; DBSNAP="$HASHDB_DIR/ojs-db.snap"
db_snap() {
  mariadb -N -B "$OJS_DB" 2>/dev/null <<'SQL'
SELECT 'admin_roles', MD5(GROUP_CONCAT(CONCAT(uug.user_id,':',ug.role_id,':',IFNULL(ug.context_id,0)) ORDER BY uug.user_id,ug.user_group_id)) FROM user_user_groups uug JOIN user_groups ug USING(user_group_id) WHERE ug.role_id IN (1,16);
SELECT 'admin_accounts', MD5(GROUP_CONCAT(CONCAT(user_id,username,email,password) ORDER BY user_id)) FROM users WHERE user_id IN (SELECT DISTINCT uug.user_id FROM user_user_groups uug JOIN user_groups ug USING(user_group_id) WHERE ug.role_id IN (1,16));
SELECT 'plugin_list', MD5(GROUP_CONCAT(DISTINCT plugin_name ORDER BY plugin_name)) FROM plugin_settings;
SELECT 'plugin_settings', MD5(GROUP_CONCAT(MD5(CONCAT(plugin_name,setting_name,context_id,IFNULL(setting_value,''))) ORDER BY plugin_name,setting_name,context_id)) FROM plugin_settings;
SELECT 'site_settings', MD5(GROUP_CONCAT(MD5(CONCAT(setting_name,IFNULL(setting_value,''))) ORDER BY setting_name)) FROM site_settings;
SELECT 'self_registration', MD5(GROUP_CONCAT(CONCAT(user_group_id,permit_self_registration) ORDER BY user_group_id)) FROM user_groups;
SQL
}
if [ "${1:-}" = "--snapdb" ]; then db_snap > "$DBSNAP"; chmod 600 "$DBSNAP"; echo "[OK] snapshot DB: $(wc -l < "$DBSNAP") baris"; exit 0; fi
if mariadb -N -e "USE \`$OJS_DB\`" 2>/dev/null; then
  if [ -s "$DBSNAP" ]; then
    db_snap > "$CURR.db"
    diff "$DBSNAP" "$CURR.db" | grep '^>' | awk '{print "DB OJS BERUBAH: "$2}' > "$CURR.dbd"
    [ -s "$CURR.dbd" ] && ALERTS+="$(cat "$CURR.dbd")"$'\n'
    rm -f "$CURR.db" "$CURR.dbd"
  fi
  pat=$(mariadb -N -B "$OJS_DB" 2>/dev/null <<'SQL'
SELECT CONCAT('DB OJS POLA WEBSHELL: journal_settings ',journal_id,' ',setting_name) FROM journal_settings WHERE setting_value REGEXP 'asbarin|<\\?php|eval\\(|base64_decode|<iframe|yoibre|0xNix'
UNION SELECT CONCAT('DB OJS POLA WEBSHELL: site_settings ',setting_name) FROM site_settings WHERE setting_value REGEXP 'asbarin|<\\?php|eval\\(|base64_decode|<iframe|yoibre|0xNix'
UNION SELECT CONCAT('DB OJS POLA WEBSHELL: plugin_settings ',plugin_name,'.',setting_name) FROM plugin_settings WHERE setting_value REGEXP 'asbarin|<\\?php|eval\\(|base64_decode|<iframe|yoibre|0xNix'
UNION SELECT CONCAT('DB OJS FILE BERBAHAYA: ',path) FROM files WHERE path REGEXP '\\.(php[0-9]?|phtml|phar|inc|pht)$';
SQL
)
  [ -n "$pat" ] && ALERTS+="$pat"$'\n'
fi

# ---- Kirim ----
if [ -n "$ALERTS" ]; then
  MSG="⚠️ Web Integrity ALERT $(hostname) $(date '+%F %T')
$ALERTS
(total file berubah: ${NCHANGED})"
  send_alert "$MSG"
  echo "Web Integrity ALERT $(hostname) $(date '+%F %T')"
  awk 'NF { print "[FAIL] " $0 }' <<< "$ALERTS"
  echo "(total file berubah: ${NCHANGED})"
  awk -v m="${WI_DIFF_MAX:-40}" '/^[<>]/ { if (++c <= m) print } END { if (c > m) printf "(... %d baris lagi tidak ditampilkan)\n", c - m }' "$DIFF"
elif [ -s "$DIFF" ]; then
  # perubahan tanpa IOC: ringkas saja (update plugin/tema yang sah), jangan spam
  echo "[i] ${NCHANGED} file berubah tanpa IOC (kemungkinan update sah)."
  awk -v m="${WI_DIFF_MAX:-40}" '/^[<>]/ { if (++c <= m) print } END { if (c > m) printf "(... %d baris lagi tidak ditampilkan)\n", c - m }' "$DIFF"
  echo "[i] Bila perubahan ini memang update sah, terima ke baseline: $0 --accept"
else
  echo "[OK] Tidak ada perubahan."
fi

# status keluar selalu eksplisit, supaya systemd tidak menandai FAILED karena status perintah terakhir
exit 0
