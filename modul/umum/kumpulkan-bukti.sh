#!/usr/bin/env bash
# kumpulkan-bukti.sh - kumpulkan bukti insiden. HANYA MENYALIN, tidak menghapus atau mengubah apa pun.
# Pakai (root):
#   kumpulkan-bukti.sh [--auto] [--dari-m1] [--kasus NAMA] [BERKAS_ATAU_FOLDER...]
#     --auto     cari sendiri: temuan terbaru M1 (lihat --dari-m1), folder plugin bernama acak, PHP di folder data,
#                error_log di inti WordPress, dan berkas berekstensi ganda
#     --dari-m1  ambil semua berkas yang dilaporkan web-integrity-cek.sh (M1) dua hari terakhir
#                (IOC, PHP di dalam gambar, PHP di folder data, ekstensi ganda, plugin baru)
#     --kasus    nama kasus, mis. jurnal-asbarin-20261124; bawaan bukti-<waktu UTC>
#     BERKAS     path absolut tambahan
# Target tambahan juga dibaca dari TARGET_FILE (bawaan /etc/lab-reproduksi/target-bukti.txt), relatif ke webroot.
# Bukti disimpan lewat simpan-bukti.py: salinan 0400 bernama hash SHA-256, metadata JSON, dan MANIFEST.tsv
# di BUKTI_DIR/<kasus>/. Bukti akun database dan potongan log yang cocok pola serangan disimpan dengan cara yang sama.
# Berkas bawaan aplikasi yang memang berisi PHP (cache template OJS, vendor, plugin/tema resmi) tidak ikut dicari
# otomatis supaya hasilnya tidak penuh berkas aman; kalau perlu, sebut path-nya langsung sebagai argumen.
set -uo pipefail
umask 077
[ -f /etc/web-integrity.env ] && . /etc/web-integrity.env
SRC_ROOT="${WEBROOT:-/var/www/html}"
BUKTI_DIR="${BUKTI_DIR:-/var/opt/bukti}"; export BUKTI_DIR
BUKTI="${BUKTI_PY:-$(dirname "$(readlink -f "$0")")/simpan-bukti.py}"
M1_LOG_DIR="${M1_LOG_DIR:-/var/log/audit-run}"
TS=$(date -u +%Y%m%dT%H%M%SZ)
KASUS="bukti-$TS"; AUTO=0; DARI_M1=0; EXTRA=()
while [ $# -gt 0 ]; do case "$1" in
  --auto) AUTO=1; DARI_M1=1; shift;; --dari-m1) DARI_M1=1; shift;; --kasus) KASUS=${2:?nama kasus}; shift 2;;
  -h|--help) sed -n '2,16p' "$0"; exit 0;;
  /*) EXTRA+=("$1"); shift;; *) echo "argumen tidak dikenal: $1"; exit 2;; esac; done
[[ $KASUS =~ ^[A-Za-z0-9][A-Za-z0-9._-]{0,99}$ ]] || { echo "nama kasus tidak valid"; exit 2; }
[ -f "$BUKTI" ] || { echo "simpan-bukti.py tidak ditemukan ($BUKTI)"; exit 2; }
simpan() { /usr/bin/python3 -I "$BUKTI" simpan --kasus "$KASUS" "$@"; }

# berkas PHP bawaan aplikasi yang wajar berada di folder bernama cache/images/upgrade (sama dengan pengecualian M1)
aman_bawaan() {
  case "$1" in
    */wp-content/plugins/*|*/wp-content/themes/*|*/vendor/*) return 0;;
    */cache/t_compile/*|*/cache/fc-*|*/cache/opcache/*|*/bootstrap/cache/*|*/classes/migration/upgrade/*) return 0;;
  esac
  return 1
}

TARGETS=()
TFILE="${TARGET_FILE:-/etc/lab-reproduksi/target-bukti.txt}"
[ -f "$TFILE" ] && while IFS= read -r t; do case "$t" in ""|\#*) ;; *) TARGETS+=("$SRC_ROOT/$t");; esac; done < "$TFILE"
TARGETS+=("${EXTRA[@]}")

if [ $DARI_M1 -eq 1 ]; then
  echo "[*] Mengambil temuan M1 dua hari terakhir dari $M1_LOG_DIR ..."
  n0=${#TARGETS[@]}
  while IFS= read -r f; do TARGETS+=("$f"); done < <(
    cat "$M1_LOG_DIR"/web-integrity-"$(date +%F)".log "$M1_LOG_DIR"/web-integrity-"$(date -d yesterday +%F)".log 2>/dev/null \
      | sed -nE 's#^(\[FAIL\] )?(IOC|PHP DI DALAM GAMBAR|PHP DI FOLDER DATA|EKSTENSI GANDA|PLUGIN/MU-PLUGIN BARU): (/[^ ]+).*#\3#p' \
      | sort -u)
  echo "    $(( ${#TARGETS[@]} - n0 )) berkas dari laporan M1"
fi

if [ $AUTO -eq 1 ]; then
  echo "[*] Pencarian otomatis..."
  while IFS= read -r d; do TARGETS+=("$d"); done < <(      # 1) plugin bernama samaran (akhiran heksadesimal)
    find "$SRC_ROOT" -maxdepth 6 -type d -path '*/wp-content/plugins/*' -regextype posix-extended \
      -regex '.*/plugins/[a-z0-9-]+-[0-9a-f]{6}$' 2>/dev/null)
  while IFS= read -r f; do aman_bawaan "$f" || TARGETS+=("$f"); done < <(      # 2) PHP di folder data (selain index.php)
    find "$SRC_ROOT" -type f \( -iname '*.php' -o -iname '*.phtml' -o -iname '*.phar' \) \
      \( -path '*/uploads/*' -o -path '*/images/*' -o -path '*/cache/*' -o -path '*/files/*' -o -path '*/public/*' \) \
      ! -name 'index.php' 2>/dev/null | head -500)
  while IFS= read -r f; do TARGETS+=("$f"); done < <(      # 3) error_log di inti WordPress
    find "$SRC_ROOT" -type f -name error_log \( -path '*/wp-admin/*' -o -path '*/wp-includes/*' \) 2>/dev/null)
  while IFS= read -r f; do aman_bawaan "$f" || TARGETS+=("$f"); done < <(      # 4) ekstensi ganda atau cadangan berisi PHP
    find "$SRC_ROOT" -type f -regextype posix-extended \
      -iregex '.*\.(map|css|json|txt|jpe?g|png|gif|ico|svg|webp|dat|log)\.(php|phtml|phar)|.*\.php\.(save|bak|old|gif|jpg|png|txt)' 2>/dev/null | head -200)
fi

# buang duplikat (urutan dipertahankan)
mapfile -t TARGETS < <(printf '%s\n' "${TARGETS[@]}" | awk 'NF && !seen[$0]++')

ok=0; skip=0
for src in "${TARGETS[@]}"; do
  if [ -L "$src" ] || [ ! -e "$src" ]; then echo "[SKIP] $src (tidak ada atau symlink)"; skip=$((skip+1)); continue; fi
  if [ -d "$src" ]; then
    mapfile -d '' isi < <(find "$src" -type f -print0 2>/dev/null | head -z -n 300)
    [ ${#isi[@]} -gt 0 ] && simpan --label "dir:${src#$SRC_ROOT/}" -- "${isi[@]}" > /dev/null
  else
    simpan -- "$src" > /dev/null
  fi && { ok=$((ok+1)); echo "[OK] $src"; } || { skip=$((skip+1)); echo "[SKIP] $src (ditolak simpan-bukti.py)"; }
done

# ---- bukti database: akun palsu (susupan) dan admin baru (hanya SELECT) ----
SEJAK=${ADMIN_SEJAK:-$(date -d '-30 days' +%F)}
TMP=$(mktemp); trap 'rm -f "$TMP"' EXIT
if command -v mariadb >/dev/null; then
  for db in $(mariadb -N -e "SHOW DATABASES" 2>/dev/null | grep -vE '^(information_schema|performance_schema|mysql|sys)$'); do
    for t in $(mariadb -N -e "SELECT table_name FROM information_schema.columns WHERE table_schema='$db' AND column_name='user_login' AND table_name LIKE '%users'"); do
      echo "== $db.$t"
      mariadb -N -e "SELECT ID,user_login,user_email,user_registered FROM \`$db\`.\`$t\` WHERE user_email LIKE '%.internal' OR user_login LIKE 'wpsvc%' OR user_login LIKE 'svc\\_%' OR user_registered >= '$SEJAK'" 2>/dev/null
    done
  done > "$TMP"
  [ -s "$TMP" ] && /usr/bin/python3 -I "$BUKTI" simpan-stdin --kasus "$KASUS" --label "db-akun-sejak-$SEJAK" < "$TMP" > /dev/null && echo "[OK] bukti akun database"
fi

# ---- potongan log akses yang cocok pola serangan (paling banyak 200 MB) ----
zgrep -hE 'security-headers-manager|[?&]c=(id|whoami|echo)|GH_R0_EXEC|wpsvc_|/shell_[0-9]+\.php|blank\.php\?c=' /var/log/nginx/*access.log* 2>/dev/null \
  | head -c $((200*1024*1024)) > "$TMP"
[ -s "$TMP" ] && /usr/bin/python3 -I "$BUKTI" simpan-stdin --kasus "$KASUS" --label "log-ioc-nginx" < "$TMP" > /dev/null && echo "[OK] potongan log yang cocok pola serangan"

echo "Selesai. OK=$ok SKIP=$skip  Kasus: $BUKTI_DIR/$KASUS (MANIFEST.tsv)"
