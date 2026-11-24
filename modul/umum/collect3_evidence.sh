#!/usr/bin/env bash
# collect3_evidence.sh - kumpulkan bukti insiden (hanya menyalin, tidak menghapus apa pun). Utilitas bersama.
# Pakai (root):
#   collect3_evidence.sh [--auto] [--kasus NAMA] [BERKAS_ATAU_FOLDER...]
#     --auto   tambahkan temuan otomatis: folder plugin bernama acak heksadesimal, PHP di folder data,
#              error_log di inti WordPress, dan ekstensi ganda
#     --kasus  nama kasus (mis. ID insiden SOC-IR); bawaan collect3-<waktu UTC>
#     BERKAS   path absolut tambahan (dipakai bg-root untuk satu berkas yang baru dikunci)
# Target tambahan juga dibaca dari TARGET_FILE (bawaan /etc/lab-reproduksi/target-bukti.txt), relatif ke webroot.
# Penyimpanan memakai fungsi bersama bukti.py: salinan 0400 bernama hash SHA-256, metadata JSON, dan MANIFEST.tsv
# di BUKTI_DIR/<kasus>/. Bukti database dan potongan log IOC disimpan dengan cara yang sama (log dibatasi 200 MB).
set -uo pipefail
umask 077
[ -f /etc/web-integrity.env ] && . /etc/web-integrity.env
SRC_ROOT="${WEBROOT:-/var/www/html}"
BUKTI_DIR="${BUKTI_DIR:-/var/opt/bukti}"; export BUKTI_DIR
BUKTI="${BUKTI_PY:-$(dirname "$(readlink -f "$0")")/bukti.py}"
TS=$(date -u +%Y%m%dT%H%M%SZ)
KASUS="collect3-$TS"; AUTO=0; EXTRA=()
while [ $# -gt 0 ]; do case "$1" in
  --auto) AUTO=1; shift;; --kasus) KASUS=${2:?nama kasus}; shift 2;;
  /*) EXTRA+=("$1"); shift;; *) echo "argumen tidak dikenal: $1"; exit 2;; esac; done
[[ $KASUS =~ ^[A-Za-z0-9][A-Za-z0-9._-]{0,99}$ ]] || { echo "nama kasus tidak valid"; exit 2; }
[ -f "$BUKTI" ] || { echo "bukti.py tidak ditemukan ($BUKTI)"; exit 2; }
simpan() { /usr/bin/python3 -I "$BUKTI" simpan --kasus "$KASUS" "$@"; }

TARGETS=()
TFILE="${TARGET_FILE:-/etc/lab-reproduksi/target-bukti.txt}"
[ -f "$TFILE" ] && while IFS= read -r t; do case "$t" in ""|\#*) ;; *) TARGETS+=("$SRC_ROOT/$t");; esac; done < "$TFILE"
TARGETS+=("${EXTRA[@]}")

if [ $AUTO -eq 1 ]; then
  echo "[*] Pencarian otomatis..."
  while IFS= read -r d; do TARGETS+=("$d"); done < <(      # 1) plugin bernama samaran (akhiran heksadesimal)
    find "$SRC_ROOT" -maxdepth 6 -type d -path '*/wp-content/plugins/*' -regextype posix-extended \
      -regex '.*/plugins/[a-z0-9-]+-[0-9a-f]{6}$' 2>/dev/null)
  while IFS= read -r f; do TARGETS+=("$f"); done < <(      # 2) PHP di folder data (selain index.php)
    find "$SRC_ROOT" -type f \( -iname '*.php' -o -iname '*.phtml' -o -iname '*.phar' \) \
      \( -path '*/uploads/*' -o -path '*/images/*' -o -path '*/cache/*' \) ! -name 'index.php' 2>/dev/null | head -200)
  while IFS= read -r f; do TARGETS+=("$f"); done < <(      # 3) error_log di inti WordPress
    find "$SRC_ROOT" -type f -name error_log \( -path '*/wp-admin/*' -o -path '*/wp-includes/*' \) 2>/dev/null)
  while IFS= read -r f; do TARGETS+=("$f"); done < <(      # 4) ekstensi ganda atau cadangan berisi PHP
    find "$SRC_ROOT" -type f -regextype posix-extended \
      -iregex '.*\.(map|js|css|json|txt|jpe?g|png|gif|ico|svg|webp|dat|log)\.(php|phtml|phar)|.*\.php\.(save|bak|old|gif|jpg|png|txt)' 2>/dev/null | head -200)
fi

ok=0; skip=0
for src in "${TARGETS[@]}"; do
  if [ -L "$src" ] || [ ! -e "$src" ]; then echo "[SKIP] $src (tidak ada atau symlink)"; skip=$((skip+1)); continue; fi
  if [ -d "$src" ]; then
    mapfile -d '' isi < <(find "$src" -type f -print0 2>/dev/null | head -z -n 300)
    [ ${#isi[@]} -gt 0 ] && simpan --label "dir:${src#$SRC_ROOT/}" -- "${isi[@]}" > /dev/null
  else
    simpan -- "$src" > /dev/null
  fi && { ok=$((ok+1)); echo "[OK] $src"; } || { skip=$((skip+1)); echo "[SKIP] $src (ditolak bukti.py)"; }
done

# ---- bukti database: akun siluman dan admin baru (hanya SELECT) ----
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

# ---- potongan log akses berpola IOC (paling banyak 200 MB) ----
zgrep -hE 'security-headers-manager|[?&]c=(id|whoami|echo)|GH_R0_EXEC|wpsvc_|/shell_[0-9]+\.php|blank\.php\?c=' /var/log/nginx/*access.log* 2>/dev/null \
  | head -c $((200*1024*1024)) > "$TMP"
[ -s "$TMP" ] && /usr/bin/python3 -I "$BUKTI" simpan-stdin --kasus "$KASUS" --label "log-ioc-nginx" < "$TMP" > /dev/null && echo "[OK] potongan log IOC"

echo "Selesai. OK=$ok SKIP=$skip  Kasus: $BUKTI_DIR/$KASUS (MANIFEST.tsv)"
