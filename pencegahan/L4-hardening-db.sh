#!/usr/bin/env bash
# L4-hardening-db.sh - hardening MariaDB lapisan L4: cabut hak GLOBAL (*.*) akun aplikasi; hak per-database TETAP.
# Bertahap dan bisa dibatalkan. Tidak mencetak password maupun hash password.
#   bash L4-hardening-db.sh [cek]              lihat rencana saja (hanya membaca, tidak mengubah apa pun)
#   bash L4-hardening-db.sh uji user@host      ubah SATU akun dulu, lalu cek semua situs
#   bash L4-hardening-db.sh pasang             ubah semua akun pada rencana (harus ketik YA)
#   bash L4-hardening-db.sh kunci user@host    kunci akun yang tidak dipakai (ACCOUNT LOCK; bisa dibuka lagi)
#   bash L4-hardening-db.sh buka  user@host    buka kunci akun
#   bash L4-hardening-db.sh batal              kembalikan perubahan uji/pasang terakhir
#   bash L4-hardening-db.sh cek-situs          cek semua situs saja
# Berkas kerja (root 700): /root/hardening-db/  -> grants-*.sql (cadangan), *.sql (yang dijalankan), *.undo.sql
set -uo pipefail
export LC_ALL=C
[ "$(id -u)" -eq 0 ] || { echo "Jalankan sebagai root (sudo)."; exit 1; }
DIR=/root/hardening-db; mkdir -p "$DIR"; chmod 700 "$DIR"; umask 077
TS=$(date +%F-%H%M%S)
SISTEM="'root','mysql.sys','mariadb.sys','mysql.session','mysql.infoschema','debian-sys-maint'"
q() { mysql -N -B -r -e "$1"; }
AKUN_SQL="SELECT CONCAT('''',User,'''@''',Host,'''') FROM mysql.user"

norm() {  # user@host atau 'user'@'host' -> 'user'@'host'
  local a=$1
  if [[ $a =~ ^\'[^\']+\'@\'[^\']+\'$ ]]; then echo "$a"; return 0; fi
  [[ $a == *@* ]] || { echo "Format akun: user@host, contoh wpuser@localhost" >&2; return 1; }
  echo "'${a%@*}'@'${a##*@}'"
}

rencana() {  # menulis $DIR/rencana.tsv: grantee, hak global, grant option, hak per-DB, dipakai di, aksi, db
  local akun glob sch dbs pakai kunci pola=$DIR/.pola
  akun=$(q "$AKUN_SQL WHERE User<>'' AND User NOT IN ($SISTEM) ORDER BY User,Host")
  glob=$(q "SELECT GRANTEE, IFNULL(GROUP_CONCAT(IF(PRIVILEGE_TYPE='USAGE',NULL,PRIVILEGE_TYPE) ORDER BY PRIVILEGE_TYPE SEPARATOR ', '),''), MAX(IS_GRANTABLE) FROM information_schema.USER_PRIVILEGES GROUP BY GRANTEE")
  sch=$(q "SELECT GRANTEE, GROUP_CONCAT(DISTINCT TABLE_SCHEMA ORDER BY TABLE_SCHEMA SEPARATOR ',') FROM information_schema.SCHEMA_PRIVILEGES GROUP BY GRANTEE")
  dbs=$(q "SELECT SCHEMA_NAME FROM information_schema.SCHEMATA")
  kunci=$(q "SELECT CONCAT('''',User,'''@''',Host,'''') FROM mysql.global_priv WHERE JSON_VALUE(Priv,'\$.account_locked')='true'" 2>/dev/null)
  # di mana nama akun dipakai: satu kali grep, hanya mencetak nama akun (bukan password)
  sed -E "s/^'(.*)'@'.*'$/\1/" <<<"$akun" | sort -u > "$pola"
  echo "Mencari pemakaian akun di konfigurasi (bisa 1-2 menit)..." >&2
  pakai=$( { grep -rsowF -f "$pola" /var/www /opt --include='*config*.php' --include='wp-config.php' --include='database.php' \
               --include='.env' --include='*.env' --include='*.pl' --include='*.ini'
             grep -rsowF -f "$pola" /etc /var/opt/script --include='*.sh' --include='*.py' --include='*.env' \
               --include='*.conf' --include='*.cnf' --include='*.ini' --include='*.pl'; } 2>/dev/null | sort -u)
  rm -f "$pola"
  : > "$DIR/rencana.tsv"
  local g u gp gr sc where aksi db
  while IFS= read -r g; do
    [ -n "$g" ] || continue
    u=${g#\'}; u=${u%%\'@*}
    gp=$(awk -F'\t' -v g="$g" '$1==g{print $2}' <<<"$glob")
    gr=$(awk -F'\t' -v g="$g" '$1==g{print $3}' <<<"$glob")
    sc=$(awk -F'\t' -v g="$g" '$1==g{print $2}' <<<"$sch")
    where=$(awk -F: -v u="$u" '$NF==u{print $1}' <<<"$pakai" | head -3 | paste -sd' ' -)
    db=""
    if [ -z "$gp" ] && [ "$gr" != YES ]; then aksi=aman
    elif [ -n "$sc" ]; then aksi=cabut
    elif grep -qxF -- "$u" <<<"$dbs"; then aksi=cabut+db; db=$u
    else aksi=lewati; fi
    grep -qxF -- "$g" <<<"$kunci" && where="(TERKUNCI) ${where}"
    printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\n' "$g" "${gp:--}" "${gr:-NO}" "${sc:--}" "${where:-TIDAK DITEMUKAN}" "$aksi" "${db:--}" >> "$DIR/rencana.tsv"
  done <<<"$akun"
}

tampil() {
  local g gp gr sc where aksi db
  echo; echo "== Akun aplikasi MariaDB =="
  while IFS=$'\t' read -r g gp gr sc where aksi db; do
    echo; echo "$g"
    echo "   hak global : $gp$([ "$gr" = YES ] && echo ' + GRANT OPTION')"
    echo "   hak per-DB : $sc"
    echo "   dipakai di : $where"
    case "$aksi" in
      aman)     echo "   rencana    : sudah aman (tidak punya hak global)";;
      cabut)    echo "   rencana    : CABUT hak global; hak per-DB tetap";;
      cabut+db) echo "   rencana    : GRANT ALL ON \`$db\`.* dulu (supaya situs tetap jalan), lalu CABUT hak global";;
      lewati)   echo "   rencana    : DILEWATI - tidak punya hak per-DB dan tidak ada DB bernama sama; tentukan manual";;
    esac
    case "$g" in *"@'localhost'"|*"@'127.0.0.1'"|*"@'::1'") ;;
      *) echo "   catatan    : host remote; sejak bind 127.0.0.1 akun ini tidak bisa dipakai -> kandidat kunci";; esac
    case "$where" in *"TIDAK DITEMUKAN"*) echo "   catatan    : nama akun tidak ditemukan di konfigurasi -> kandidat kunci (kunci dulu, jangan langsung hapus)";; esac
  done < "$DIR/rencana.tsv"
  echo; echo "== Pemeriksaan umum =="
  echo "   bind_address : $(q 'SELECT @@bind_address')"
  local an pc tdb
  an=$(q "$AKUN_SQL WHERE User=''" | paste -sd' ' -); echo "   akun anonim  : ${an:-tidak ada}${an:+ (dihapus saat pasang)}"
  pc=$(q "$AKUN_SQL WHERE Host='%'" | paste -sd' ' -); echo "   host '%'     : ${pc:-tidak ada}"
  tdb=$(q "SHOW DATABASES" | grep -xiE 'test|dvwa|demo' | paste -sd' ' -); echo "   DB uji       : ${tdb:-tidak ada}"
  echo; echo "Akun yang akan diubah saat 'pasang': $(awk -F'\t' '$6=="cabut"||$6=="cabut+db"' "$DIR/rencana.tsv" | wc -l)"
}

buat_sql() {  # $1 baris rencana, $2 berkas terapkan, $3 berkas undo
  local g gp gr sc where aksi db
  IFS=$'\t' read -r g gp gr sc where aksi db <<<"$1"
  case "$aksi" in cabut|cabut+db) ;; *) return 0;; esac
  if [ "$aksi" = cabut+db ]; then
    echo "GRANT ALL PRIVILEGES ON \`$db\`.* TO $g;" >> "$2"
    echo "REVOKE ALL PRIVILEGES ON \`$db\`.* FROM $g;" >> "$3"
  fi
  if [ "$gp" != - ]; then
    echo "REVOKE ALL PRIVILEGES ON *.* FROM $g;" >> "$2"
    echo "GRANT $gp ON *.* TO $g;" >> "$3"
  fi
  if [ "$gr" = YES ]; then
    echo "REVOKE GRANT OPTION ON *.* FROM $g;" >> "$2"
    echo "GRANT USAGE ON *.* TO $g WITH GRANT OPTION;" >> "$3"
  fi
}

cadangan() {  # SHOW GRANTS semua akun; berisi hash password, jadi hanya disimpan (root 600), tidak dicetak
  local out=$DIR/grants-$TS.sql g
  q "$AKUN_SQL" | while IFS= read -r g; do q "SHOW GRANTS FOR $g" 2>/dev/null | sed 's/$/;/'; done > "$out"
  echo "Cadangan hak akses: $out ($(wc -l < "$out") baris)"
}

jalankan() {  # $1 berkas sql
  local f=$1 undo=${1%.sql}.undo.sql
  [ -s "$f" ] || { echo "Tidak ada yang perlu diubah."; return 0; }
  cadangan
  echo "Perintah yang dijalankan:"; sed 's/^/   /' "$f"
  ln -sf "$undo" "$DIR/undo-terakhir.sql"
  if mysql < "$f"; then echo "[ OK ] sudah diubah. Kembalikan dengan: bash $0 batal"
  else echo "[FAIL] ada perintah yang gagal (perintah sebelumnya sudah berlaku). Kembalikan dengan: bash $0 batal"; return 1; fi
}

verifikasi() {
  local sisa
  sisa=$(q "SELECT DISTINCT GRANTEE FROM information_schema.USER_PRIVILEGES WHERE (PRIVILEGE_TYPE<>'USAGE' OR IS_GRANTABLE='YES') AND SUBSTRING_INDEX(SUBSTRING_INDEX(GRANTEE,'''',2),'''',-1) NOT IN ($SISTEM)")
  if [ -z "$sisa" ]; then echo "[ OK ] tidak ada lagi akun aplikasi yang punya hak global (termasuk FILE dan SUPER)"
  else echo "[WARN] masih punya hak global:"; sed 's/^/   /' <<<"$sisa"; fi
}

situs() {
  echo "== Cek situs (lewat domain asli, dengan query acak supaya tidak dari cache) =="
  local d c b bad=0
  for d in $(nginx -T 2>/dev/null | awk '/^[ \t]*server_name/{for(i=2;i<=NF;i++){gsub(/;/,"",$i); print $i}}' \
             | grep -E '^[a-z0-9.-]+\.[a-z]+$' | grep -v '^www\.' | sort -u); do
    b=$(mktemp); c=$(curl -sk -o "$b" -w '%{http_code}' -m 20 "https://$d/?hdb=$RANDOM" 2>/dev/null)
    if grep -qiE 'Error establishing a database connection|database connection (error|failed)|SQLSTATE|Access denied for user|DB Error' "$b"; then
      printf '  [FAIL] %-40s %s galat database\n' "$d" "$c"; bad=1
    elif [[ $c =~ ^[23] ]]; then printf '  [ OK ] %-40s %s\n' "$d" "$c"
    else printf '  [WARN] %-40s %s (bukan galat database; periksa manual)\n' "$d" "$c"; fi
    rm -f "$b"
  done
  [ $bad -eq 0 ] || echo "Ada galat database. Kembalikan dengan: bash $0 batal"
  return $bad
}

case "${1:-cek}" in
  cek) rencana; tampil;;
  uji)
    [ $# -ge 2 ] || { echo "Pakai: bash $0 uji user@host"; exit 1; }
    g=$(norm "$2") || exit 1
    rencana; baris=$(awk -F'\t' -v g="$g" '$1==g' "$DIR/rencana.tsv")
    [ -n "$baris" ] || { echo "Akun $g tidak ditemukan."; exit 1; }
    f=$DIR/uji-$TS.sql; : > "$f"; : > "${f%.sql}.undo.sql"
    buat_sql "$baris" "$f" "${f%.sql}.undo.sql"
    jalankan "$f" && { echo; situs; };;
  pasang)
    rencana; tampil; echo
    read -r -p "Ketik YA untuk mengubah semua akun bertanda CABUT di atas: " j
    [ "$j" = YA ] || { echo "Dibatalkan."; exit 0; }
    f=$DIR/pasang-$TS.sql; u=${f%.sql}.undo.sql; : > "$f"; : > "$u"
    while IFS= read -r b; do buat_sql "$b" "$f" "$u"; done < "$DIR/rencana.tsv"
    q "$AKUN_SQL WHERE User=''" | while IFS= read -r a; do
      [ -n "$a" ] && { echo "DROP USER $a;" >> "$f"; echo "CREATE USER $a;" >> "$u"; }; done
    jalankan "$f"; echo; verifikasi; echo; situs;;
  kunci|buka)
    [ $# -ge 2 ] || { echo "Pakai: bash $0 $1 user@host"; exit 1; }
    g=$(norm "$2") || exit 1; cadangan
    if [ "$1" = kunci ]; then mysql -e "ALTER USER $g ACCOUNT LOCK" && echo "[ OK ] $g dikunci. Buka lagi: bash $0 buka \"$2\""
    else mysql -e "ALTER USER $g ACCOUNT UNLOCK" && echo "[ OK ] $g dibuka."; fi;;
  batal)
    un=${2:-$DIR/undo-terakhir.sql}; [ -s "$un" ] || { echo "Tidak ada berkas undo."; exit 1; }
    echo "Mengembalikan dari $(readlink -f "$un")"; mysql --force < "$un"; echo; situs;;
  cek-situs) situs;;
  *) sed -n '2,11p' "$0"; exit 2;;
esac
