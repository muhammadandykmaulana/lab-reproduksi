#!/usr/bin/env bash
# db-integrity-cek.sh - pemantau integritas database aplikasi web (HANYA SELECT; yang ditulis hanya folder baseline)
# Rancangan: Skripsi Bab III bagian 3, Tabel 3.4 (enam pemeriksaan).
# Aplikasi yang dikenali otomatis dari struktur tabel: WordPress, OJS, SLiMS Senayan, EPrints.
#
# Pakai (root):
#   db-integrity-cek.sh --rebuild     buat baseline (jalankan saat situs dipastikan bersih)
#   db-integrity-cek.sh               pemeriksaan biasa (konten 1 hari terakhir)
#   db-integrity-cek.sh --days=7      pemeriksaan konten 7 hari terakhir
#   db-integrity-cek.sh --full        pemeriksaan seluruh konten (mis. tiap Sabtu)
#   db-integrity-cek.sh --accept      terima perubahan SAH (baseline lama diarsipkan)
# Keluaran: [ OK ] [WARN] [FAIL] [INFO]. Kode keluar 1 bila ada FAIL. Kirim ke Telegram lewat notify-run.sh.
# Berkas pendukung (opsional):
#   /var/opt/script/known_admins.txt   satu per baris: namadb:login
#   /var/opt/db-integrity/trusted_ips.txt   rentang IP tepercaya (CIDR), satu per baris
# Koneksi: root lewat unix socket. Bila perlu sandi, isi /root/.my.cnf atau DB_DEFAULTS=/path/berkas.cnf
set -uo pipefail
export LC_ALL=C

[ -f /etc/web-integrity.env ] && . /etc/web-integrity.env
BASE=${DBI_BASE:-/var/opt/db-integrity}
KNOWN=${KNOWN_ADMINS:-/var/opt/script/known_admins.txt}
TRUSTED=${TRUSTED_IPS:-$BASE/trusted_ips.txt}
MODE=check; DAYS=1
for a in "$@"; do
  case "$a" in
    --rebuild) MODE=rebuild;; --accept) MODE=accept;; --full) DAYS=0;;
    --days=*) DAYS=${a#--days=};;
    -h|--help) sed -n '2,17p' "$0"; exit 0;;
    *) echo "opsi tidak dikenal: $a"; exit 2;;
  esac
done
[ "$(id -u)" -eq 0 ] || [ -n "${DB_DEFAULTS:-}" ] || { echo "Jalankan sebagai root (atau set DB_DEFAULTS)."; exit 2; }
MYSQL=$(command -v mariadb || command -v mysql) || { echo "[FAIL] klien mariadb/mysql tidak ada"; exit 2; }
MYOPT=(); [ -n "${DB_DEFAULTS:-}" ] && MYOPT=(--defaults-extra-file="$DB_DEFAULTS")
q() { "$MYSQL" "${MYOPT[@]}" -N -B "$1" -e "$2" 2>/dev/null; }
q0() { "$MYSQL" "${MYOPT[@]}" -N -B -e "$1" 2>/dev/null; }

NF=0; NW=0
ok()   { echo "[ OK ] $*"; }
warn() { echo "[WARN] $*"; NW=$((NW+1)); }
fail() { echo "[FAIL] $*"; NF=$((NF+1)); }
info() { echo "[INFO] $*"; }

q0 "SELECT 1" >/dev/null || { echo "[FAIL] tidak bisa terhubung ke MariaDB sebagai $(id -un)"; exit 2; }
mkdir -p "$BASE"; chmod 700 "$BASE"
NOW=$(mktemp -d /run/dbi.XXXXXX 2>/dev/null || mktemp -d); trap 'rm -rf "$NOW"' EXIT

# Pola konten judi dan injeksi JavaScript (REGEXP MariaDB, tidak peka huruf besar)
POLA='slot ?gacor|judi ?online|togel|maxwin|mahjong ?ways|mahyong|rtp ?live|situs ?slot|scatter ?hitam|bandar ?(slot|togel)|eval\\(atob|string\\.fromcharcode\\(|<iframe[^>]{0,200}(display: ?none|width=.?0)'
TGL=""; [ "$DAYS" != "0" ] && TGL="$DAYS"

# Prefiks IP: IPv4 per /24, IPv6 per /64
prefix() { case "$1" in *:*) echo "$1" | awk -F: '{printf "%s:%s:%s:%s::/64\n",$1,$2,$3,$4}';; *.*.*.*) echo "${1%.*}.0/24";; *) echo "$1";; esac; }
trusted() {  # 0 bila IP masuk rentang tepercaya
  [ -s "$TRUSTED" ] || return 1
  python3 -I - "$1" "$TRUSTED" <<'PY' 2>/dev/null
import ipaddress, sys
ip = ipaddress.ip_address(sys.argv[1])
for line in open(sys.argv[2]):
    line = line.split("#")[0].strip()
    if line:
        try:
            if ip in ipaddress.ip_network(line, strict=False):
                sys.exit(0)
        except ValueError:
            pass
sys.exit(1)
PY
}

# ------------------------------------------------------------------ kenali aplikasi per database
q0 "SELECT table_schema, table_name FROM information_schema.tables
    WHERE table_schema NOT IN ('mysql','information_schema','performance_schema','sys')" > "$NOW/tables"
apps=()   # baris: db|jenis|prefiks
while read -r db; do
  t=$(awk -v d="$db" '$1==d{print $2}' "$NOW/tables")
  for p in $(echo "$t" | sed -n 's/^\(.*\)usermeta$/\1/p'); do
    echo "$t" | grep -qx "${p}users" && echo "$t" | grep -qx "${p}options" && apps+=("$db|wp|$p")
  done
  echo "$t" | grep -qx users && echo "$t" | grep -qx user_user_groups && echo "$t" | grep -qx user_groups && apps+=("$db|ojs|")
  echo "$t" | grep -qx user && echo "$t" | grep -qx biblio && apps+=("$db|slims|")
  echo "$t" | grep -qx user && echo "$t" | grep -qx eprint && apps+=("$db|eprints|")
done < <(awk '{print $1}' "$NOW/tables" | sort -u)
[ ${#apps[@]} -gt 0 ] || { info "tidak ada database WordPress/OJS/SLiMS/EPrints yang dikenali"; }

# ------------------------------------------------------------------ kumpulkan keadaan sekarang
# berkas per aplikasi: KEY.admins (login<TAB>surel<TAB>sha256(hash sandi)), KEY.opts, KEY.ips (login<TAB>prefiks)
for a in "${apps[@]}"; do
  IFS='|' read -r db kind p <<< "$a"; key="${db}__${kind}${p:+__$p}"
  case "$kind" in
    wp)
      q "$db" "SELECT u.user_login, u.user_email, SHA2(u.user_pass,256) FROM \`${p}users\` u
               JOIN \`${p}usermeta\` m ON m.user_id=u.ID AND m.meta_key='${p}capabilities'
               WHERE m.meta_value LIKE '%administrator%' ORDER BY 1" > "$NOW/$key.admins"
      q "$db" "SELECT option_name, IF(option_name='active_plugins', SHA2(option_value,256), option_value) FROM \`${p}options\`
               WHERE option_name IN ('siteurl','home','default_role','users_can_register','active_plugins') ORDER BY 1" > "$NOW/$key.opts"
      q "$db" "SELECT u.user_login, m.meta_value FROM \`${p}users\` u JOIN \`${p}usermeta\` m ON m.user_id=u.ID
               AND m.meta_key='session_tokens' JOIN \`${p}usermeta\` c ON c.user_id=u.ID AND c.meta_key='${p}capabilities'
               AND c.meta_value LIKE '%administrator%'" \
        | while IFS=$'\t' read -r login val; do
            echo "$val" | grep -oE '"ip";s:[0-9]+:"[^"]+"' | sed -E 's/.*:"([^"]+)"/\1/' | sort -u | sed "s/^/$login\t/"
          done > "$NOW/$key.ips";;
    ojs)
      q "$db" "SELECT u.username, u.email, SHA2(u.password,256) FROM users u
               JOIN user_user_groups uug ON uug.user_id=u.user_id JOIN user_groups ug ON ug.user_group_id=uug.user_group_id
               WHERE ug.role_id IN (1,16) GROUP BY u.user_id, u.username, u.email, u.password ORDER BY 1" > "$NOW/$key.admins"
      : > "$NOW/$key.opts"
      q "$db" "SELECT DISTINCT u.username, s.ip_address FROM sessions s JOIN users u ON u.user_id=s.user_id
               WHERE s.user_id IN (SELECT uug.user_id FROM user_user_groups uug JOIN user_groups ug
               ON ug.user_group_id=uug.user_group_id WHERE ug.role_id IN (1,16))" > "$NOW/$key.ips" \
        || info "$db (OJS): kolom sessions tidak cocok dengan versi ini, pemeriksaan sesi dilewati";;
    slims)
      q "$db" "SELECT username, IFNULL(email,''), SHA2(passwd,256) FROM user
               WHERE user_id=1 OR \`groups\` LIKE '%\"1\"%' ORDER BY 1" > "$NOW/$key.admins" \
        || info "$db (SLiMS): kolom user tidak cocok, pemeriksaan admin dilewati"
      : > "$NOW/$key.opts"
      q "$db" "SELECT username, last_login_ip FROM user WHERE (user_id=1 OR \`groups\` LIKE '%\"1\"%')
               AND last_login_ip IS NOT NULL AND last_login_ip<>''" > "$NOW/$key.ips" \
        || info "$db (SLiMS): last_login_ip tidak ada pada versi ini";;
    eprints)
      q "$db" "SELECT username, IFNULL(email,''), SHA2(IFNULL(password,''),256) FROM user WHERE usertype='admin' ORDER BY 1" > "$NOW/$key.admins" \
        || info "$db (EPrints): kolom user tidak cocok, pemeriksaan admin dilewati"
      : > "$NOW/$key.opts"
      q "$db" "SELECT DISTINCT u.username, l.ip FROM loginticket l JOIN user u ON u.userid=l.userid
               WHERE u.usertype='admin' AND l.expires > UNIX_TIMESTAMP()" > "$NOW/$key.ips" \
        || info "$db (EPrints): tabel loginticket tidak cocok, pemeriksaan sesi dilewati";;
  esac
  touch "$NOW/$key.admins" "$NOW/$key.opts" "$NOW/$key.ips"
done

# ------------------------------------------------------------------ mode rebuild / accept
if [ "$MODE" != check ]; then
  if [ "$MODE" = accept ] && ls "$BASE"/*.admins >/dev/null 2>&1; then
    arsip="$BASE/arsip-$(date +%Y%m%d-%H%M%S)"; mkdir -p "$arsip"; cp -a "$BASE"/*.admins "$BASE"/*.opts "$BASE"/*.ips "$arsip"/ 2>/dev/null
    ls -dt "$BASE"/arsip-* 2>/dev/null | tail -n +7 | while read -r d; do mv "$d" "$d.lama"; done   # 6 arsip terakhir dipertahankan
  fi
  for f in "$NOW"/*.admins "$NOW"/*.opts "$NOW"/*.ips; do [ -e "$f" ] && install -m 600 "$f" "$BASE/"; done
  # IP sesi yang sekarang terlihat dicatat sebagai prefiks yang sudah dikenal
  for f in "$NOW"/*.ips; do [ -e "$f" ] || continue
    while IFS=$'\t' read -r login ip; do [ -n "$ip" ] && printf '%s\t%s\n' "$login" "$(prefix "$ip")"; done < "$f" | sort -u > "$BASE/$(basename "$f").prefix"
    chmod 600 "$BASE/$(basename "$f").prefix"
  done
  echo "[ OK ] baseline database ${MODE}: ${#apps[@]} aplikasi -> $BASE"; exit 0
fi
ls "$BASE"/*.admins >/dev/null 2>&1 || { echo "[FAIL] baseline database belum ada. Jalankan: $0 --rebuild saat situs bersih."; exit 1; }

echo "== db-integrity-cek $(hostname) $(date '+%F %T') | ${#apps[@]} aplikasi | konten: $([ "$DAYS" = 0 ] && echo seluruhnya || echo "$DAYS hari terakhir") =="
for a in "${apps[@]}"; do
  IFS='|' read -r db kind p <<< "$a"; key="${db}__${kind}${p:+__$p}"
  echo "-- $db ($kind${p:+, prefiks $p})"
  berubah=""   # login yang surel/sandinya berubah (dipakai menaikkan sesi IP baru jadi FAIL)
  if [ ! -f "$BASE/$key.admins" ]; then
    warn "$db: aplikasi baru, belum ada di baseline (jalankan --accept bila sah)"
  else
    # 1. akun admin dibanding baseline
    join -t $'\t' -a1 -a2 -e '-' -o 0,1.2,1.3,2.2,2.3 <(sort "$BASE/$key.admins") <(sort "$NOW/$key.admins") > "$NOW/j"
    while IFS=$'\t' read -r login e0 h0 e1 h1; do
      if [ "$e0" = "-" ] && [ "$h0" = "-" ]; then fail "$db: ADMIN BARU '$login' <$e1> (tidak ada di baseline)"
      elif [ "$e1" = "-" ] && [ "$h1" = "-" ]; then fail "$db: admin '$login' HILANG dari daftar admin"
      else
        [ "$e0" != "$e1" ] && { fail "$db: SUREL admin '$login' berubah: $e0 -> $e1"; berubah+=" $login "; }
        [ "$h0" != "$h1" ] && { fail "$db: PASSWORD admin '$login' berubah sejak baseline"; berubah+=" $login "; }
      fi
    done < "$NOW/j"
    if [ "$kind" = wp ]; then
      while IFS=$'\t' read -r n v0 v1; do
        [ "$v0" = "$v1" ] && continue
        warn "$db: opsi WordPress '$n' berubah: ${v0:0:60} -> ${v1:0:60}"
      done < <(join -t $'\t' -a1 -a2 -e '-' -o 0,1.2,2.2 <(sort "$BASE/$key.opts") <(sort "$NOW/$key.opts"))
      grep -qxF "$(printf 'default_role\tadministrator')" "$NOW/$key.opts" && fail "$db: default_role = administrator (pendaftar baru otomatis jadi admin)"
    fi
  fi
  # 2. admin yang tidak ada di known_admins.txt
  if [ -s "$KNOWN" ]; then
    while IFS=$'\t' read -r login _ _; do
      grep -qxF "$db:$login" "$KNOWN" || fail "$db: admin '$login' tidak terdaftar di $(basename "$KNOWN")"
    done < "$NOW/$key.admins"
  fi
  # 3. sesi admin dari IP baru
  while IFS=$'\t' read -r login ip; do
    [ -n "$ip" ] || continue
    pf=$(prefix "$ip")
    grep -qxF "$(printf '%s\t%s' "$login" "$pf")" "$BASE/$key.ips.prefix" 2>/dev/null && continue
    trusted "$ip" && continue
    case "$berubah" in *" $login "*) fail "$db: sesi admin '$login' dari IP BARU $ip ($pf) DAN surel/sandinya berubah";;
                     *) warn "$db: sesi admin '$login' dari IP baru $ip ($pf)";; esac
  done < "$NOW/$key.ips"
  # 4. akun penanda serangan
  case "$kind" in
    wp) q "$db" "SELECT user_login, user_email FROM \`${p}users\` WHERE user_email LIKE '%.internal' OR user_login LIKE 'wpsvc%' OR user_login LIKE 'svc\\_%'";;
    slims) q "$db" "SELECT username, IFNULL(email,'') FROM user WHERE email LIKE '%.internal' OR username LIKE 'wpsvc%' OR username LIKE 'svc\\_%'";;
    eprints) q "$db" "SELECT username, IFNULL(email,'') FROM user WHERE email LIKE '%.internal' OR username LIKE 'wpsvc%' OR username LIKE 'svc\\_%'";;
    ojs) q "$db" "SELECT username, email FROM users WHERE email LIKE '%.internal'";;
  esac | while IFS=$'\t' read -r login em; do [ -n "$login" ] && echo "[FAIL] $db: AKUN PENANDA SERANGAN '$login' <$em>"; done | tee -a "$NOW/fail4"
  # 5. konten judi / injeksi JavaScript
  case "$kind" in
    wp)
      w=""; [ -n "$TGL" ] && w="AND post_modified >= NOW() - INTERVAL $TGL DAY"
      q "$db" "SELECT ID, post_type, LEFT(REPLACE(post_title,'\t',' '),60) FROM \`${p}posts\`
               WHERE post_status IN ('publish','draft','private','future') $w AND (post_content REGEXP '$POLA' OR post_title REGEXP '$POLA')
               LIMIT 20" | while IFS=$'\t' read -r id t ti; do echo "[FAIL] $db: KONTEN JUDI/INJEKSI pada $t #$id \"$ti\""; done | tee -a "$NOW/fail5"
      q "$db" "SELECT option_name FROM \`${p}options\` WHERE option_name NOT LIKE '\\_%transient%' AND option_value REGEXP '$POLA' LIMIT 20" \
        | while read -r n; do echo "[WARN] $db: opsi '$n' memuat pola judi/injeksi"; done | tee -a "$NOW/warn5";;
    slims)
      w=""; [ -n "$TGL" ] && w="AND last_update >= NOW() - INTERVAL $TGL DAY"
      q "$db" "SELECT biblio_id, LEFT(title,60) FROM biblio WHERE (title REGEXP '$POLA' OR IFNULL(notes,'') REGEXP '$POLA') $w LIMIT 20" \
        | while IFS=$'\t' read -r id ti; do echo "[FAIL] $db: KONTEN JUDI pada biblio #$id \"$ti\""; done | tee -a "$NOW/fail5";;
  esac
done
NF=$((NF + $(cat "$NOW"/fail4 "$NOW"/fail5 2>/dev/null | grep -c '^\[FAIL\]')))
NW=$((NW + $(cat "$NOW"/warn5 2>/dev/null | grep -c '^\[WARN\]')))

# 6. akun dan hak MariaDB
echo "-- MariaDB"
while IFS=$'\t' read -r u h; do
  if [ -z "$u" ]; then fail "akun MariaDB ANONIM di host '$h'"; else fail "akun MariaDB '$u'@'%' (boleh masuk dari mana saja)"; fi
done < <(q0 "SELECT User, Host FROM mysql.user WHERE Host='%' OR User=''")
while IFS=$'\t' read -r u h f s; do
  warn "akun MariaDB '$u'@'$h' punya hak $( [ "$f" = Y ] && echo -n 'FILE ')$( [ "$s" = Y ] && echo -n 'SUPER')"
done < <(q0 "SELECT User, Host, File_priv, Super_priv FROM mysql.user WHERE (File_priv='Y' OR Super_priv='Y')
             AND User NOT IN ('root','mariadb.sys','mysql','debian-sys-maint')")
while IFS=$'\t' read -r u n; do warn "akun MariaDB '$u' menjangkau $n database (sebaiknya satu akun satu database)"; done \
  < <(q0 "SELECT User, COUNT(DISTINCT Db) FROM mysql.db WHERE User NOT IN ('root','mariadb.sys') GROUP BY User HAVING COUNT(DISTINCT Db) > 3")
for d in $(q0 "SHOW DATABASES" | grep -ixE 'dvwa|test|demo|testing|wordpress_test'); do warn "database sisa '$d' masih ada (hapus bila tidak dipakai)"; done

echo
echo "Ringkasan: FAIL=$NF WARN=$NW | baseline: $BASE"
[ "$NF" -eq 0 ] && [ "$NW" -eq 0 ] && ok "tidak ada temuan"
[ "$NF" -gt 0 ] && echo "Tindak lanjut: periksa akun di atas, lalu kumpulkan bukti: collect3_evidence.sh --auto. Terima perubahan sah dengan --accept."
exit $([ "$NF" -gt 0 ] && echo 1 || echo 0)
