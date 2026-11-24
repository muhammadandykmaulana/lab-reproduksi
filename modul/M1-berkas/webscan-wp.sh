#!/usr/bin/env bash
# webscan-wp.sh - pemindai khusus pola serangan WordPress yang kita alami (hanya membaca)
# Pakai: sudo bash webscan-wp.sh [-p /var/www/html] [-d HARI] [-o laporan.txt]
# Melengkapi webscan.sh. Cek:
#  1. Akun admin siluman (DB): email .internal, login wpsvc*, registrasi baru, admin tak dikenal
#  2. Plugin samaran: nama berakhiran hex acak, plugin 1 file php, plugin tidak aktif berisi php
#  3. Pola webshell token (hash_equals + $_GET/$_REQUEST, marker <<S>>, GH_R0_EXEC, SSInjection)
#  4. PHP di uploads/cache/images, mu-plugins tak dikenal, error_log di core
#  5. Izin: wp-config.php, folder yang dapat ditulis www-data di luar wp-content
#  6. Plugin/tema checksum (wp-cli) per situs
#  7. Opsi WP berbahaya: siteurl/home berubah, cron mencurigakan, active_plugins aneh

[ -f /etc/web-integrity.env ] && . /etc/web-integrity.env
PATH_SCAN="${WEBROOT:-/var/www/html}"; DAYS=""; OUT=""
while getopts "p:d:o:" o; do case $o in p) PATH_SCAN=$OPTARG;; d) DAYS=$OPTARG;; o) OUT=$OPTARG;; esac; done
[ -n "$OUT" ] && exec > >(tee "$OUT") 2>&1
TIME=(); [ -n "$DAYS" ] && TIME=( \( -mtime "-$DAYS" -o -ctime "-$DAYS" \) )
KNOWN_ADMINS_FILE="/var/opt/script/known_admins.txt"   # format: db:user_login (satu per baris), opsional

IOC_RE='0xNix Encrypted Code|SPLIT&ENCRYPTed|yoibre\.com|aHR0cHM6Ly95b2li|hash_equals[[:space:]]*\([^)]{0,80}\$_(GET|POST|REQUEST)|<<S>>|<<E>>|GH_R0_EXEC|SSInjection|wordpress-svc\.internal|wpsvc_[0-9a-f]{6,}|\[BLOCKED\]disable_functions|\[(SE|EX|PT|SY|PO|PN)\]'

echo "=== webscan-wp $(date '+%F %T') path=$PATH_SCAN ${DAYS:+hari=$DAYS} ==="

echo; echo "-- 1) Akun siluman / admin baru di database"
for db in $(mariadb -N -e "SHOW DATABASES" 2>/dev/null | grep -vE '^(information_schema|performance_schema|mysql|sys)$'); do
  for t in $(mariadb -N -e "SELECT table_name FROM information_schema.columns WHERE table_schema='$db' AND column_name='user_login' AND table_name LIKE '%users'" 2>/dev/null); do
    pre=${t%users}
    mariadb -N -e "SELECT CONCAT('  SUSPECT $db.$t: ',u.ID,' ',u.user_login,' ',u.user_email,' ',u.user_registered)
      FROM \`$db\`.\`$t\` u
      WHERE u.user_email LIKE '%.internal' OR u.user_login REGEXP '^(wpsvc|svc|support|wp-?admin[0-9]+|sysadmin)' OR u.user_registered >= DATE_SUB(NOW(), INTERVAL ${DAYS:-30} DAY)" 2>/dev/null
    # admin (capabilities berisi administrator) yang tidak ada di daftar dikenal
    mariadb -N -e "SELECT CONCAT('  ADMIN $db: ',u.user_login,' <',u.user_email,'> ',u.user_registered)
      FROM \`$db\`.\`$t\` u JOIN \`$db\`.\`${pre}usermeta\` m ON m.user_id=u.ID
      WHERE m.meta_key='${pre}capabilities' AND m.meta_value LIKE '%administrator%'" 2>/dev/null \
      | while read -r line; do
          login=$(echo "$line" | awk '{print $3}')
          if [ -f "$KNOWN_ADMINS_FILE" ] && grep -qx "$db:$login" "$KNOWN_ADMINS_FILE"; then continue; fi
          echo "$line"
        done
  done
done

echo; echo "-- 2) Plugin samaran"
find "$PATH_SCAN" -maxdepth 6 -type d -path '*/wp-content/plugins/*' -regextype posix-extended -regex '.*/plugins/[a-z0-9-]+-[0-9a-f]{6}$' 2>/dev/null | sed 's/^/  NAMA-ACAK-HEX: /'
for pd in $(find "$PATH_SCAN" -maxdepth 4 -type d -path '*/wp-content/plugins/*' 2>/dev/null); do
  n=$(find "$pd" -type f -name '*.php' 2>/dev/null | head -4 | wc -l)
  [ "$n" -eq 1 ] && echo "  PLUGIN-1-FILE-PHP: $pd"
done | head -60
# plugin yang headernya mengaku "WordPress.org Community" / author generik
grep -rlE '^\s*\*?\s*Author:\s*WordPress\.org Community' "$PATH_SCAN" --include=*.php 2>/dev/null | grep '/wp-content/plugins/' | sed 's/^/  AUTHOR-PALSU: /'

echo; echo "-- 3) Pola webshell token/marker"
find "$PATH_SCAN" -xdev -type f \( -iname '*.php' -o -iname '*.phtml' -o -iname '*.phar' -o -iname '*.inc' -o -iname '*.txt' \) "${TIME[@]}" -size -2M -print0 2>/dev/null \
  | xargs -0 -r grep -lE -Z -e "$IOC_RE" 2>/dev/null | tr '\0' '\n' | grep -v "${BUKTI_DIR:-/var/opt/bukti}" | sed 's/^/  IOC: /'

echo; echo "-- 4) PHP di uploads/cache/images, mu-plugins, error_log core"
find "$PATH_SCAN" -type f \( -iname '*.php' -o -iname '*.phtml' -o -iname '*.phar' -o -iname '*.php[0-9]' \) \
  \( -path '*/uploads/*' -o -path '*/images/*' -o -path '*/cache/*' -o -path '*/upgrade/*' -o -path '*/fonts/*' -o -path '*/languages/*' -o -path '*/files/*' -o -path '*/public/*' \) "${TIME[@]}" 2>/dev/null \
  | grep -vE '/(index\.php)$|\.l10n\.php$' | sed 's/^/  PHP-DI-FOLDER-DATA: /' | head -100
find "$PATH_SCAN" -maxdepth 4 -type d -name mu-plugins -path '*/wp-content/*' -exec find {} -maxdepth 1 -type f -name '*.php' \; 2>/dev/null | sed 's/^/  MU-PLUGIN: /'
find "$PATH_SCAN" -type f -name error_log \( -path '*/wp-admin/*' -o -path '*/wp-includes/*' \) 2>/dev/null | sed 's/^/  ERROR_LOG-CORE: /'
find "$PATH_SCAN" -maxdepth 3 -type f \( -name '.user.ini' -o -name '.htaccess' \) "${TIME[@]}" 2>/dev/null | xargs -r grep -lE 'auto_prepend_file|auto_append_file|AddHandler|SetHandler' 2>/dev/null | sed 's/^/  PREPEND-HANDLER: /'

echo; echo "-- 5) Izin"
for cfg in $(find "$PATH_SCAN" -maxdepth 2 -name wp-config.php 2>/dev/null); do
  stat -c '  WP-CONFIG %a %U:%G %n' "$cfg"
done | awk '{ if ($3 !~ /^(600|640|400|440)$/) print "  [LONGGAR]" $0; else print $0 }'
find "$PATH_SCAN" -maxdepth 2 -type d -user www-data ! -path '*/wp-content*' 2>/dev/null | sed 's/^/  DIR-DITULIS-WWWDATA: /' | head -40
find "$PATH_SCAN" -maxdepth 3 -type f -perm -o+w 2>/dev/null | sed 's/^/  WORLD-WRITABLE: /' | head -40

echo; echo "-- 6) Checksum core + plugin (wp-cli)"
if command -v wp >/dev/null; then
  for cfg in $(find "$PATH_SCAN" -maxdepth 2 -name wp-config.php 2>/dev/null); do
    d=$(dirname "$cfg"); echo "  [$d]"
    ( cd "$d" && sudo -u www-data wp core verify-checksums --skip-themes 2>&1 | grep -vE 'SERVER_NAME|license.txt|readme.html|^Success' | sed 's/^/    /' )
    ( cd "$d" && sudo -u www-data wp plugin verify-checksums --all --skip-themes 2>&1 | grep -E "doesn't verify|should not exist|Checksum does not match|was added" | grep -v SERVER_NAME | head -15 | sed 's/^/    /' )
  done
fi

echo; echo "-- 7) Opsi WP: siteurl/home, active_plugins, cron"
if command -v wp >/dev/null; then
  for cfg in $(find "$PATH_SCAN" -maxdepth 2 -name wp-config.php 2>/dev/null); do
    d=$(dirname "$cfg")
    ( cd "$d" && echo "  [$(basename "$d")] siteurl=$(sudo -u www-data wp option get siteurl --skip-themes 2>/dev/null) home=$(sudo -u www-data wp option get home --skip-themes 2>/dev/null)"
      sudo -u www-data wp cron event list --fields=hook,next_run_relative --format=csv --skip-themes 2>/dev/null | grep -viE 'wp_|woocommerce|action_scheduler|jetpack|elementor|rank_math|yoast|litespeed|updraft|backuply|googlesitekit|cmb2|wc_|revslider|post_views|learnpress|mailchimp|wpfront|visualizer|gtranslate|aiko|cm_|rocket' | head -10 | sed 's/^/    CRON-ASING: /' )
  done
fi
