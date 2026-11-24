#!/bin/bash
# tools/bg-survey.sh - survei lingkungan server untuk Bodyguard HITL. 100% READ-ONLY.
# Tidak mengubah file, firewall, layanan, maupun database. Token/password disamarkan otomatis.
# Jalankan sebagai root agar semua bagian terbaca; kirim keluarannya untuk penyesuaian adapter.
set -u

red() {
  python3 -c '
import re, sys
tok = re.compile(r"\d{6,12}:[A-Za-z0-9_-]{30,}")
kv = re.compile(r"(?i)((?:pass(?:word)?|pwd|token|secret|api[_-]?key|hmac|salt|chat_?id)[A-Za-z0-9_]*[\"\x27 ]*[:=][ \"\x27]*)[^ \"\x27;,)\r\n]+")
for line in sys.stdin:
    line = tok.sub("<TOKEN>", line)
    sys.stdout.write(kv.sub(lambda m: m.group(1) + "<DISAMARKAN>", line))
'
}
h() { printf '\n===== %s =====\n' "$*"; }

h "Sistem"
uname -srm; grep -E '^(PRETTY_NAME|VERSION_ID)=' /etc/os-release 2>/dev/null; uptime

h "Python (Bodyguard butuh >= 3.6, hanya stdlib)"
command -v python3 && python3 --version
python3 -c 'import sqlite3, ssl; print("sqlite", sqlite3.sqlite_version, "|", ssl.OPENSSL_VERSION)' 2>&1

h "Alat"
for c in sudo visudo ipset iptables ip6tables nft fail2ban-client nginx php mysql mariadb systemctl setfacl curl; do
  printf '%-16s %s\n' "$c" "$(command -v "$c" || echo '-')"
done
sudo -V 2>/dev/null | head -1; ipset --version 2>/dev/null; nginx -v 2>&1; mysql --version 2>/dev/null

h "Skrip kontrol yang sudah ada"
for n in web-integrity-cek.sh kumpulkan-bukti.sh fw.sh notify-run.sh; do
  found=0
  while IFS= read -r f; do
    found=1
    echo "--- $f"; ls -la "$f"; echo "baris: $(wc -l < "$f")"; head -1 "$f"
    echo "[argumen/opsi]"; grep -nE 'getopts|case .*\$1|\$\{?[12]\}?|--[a-z][a-z-]+|[Uu]sage' "$f" | head -25 | red
    echo "[eval / sh -c / backtick: risiko injeksi bila menerima nama file]"; grep -nE '\beval\b|sh -c|bash -c|`' "$f" | head -10 | red
    echo "[tujuan output/log]"; grep -nE '(>>?|tee) *[^ ]*\.(log|txt|out|json)|LOG(_?FILE|_?DIR)?=|OUT(_?DIR)?=' "$f" | head -10 | red
  done < <(find / -xdev \( -path /proc -o -path /sys -o -path /var/www -o -path /var/lib/docker -o -path /var/lib/mysql \) -prune \
             -o -type f -name "$n" -print 2>/dev/null)
  [ "$found" = 1 ] || echo "--- $n: tidak ditemukan"
done

h "Cron yang memanggil skrip tersebut"
{ crontab -l 2>/dev/null; cat /etc/crontab /etc/cron.d/* 2>/dev/null; } | grep -E 'integrity|kumpulkan-bukti|fw\.sh|notify-run' | red

h "Nginx: log & real_ip"
nginx -T 2>/dev/null | grep -E '^\s*(access_log|log_format|real_ip_header|set_real_ip_from|real_ip_recursive)' | sed 's/^\s*//' | sort | uniq -c | head -40
ls -la /var/log/nginx/ 2>/dev/null | head -15

h "Contoh baris log akses (2 oktet terakhir IPv4 disamarkan)"
tail -3 /var/log/nginx/access.log 2>/dev/null | sed -E 's/^([0-9]+\.[0-9]+)\.[0-9]+\.[0-9]+/\1.x.x/' | cut -c1-220

h "Situs di /var/www/html"
ls -la /var/www/html 2>/dev/null

h "Kandidat folder data (mode pemilik path)"
find /var/www/html -maxdepth 5 -type d \( -name uploads -o -name fonts -o -name ijazah -o -name public -o -name files \) \
  -printf '%m %u:%g %p\n' 2>/dev/null | head -60

h "Symlink di bawah /var/www/html (maks 3 tingkat)"
find /var/www/html -maxdepth 3 -type l -printf '%p -> %l\n' 2>/dev/null | head -20

h "Jumlah file PHP di uploads WordPress"
for d in /var/www/html/*/wp-content/uploads; do
  [ -d "$d" ] && printf '%6d %s\n' "$(find "$d" -type f \( -iname '*.php*' -o -iname '*.phtml' -o -iname '*.phar' \) 2>/dev/null | wc -l)" "$d"
done

h "Plugin WordPress (nama folder) & mu-plugins"
for d in /var/www/html/*/wp-content/plugins; do [ -d "$d" ] && { echo "--- $d"; ls -1 "$d" | head -80; }; done
ls -la /var/www/html/*/wp-content/mu-plugins 2>/dev/null

h "WordPress: nama DB & prefix tabel (TANPA password)"
grep -HE "table_prefix|define\(\s*['\"]DB_NAME" /var/www/html/*/wp-config.php 2>/dev/null | red

h "OJS: lokasi files_dir & driver DB (TANPA rahasia)"
grep -HE '^\s*(files_dir|driver|name)\s*=' /var/www/html/*/config.inc.php 2>/dev/null | head -20 | red

h "User PHP-FPM"
grep -hE '^\s*(user|group)\s*=' /etc/php/*/fpm/pool.d/*.conf 2>/dev/null | sort | uniq -c

h "ipset / iptables (ringkas)"
ipset list -n 2>/dev/null
echo "jumlah aturan iptables: $(iptables -S 2>/dev/null | grep -c -- ' -j ')"
iptables -S 2>/dev/null | grep -- '--match-set' | head

h "fail2ban"
fail2ban-client status 2>/dev/null | head -5

h "sudoers.d (nama file saja) & user guard"
ls -la /etc/sudoers.d/ 2>/dev/null
id guard 2>/dev/null || echo "user guard belum ada"

h "Ruang disk"
df -h / /var /var/www 2>/dev/null | awk '!seen[$0]++'

h "Selesai - tidak ada yang diubah"
