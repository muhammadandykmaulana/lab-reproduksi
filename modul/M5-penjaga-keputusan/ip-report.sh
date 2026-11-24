#!/usr/bin/env bash
# ip-report.sh - laporan forensik berbasis IP dari log nginx + sesi OJS (hanya membaca)
# Pakai: sudo bash ip-report.sh [HARI=30] [--ip 1.2.3.4]
# Seksi 1-10: forensik mentah. Seksi 11: ANALISIS PERILAKU per IP (label, skor 0-100, alur serangan, akun yang dipakai).
# Keluaran: /root/ip-report-TANGGAL.txt + /root/ip-behavior-TANGGAL.csv (mode 600).
# Opsional: ABUSEIPDB_KEY di /etc/web-integrity.env untuk pengayaan skor IP
set -uo pipefail
umask 077
DAYS=30; ONEIP=""
while [ $# -gt 0 ]; do case "$1" in --ip) ONEIP=$2; shift 2;; [0-9]*) DAYS=$1; shift;; *) echo "argumen tidak dikenal: $1"; exit 2;; esac; done
[ "$(id -u)" -eq 0 ] || { echo "Jalankan dengan sudo."; exit 2; }
[ -f /etc/web-integrity.env ] && . /etc/web-integrity.env
LOGDIR=/var/log/nginx
OJS_DB="${OJS_DB:-ojs}"
SAFE=" ${IP_KANTOR:-} "                      # IP kantor dari /etc/web-integrity.env
OUT=/root/ip-report-$(date +%F).txt
SUS=$(mktemp); ABUSE_TSV=$(mktemp); trap 'rm -f "$SUS" "$ABUSE_TSV"' EXIT
exec > >(tee "$OUT") 2>&1
L() { zcat -f $LOGDIR/*access.log* 2>/dev/null; }     # semua log, termasuk .gz
echo "=== IP REPORT $(date '+%F %T') host=$(hostname) ==="
echo "Log tertua: $(ls -tr $LOGDIR/*access.log* 2>/dev/null | head -1)  (retensi menentukan sejauh mana pelaku bisa dilacak)"

echo; echo "== 1. Siapa yang meminta path IOC (shell, loader, file kita karantina)"
L | grep -E 'asbarin|shell\.(gif|php|phtml)|/404\.php|zs\.txt|/sz\.php|wp-upgrade\.php|/tools\.php|/logs\.php|/setup\.php|autoloads\.php|feed-rss\.php|\.php\.save|sxc=|ijazah_17(54893|73839)|6a12658becbf2' \
 | awk '{print $1, $4, $6, $7, $9}' | tr -d '[' | sort -k2 | tee /tmp/ip1.$$ | head -100
awk '{print $1}' /tmp/ip1.$$ | sort -u >> "$SUS"; rm -f /tmp/ip1.$$

echo; echo "== 2. Brute-force login OJS (>=15 percobaan): IP, percobaan, respons 302 (login sukses/redirect)"
L | awk '/login\/signIn/ && $6=="\"POST"{n[$1]++; if($9==302)s[$1]++} END{for(i in n) if(n[i]>=15) print n[i], s[i]+0, i}' \
 | sort -rn | while read -r n s ip; do
     case "$SAFE" in *" $ip "*) continue;; esac
     echo "$ip percobaan=$n respons302=$s"; echo "$ip" >> "$SUS"; done

echo; echo "== 3. Unggahan ke OJS oleh IP non-kantor (temporaryFiles/saveStep/uploadFile)"
L | awk '$6=="\"POST" && $7 ~ /temporaryFiles|saveStep|uploadFile|fileUpload/ {print $1, $4, $7, $9}' | tr -d '[' \
 | awk -v s="$SAFE" '{ if (index(s," "$1" ")==0) print }' | sort -k2 | tail -60

echo; echo "== 4. Pemindai: IP yang memeriksa file sensitif (composer, .env, .git, wp-config, phpunit, xmlrpc, adminer)"
L | grep -E 'composer\.(json|lock)|phpunit|/\.env|/\.git/|wp-config|xmlrpc\.php|adminer|phpmyadmin|/vendor/' \
 | awk '{c[$1]++} END{for(i in c) print c[i], i}' | sort -rn | head -25 | tee /tmp/ip4.$$
awk '$1>=5{print $2}' /tmp/ip4.$$ >> "$SUS"; rm -f /tmp/ip4.$$

echo; echo "== 5. Akses ke /public/site/images/ dan /files/ (OJS) per IP + status"
L | grep -E 'GET /(public/site/images|files)/' | awk '{print $1, $4, $7, $9}' | tr -d '[' | sort -k2 | tail -40

echo; echo "== 6. Sesi OJS aktif: user, IP, aktivitas terakhir"
mysql -N -B "$OJS_DB" -e "SELECT s.user_id,u.username,s.ip_address,FROM_UNIXTIME(s.last_activity),LEFT(s.user_agent,50)
 FROM sessions s LEFT JOIN users u ON u.user_id=s.user_id WHERE s.user_id IS NOT NULL ORDER BY s.last_activity DESC LIMIT 40" 2>&1 | column -t -s$'\t'

echo; echo "== 7. Admin OJS: login terakhir (cocokkan dengan known_admins.txt)"
mysql -N -B "$OJS_DB" -e "SELECT DISTINCT u.user_id,u.username,u.email,u.date_registered,u.date_last_login,u.disabled
 FROM users u JOIN user_user_groups uug USING(user_id) JOIN user_groups ug USING(user_group_id) WHERE ug.role_id IN (1,16)" 2>&1 | column -t -s$'\t'

echo; echo "== 8. Top 20 IP penghasil 403/404 (indikasi probing)"
L | awk '$9==403||$9==404{c[$1]++} END{for(i in c) print c[i], i}' | sort -rn | head -20 | tee /tmp/ip8.$$
awk '$1>=200{print $2}' /tmp/ip8.$$ >> "$SUS"; rm -f /tmp/ip8.$$

# bersihkan daftar IP mencurigakan: buang IP kantor, IP Cloudflare/localhost
sort -u "$SUS" | grep -E '^[0-9a-fA-F:.]+$' | grep -vE '^(127\.|10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[01])\.)' \
 | while read -r ip; do case "$SAFE" in *" $ip "*) ;; *) echo "$ip";; esac; done > /root/ip-suspects-$(date +%F).txt
echo; echo "== 9. Daftar IP mencurigakan: $(wc -l < /root/ip-suspects-$(date +%F).txt) IP -> /root/ip-suspects-$(date +%F).txt"

if [ -n "${ABUSEIPDB_KEY:-}" ] && command -v jq >/dev/null; then
  echo; echo "== 10. AbuseIPDB (skor, negara, ISP, jumlah laporan)"
  printf "IP\tSKOR\tNEGARA\tISP\tLAPORAN\tTYPE\n"
  while read -r ip; do
    curl -s -m 15 -G https://api.abuseipdb.com/api/v2/check --data-urlencode "ipAddress=$ip" -d maxAgeInDays=365 \
      -H "Key: $ABUSEIPDB_KEY" -H "Accept: application/json" \
      | jq -r --arg ip "$ip" '[$ip,.data.abuseConfidenceScore,.data.countryCode,(.data.isp//"-"),.data.totalReports,(.data.usageType//"-")]|@tsv'
    sleep 1
  done < <(head -150 /root/ip-suspects-$(date +%F).txt) | sort -t$'\t' -k2 -rn | tee "$ABUSE_TSV"
else
  echo; echo "(AbuseIPDB dilewati: set ABUSEIPDB_KEY di /etc/web-integrity.env dan pasang jq)"
fi

echo; echo "== 11. ANALISIS PERILAKU per IP ($DAYS hari): label, skor, alur serangan, akun yang dipakai"
BEH_ARGS=(--days "$DAYS"); [ -n "$ONEIP" ] && BEH_ARGS+=(--ip "$ONEIP")
OJS_DB="$OJS_DB" IP_KANTOR="${IP_KANTOR:-}" ABUSE_TSV="$ABUSE_TSV" IPREPORT_EMBED=1 python3 -I - "${BEH_ARGS[@]}" <<'PYEOF'
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""ip-behavior.py - analisis PERILAKU per IP dari log nginx + akun yang dipakai (HANYA MEMBACA).

Melengkapi ip-report.sh: bukan sekadar "IP ini banyak 404", tetapi "IP ini melakukan apa, berurutan bagaimana,
memakai akun apa", lalu diberi label perilaku, skor 0-100, dan saran tindakan.

Pakai (root):  python3 /var/opt/script/tools/ip-behavior.py [--days 30] [--top 40] [--ip 1.2.3.4]
Keluaran: /root/ip-behavior-YYYY-MM-DD.txt (+ .csv), mode 600.

Sumber:
  * /var/log/nginx/*access.log* (termasuk .gz), format combined; nama situs dari nama file log.
  * Akun: sesi OJS (sessions.ip_address -> user), log Loginizer WordPress (*_loginizer_logs),
    opsi Limit Login Attempts (limit_login_logged: IP -> username yang dicoba).
  * Skor AbuseIPDB: dibaca dari laporan ip-report.sh terakhir (/root/ip-report-*.txt), tanpa memanggil API.
Tidak ada yang diubah: tidak memblokir, tidak menulis ke DB, tidak mengirim apa pun.
"""

import argparse
import collections
import csv
import glob
import gzip
import ipaddress
import os
import re
import subprocess
import sys
import time
from datetime import datetime, timedelta, timezone

LOG_GLOB = "/var/log/nginx/*access.log*"
LINE_RE = re.compile(r'^(?P<ip>[0-9A-Fa-f:.]{2,45}) \S+ \S+ \[(?P<t>[^\]]{20,32})\] "(?P<m>[A-Z]{1,12}) (?P<u>[^ "]{1,4096})'
                     r'(?: [^"]{0,24})?" (?P<s>\d{3}) \S+ "(?P<ref>[^"]*)" "(?P<ua>[^"]*)"')
SAFE_IPS = set(os.environ.get("IP_KANTOR", "").split())

# Kategori perilaku (urutan = tahapan serangan yang lazim)
CATS = collections.OrderedDict([
    ("RECON", re.compile(r"(?i)/\.env|/\.git/|wp-config|composer\.(?:json|lock)|phpunit|adminer|phpmyadmin|/vendor/|"
                         r"/\.aws|\.sql(?:\.gz)?$|\.bak$|backup|/cgi-bin/|/server-status|\.DS_Store|/actuator|/HNAP1|"
                         r"/boaform|/owa/|/\.well-known/security|wlwmanifest|/wp-json/wp/v2/users|\?author=\d")),
    ("EXPLOIT", re.compile(r"(?i)\.\./|%2e%2e|union(?:\s|%20|\+)+select|<script|%3cscript|\$\{jndi|/etc/passwd|"
                           r"base64_de|[?&](?:cmd|exec|command)=|wget(?:%20|\+)|curl(?:%20|\+)|php://|data:text")),
    ("LOGIN", None),     # POST wp-login.php / OJS login/signIn
    ("XMLRPC", None),    # POST xmlrpc.php
    ("UPLOAD", re.compile(r"(?i)temporaryFiles|saveStep|uploadFile|fileUpload|async-upload\.php|media-new\.php")),
    ("ADMIN", re.compile(r"(?i)/wp-admin/(?!admin-ajax\.php)|/management/|/index\.php/[^/]+/admin|/\$\$\$call\$\$\$")),
    ("PHP_DATA", re.compile(r"(?i)/(?:uploads|files|public|images|ijazah|fonts|cache)/[^?#]*\.(?:php[0-9]?|phtml|phar|pht)")),
    ("WEBSHELL", re.compile(r"(?i)asbarin|shell\.(?:gif|php|phtml)|/404\.php|zs\.txt|/sz\.php|wp-upgrade\.php|/tools\.php|"
                            r"/logs\.php|/setup\.php|autoloads\.php|feed-rss\.php|\.php\.save|sxc=|ijazah_17(?:54893|73839)|"
                            r"6a12658becbf2|security-headers-manager|287d723bf150786316df3ec9457cadb4|GH_R0_EXEC|wpsvc_|"
                            r"/shell_[0-9]+\.php|blank\.php\?c=|[?&]c=(?:id|whoami|echo)")),
])
UA_RESEARCH = re.compile(r"(?i)expanse|palo ?alto|censys|shodan|internet-measurement|criminalip|leakix|onyphe|netcraft")
UA_SCANNER = re.compile(r"(?i)zgrab|masscan|nuclei|sqlmap|nikto|nmap|httpx|python-requests|go-http-client|curl/|wget/|"
                        r"libwww|okhttp|aiohttp|scrapy|fuzz|dirbuster|gobuster|wpscan|feroxbuster")
UA_BOT = re.compile(r"(?i)googlebot|bingbot|yandex|baiduspider|duckduck|applebot|facebookexternalhit|semrush|ahrefs|"
                    r"mj12|petalbot|gptbot|claudebot|bytespider|dotbot|seznam")
MOBILE_ISP = re.compile(r"(?i)telkomsel|indosat|\bioh\b|xl axiata|smartfren|tri indonesia|hutchison|axis")
STAGE_LABEL = {"RECON": "recon", "EXPLOIT": "uji-injeksi", "LOGIN": "login", "XMLRPC": "xmlrpc", "UPLOAD": "unggah",
               "ADMIN": "panel-admin", "PHP_DATA": "akses-PHP-data", "WEBSHELL": "webshell"}


def clean(s, n=140):
    s = "".join(ch if 32 <= ord(ch) < 127 or ord(ch) > 159 else "\\x%02x" % ord(ch) for ch in str(s))
    return s if len(s) <= n else s[:n] + "..."


def open_log(path):
    return gzip.open(path, "rt", encoding="utf-8", errors="replace") if path.endswith(".gz") else \
        open(path, "r", encoding="utf-8", errors="replace")


def site_of(path):
    b = os.path.basename(path)
    m = re.match(r"(.+?)_access\.log", b)
    return m.group(1) if m else "default"


class Agg(object):
    __slots__ = ("n", "status", "cats", "cats_ok", "first", "last", "stage_first", "sites", "uas", "paths404",
                 "paths", "minutes", "post_login", "login_302", "php_data_post_ok", "webshell_ok", "methods")

    def __init__(self):
        self.n = 0
        self.status = collections.Counter()
        self.cats = collections.Counter()
        self.cats_ok = collections.Counter()
        self.first = self.last = None
        self.stage_first = {}
        self.sites = collections.Counter()
        self.uas = collections.Counter()
        self.paths404 = collections.Counter()
        self.paths = collections.Counter()
        self.minutes = collections.Counter()
        self.post_login = self.login_302 = self.php_data_post_ok = self.webshell_ok = 0
        self.methods = collections.Counter()


def classify(method, uri):
    hits = []
    for name, rx in CATS.items():
        if name == "LOGIN":
            if method == "POST" and re.search(r"(?i)wp-login\.php|login/signIn", uri):
                hits.append(name)
        elif name == "XMLRPC":
            if method == "POST" and "xmlrpc.php" in uri:
                hits.append(name)
        elif rx.search(uri):
            hits.append(name)
    return hits


def parse_logs(days, only_ip):
    cutoff = datetime.now(timezone.utc) - timedelta(days=days)
    data = collections.defaultdict(Agg)
    files = sorted(glob.glob(LOG_GLOB))
    bad = 0
    for path in files:
        site = site_of(path)
        try:
            fh = open_log(path)
        except OSError:
            continue
        with fh:
            for line in fh:
                m = LINE_RE.match(line)
                if not m:
                    bad += 1
                    continue
                ip = m.group("ip")
                if only_ip and ip != only_ip:
                    continue
                try:
                    t = datetime.strptime(m.group("t"), "%d/%b/%Y:%H:%M:%S %z")
                except ValueError:
                    continue
                if t < cutoff:
                    continue
                a = data[ip]
                method, uri, st, ua = m.group("m"), m.group("u")[:2048], int(m.group("s")), m.group("ua")
                ok = 200 <= st < 400
                a.n += 1
                a.status[st // 100 * 100] += 1
                a.methods[method] += 1
                a.sites[site] += 1
                a.uas[ua[:120]] += 1
                a.minutes[t.strftime("%Y%m%d%H%M")] += 1
                a.first = t if a.first is None or t < a.first else a.first
                a.last = t if a.last is None or t > a.last else a.last
                if st == 404:
                    a.paths404[uri.split("?", 1)[0][:160]] += 1
                for c in classify(method, uri):
                    a.cats[c] += 1
                    if ok:
                        a.cats_ok[c] += 1
                    if c not in a.stage_first or t < a.stage_first[c]:
                        a.stage_first[c] = t
                    if len(a.paths) < 400 or (c, uri[:160], st) in a.paths:
                        a.paths[(c, uri[:160], st)] += 1
                    if c == "LOGIN":
                        a.post_login += 1
                        if st == 302:
                            a.login_302 += 1
                    if c == "PHP_DATA" and ok and method == "POST":
                        a.php_data_post_ok += 1
                    if c == "WEBSHELL" and ok:
                        a.webshell_ok += 1
    return data, files, bad


def mysql(db, sql):
    try:
        p = subprocess.run(["mariadb", "-N", "-B", db, "-e", sql], stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                           timeout=60, universal_newlines=True)
    except (OSError, subprocess.TimeoutExpired):
        return []
    return [l.split("\t") for l in p.stdout.splitlines() if l] if p.returncode == 0 else []


def accounts_by_ip():
    acc = collections.defaultdict(set)
    for r in mysql(os.environ.get("OJS_DB", "ojs"), "SELECT s.ip_address, u.username, FROM_UNIXTIME(s.last_activity) FROM sessions s "
                                   "JOIN users u ON u.user_id=s.user_id WHERE s.user_id IS NOT NULL"):
        if len(r) >= 3:
            acc[r[0]].add(("OJS-sesi", r[1], r[2]))
    # database WordPress dikenali dari tabel *_usermeta (tidak bergantung awalan nama database; WP_DB_LIKE opsional)
    like = re.sub(r"[^A-Za-z0-9_%]", "", os.environ.get("WP_DB_LIKE", "%")) or "%"
    for db in [r[0] for r in mysql("information_schema", "SELECT DISTINCT table_schema FROM tables "
                                                         "WHERE table_name LIKE '%%\\_usermeta' AND table_schema LIKE '%s'" % like)]:
        for (t,) in [tuple(r[:1]) for r in mysql("information_schema", "SELECT table_name FROM tables WHERE table_schema='%s' "
                                                  "AND table_name LIKE '%%loginizer_logs'" % db)]:
            for r in mysql(db, "SELECT ip, username, status, FROM_UNIXTIME(time) FROM `%s` ORDER BY time DESC LIMIT 5000" % t):
                if len(r) >= 4:
                    acc[r[0]].add(("WP-%s" % db.split("wp_", 1)[-1],
                                   r[1], ("berhasil " if r[2] == "1" else "gagal ") + r[3]))
        for (t,) in [tuple(r[:1]) for r in mysql("information_schema", "SELECT table_name FROM tables WHERE table_schema='%s' "
                                                  "AND table_name LIKE '%%options'" % db)]:
            rows = mysql(db, "SELECT option_value FROM `%s` WHERE option_name='limit_login_logged'" % t)
            if rows:
                for ip, inner in re.findall(r's:\d+:"([0-9a-fA-F:.]+)";a:\d+:\{(.*?\})\}', rows[0][0]):
                    for user in re.findall(r's:\d+:"([^"]*)";a:', inner):
                        acc[ip].add(("WP-%s" % db.split("wp_", 1)[-1], user, "dicoba (limit-login)"))
    return acc


def abuse_info():
    files = [os.environ["ABUSE_TSV"]] if os.environ.get("ABUSE_TSV") else sorted(glob.glob("/root/ip-report-*.txt"))
    info = {}
    if files:
        with open(files[-1], encoding="utf-8", errors="replace") as f:
            for line in f:
                parts = line.rstrip("\n").split("\t")
                if len(parts) >= 6 and re.match(r"^[0-9A-Fa-f:.]+$", parts[0]) and parts[1].isdigit():
                    info[parts[0]] = {"score": int(parts[1]), "cc": parts[2], "isp": parts[3], "reports": parts[4],
                                      "type": parts[5]}
    return info, (files[-1] if files else None)


def cloudflare():
    nets = []
    for path in ("/etc/bodyguard/cloudflare-ips.txt",):
        if os.path.exists(path):
            for l in open(path):
                l = l.split("#")[0].strip()
                if l:
                    nets.append(ipaddress.ip_network(l, strict=False))
    if not nets:
        nets = [ipaddress.ip_network(n) for n in ("173.245.48.0/20", "103.21.244.0/22", "103.22.200.0/22", "103.31.4.0/22",
                "141.101.64.0/18", "108.162.192.0/18", "190.93.240.0/20", "188.114.96.0/20", "197.234.240.0/22",
                "198.41.128.0/17", "162.158.0.0/15", "104.16.0.0/13", "104.24.0.0/14", "172.64.0.0/13",
                "131.0.72.0/22", "2400:cb00::/32", "2606:4700::/32", "2803:f800::/32", "2405:b500::/32",
                "2405:8100::/32", "2a06:98c0::/29", "2c0f:f248::/32")]
    return nets


def judge(ip, a, ab, cf_nets, accounts):
    c = a.cats
    top_ua = a.uas.most_common(1)[0][0] if a.uas else ""
    ua_kind = ("riset" if UA_RESEARCH.search(top_ua) else "scanner" if UA_SCANNER.search(top_ua)
               else "bot" if UA_BOT.search(top_ua) else "browser")
    isp = (ab or {}).get("isp", "")
    if UA_RESEARCH.search(isp):
        ua_kind = "riset"
    n404 = sum(a.paths404.values())
    r404 = n404 / float(a.n) if a.n else 0
    d404 = len(a.paths404)
    peak = max(a.minutes.values()) if a.minutes else 0
    try:
        is_cf = any(ipaddress.ip_address(ip) in n for n in cf_nets)
    except ValueError:
        is_cf = False
    mobile = bool(MOBILE_ISP.search(isp)) or (ab or {}).get("type") == "Mobile ISP"

    if a.webshell_ok or a.php_data_post_ok:
        label = "EKSPLOITASI / WEBSHELL AKTIF"
    elif c["WEBSHELL"] or c["PHP_DATA"]:
        label = "PERCOBAAN WEBSHELL"
    elif a.post_login >= 15 or c["XMLRPC"] >= 20:
        label = "BRUTE FORCE LOGIN"
    elif c["UPLOAD"] and (c["RECON"] or c["EXPLOIT"]):
        label = "UNGGAHAN MENCURIGAKAN"
    elif c["EXPLOIT"] >= 3:
        label = "UJI INJEKSI / EXPLOIT"
    elif ua_kind == "riset":
        label = "SCANNER RISET (internet-wide)"
    elif c["RECON"] >= 5 or (r404 >= 0.6 and a.n >= 50 and d404 >= 20):
        label = "RECON / PROBING"
    elif ua_kind == "bot":
        label = "CRAWLER"
    elif r404 >= 0.5 and d404 <= 5 and a.n >= 50:
        label = "KLIEN BISING (aset hilang/aplikasi salah, bukan serangan)"
    else:
        label = "NORMAL"

    score = 0
    score += 50 if (a.webshell_ok or a.php_data_post_ok) else 0
    score += min(20, 5 * c["WEBSHELL"]) + min(15, 3 * c["PHP_DATA"])
    score += min(25, a.post_login // 4) + min(10, c["XMLRPC"] // 10)
    score += min(20, 2 * c["EXPLOIT"]) + min(15, c["RECON"]) + (10 if c["UPLOAD"] and label != "NORMAL" else 0)
    score += 5 if ua_kind == "scanner" else 0
    score += int((ab or {}).get("score", 0) * 0.15)
    if label.startswith("KLIEN BISING") or label in ("CRAWLER", "NORMAL"):
        score = min(score, 20)
    score = min(100, score)

    if ip in SAFE_IPS:
        advice = "IP kantor - abaikan"
    elif is_cf:
        advice = "IP Cloudflare: real_ip belum aktif di vhost ini, IP asli tidak terlihat"
    elif label.startswith("KLIEN BISING"):
        advice = "bukan serangan: cari path 404 yang berulang (aset/endpoint hilang)"
    elif score >= 60 and mobile:
        advice = "JANGAN blokir IP (CGNAT seluler, dipakai banyak orang); rate-limit/WAF rule pada path"
    elif score >= 60:
        advice = "blokir di Cloudflare (IP Access Rules) + periksa akun di bawah"
    elif label == "SCANNER RISET (internet-wide)":
        advice = "risiko rendah; boleh blokir ASN scanner di Cloudflare bila mengganggu"
    elif score >= 30:
        advice = "pantau; blokir di Cloudflare bila berulang"
    else:
        advice = "-"
    chain = " -> ".join("%s %s" % (STAGE_LABEL[k], v.astimezone(timezone(timedelta(hours=7))).strftime("%d/%m %H:%M"))
                        for k, v in sorted(a.stage_first.items(), key=lambda kv: kv[1]))
    return {"ip": ip, "label": label, "score": score, "ua_kind": ua_kind, "r404": r404, "d404": d404, "peak": peak,
            "chain": chain, "advice": advice, "mobile": mobile, "cf": is_cf, "accounts": sorted(accounts.get(ip, []))}


def fmt_t(t):
    return t.astimezone(timezone(timedelta(hours=7))).strftime("%Y-%m-%d %H:%M WIB") if t else "-"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--days", type=int, default=30)
    ap.add_argument("--top", type=int, default=40)
    ap.add_argument("--ip", help="analisis satu IP saja")
    ap.add_argument("--min-requests", type=int, default=20)
    args = ap.parse_args()
    if os.geteuid() != 0:
        sys.exit("Jalankan sebagai root (log nginx & DB).")
    os.umask(0o077)
    t0 = time.time()
    data, files, bad = parse_logs(args.days, args.ip)
    acc = accounts_by_ip()
    abuse, abuse_file = abuse_info()
    cf = cloudflare()
    results = []
    for ip, a in data.items():
        if a.n < args.min_requests and not (a.cats["WEBSHELL"] or a.cats["PHP_DATA"] or acc.get(ip)) and not args.ip:
            continue
        r = judge(ip, a, abuse.get(ip), cf, acc)
        r["agg"] = a
        results.append(r)
    results.sort(key=lambda r: (-r["score"], -r["agg"].n))

    out_txt = "/root/ip-behavior-%s.txt" % time.strftime("%F")
    embedded = bool(os.environ.get("ABUSE_TSV") is not None and os.environ.get("IPREPORT_EMBED"))
    lines = ["=== IP BEHAVIOR %s | %d hari | %d file log | %d baris tak terbaca | AbuseIPDB: %s ===" % (
        time.strftime("%F %T"), args.days, len(files), bad, abuse_file or "-")]
    labels = collections.Counter(r["label"] for r in results)
    lines.append("\n== Ringkasan label (IP >= %d request atau ber-IOC)" % args.min_requests)
    for k, v in labels.most_common():
        lines.append("  %4d  %s" % (v, k))

    lines.append("\n== Kartu perilaku (urut skor)")
    for r in results[:args.top]:
        a = r["agg"]
        ab = abuse.get(r["ip"], {})
        lines.append("\n[%3d] %-40s %s" % (r["score"], r["ip"], r["label"]))
        lines.append("      ISP: %s %s | AbuseIPDB %s (%s laporan) | klien: %s%s" % (
            ab.get("isp", "-"), ab.get("cc", ""), ab.get("score", "-"), ab.get("reports", "-"), r["ua_kind"],
            " | SELULER/CGNAT" if r["mobile"] else ""))
        lines.append("      aktif: %s s/d %s | %d req | puncak %d req/menit | 2xx %d 3xx %d 4xx %d 5xx %d" % (
            fmt_t(a.first), fmt_t(a.last), a.n, r["peak"], a.status[200], a.status[300], a.status[400], a.status[500]))
        lines.append("      situs: %s" % ", ".join("%s(%d)" % kv for kv in a.sites.most_common(4)))
        if a.cats:
            lines.append("      perilaku: %s" % ", ".join("%s %d (sukses %d)" % (STAGE_LABEL[k], v, a.cats_ok[k])
                                                        for k, v in a.cats.most_common()))
        if r["chain"]:
            lines.append("      alur: %s" % r["chain"])
        if a.post_login:
            lines.append("      login POST: %d, respons 302: %d" % (a.post_login, a.login_302))
        if a.paths404:
            lines.append("      404 teratas (%d path unik, %.0f%% dari request): %s" % (
                r["d404"], r["r404"] * 100, "; ".join("%s x%d" % (clean(p, 70), n) for p, n in a.paths404.most_common(3))))
        for (cat, uri, st), n in sorted(a.paths.items(), key=lambda kv: -kv[1])[:4]:
            lines.append("      contoh %-11s %3d x%-4d %s" % (STAGE_LABEL[cat], st, n, clean(uri, 100)))
        lines.append("      UA: %s" % clean(a.uas.most_common(1)[0][0], 110))
        for src, user, extra in r["accounts"][:8]:
            lines.append("      AKUN: [%s] %s - %s" % (src, clean(user, 40), extra))
        lines.append("      saran: %s" % r["advice"])

    by_user = collections.defaultdict(set)
    for ip, items in acc.items():
        for src, user, _ in items:
            by_user[(src, user)].add(ip)
    multi = sorted(((k, v) for k, v in by_user.items() if len(v) >= 3), key=lambda kv: -len(kv[1]))
    lines.append("\n== Akun yang dipakai/dicoba dari >= 3 IP (indikasi kredensial bocor atau target brute force)")
    for (src, user), ips in multi[:30]:
        lines.append("  [%s] %-30s %d IP: %s" % (src, clean(user, 30), len(ips), ", ".join(sorted(ips)[:6])))
    if not multi:
        lines.append("  (tidak ada)")
    lines.append("\nSelesai dalam %.1f detik. CSV: %s" % (time.time() - t0, out_txt[:-4] + ".csv"))

    if not embedded:
        with open(out_txt, "w", encoding="utf-8") as f:
            f.write("\n".join(lines) + "\n")
    with open(out_txt[:-4] + ".csv", "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["ip", "skor", "label", "request", "pertama", "terakhir", "recon", "injeksi", "login", "xmlrpc",
                    "unggah", "admin", "php_data", "webshell", "webshell_sukses", "rasio404", "isp", "abuse", "akun", "saran"])
        for r in results:
            a = r["agg"]
            w.writerow([r["ip"], r["score"], r["label"], a.n, fmt_t(a.first), fmt_t(a.last), a.cats["RECON"],
                        a.cats["EXPLOIT"], a.cats["LOGIN"], a.cats["XMLRPC"], a.cats["UPLOAD"], a.cats["ADMIN"],
                        a.cats["PHP_DATA"], a.cats["WEBSHELL"], a.webshell_ok, "%.2f" % r["r404"],
                        abuse.get(r["ip"], {}).get("isp", ""), abuse.get(r["ip"], {}).get("score", ""),
                        ";".join("%s:%s" % (s, u) for s, u, _ in r["accounts"]), r["advice"]])
    print("\n".join(lines))


if __name__ == "__main__":
    main()
PYEOF
echo; echo "Laporan: $OUT"
echo "Blokir yang terbukti jahat di Cloudflare (IP Access Rules), bukan ufw, karena trafik masuk lewat Cloudflare."
