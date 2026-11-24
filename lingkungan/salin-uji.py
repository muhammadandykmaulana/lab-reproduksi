#!/usr/bin/env python3
"""salin-uji.py - membuat dan menyinkronkan SITUS SALINAN untuk pengujian (berkas lewat rsync, database ditarik dari produksi).

Pakai (root):
  python3 salin-uji.py                     rencana: deteksi situs, ukuran, database, vhost. TIDAK mengubah apa pun
  python3 salin-uji.py salin               buat salinan (atau tarik ulang/sinkron bila sudah ada) untuk semua situs
  python3 salin-uji.py salin --hanya uji-jurnal.stai-ali.ac.id
  python3 salin-uji.py status              cek salinan yang sudah ada (HTTP lewat domain uji)
  python3 salin-uji.py hapus uji-jurnal.stai-ali.ac.id   hapus vhost, berkas, database, dan akun salinan itu
Opsi: --ip 203.0.113.7 (IP tambahan yang boleh mengakses salinan; IP_KANTOR dan IP_KANTOR_TETAP di /etc/web-integrity.env selalu diizinkan.
      Bila IP_KANTOR berubah (DDNS), ip-kantor-sync.sh ikut memperbarui /etc/nginx/conf.d/uji-izin.conf)

Yang dilakukan "salin" untuk tiap situs:
  1. rsync folder situs produksi -> /var/www/uji/<domain-uji>/ (di luar /var/www/html, supaya M1 tidak menganggapnya berkas baru)
  2. mysqldump database produksi (sebagai root lewat socket) -> database uji_<nama> dengan akun dan kata sandi sendiri
  3. menyesuaikan konfigurasi: kredensial database, alamat situs (WordPress/OJS), folder berkas OJS, jalur absolut
  4. mematikan email keluar (WordPress: mu-plugin; OJS: mailer log) supaya salinan tidak mengirim email ke pengguna sungguhan
  5. vhost Nginx dari blok server produksi: server_name/root diganti, hanya IP yang diizinkan (CF-Connecting-IP), noindex
  6. log salinan ditulis TERPISAH di /var/log/nginx/uji/ (format log sama dengan produksi), supaya lalu lintas uji tidak
     tercampur ke log produksi yang dianalisis ip-report, cf-guard, SOC-IR, dan metrik baseline/evaluasi
Produksi hanya DIBACA. Kata sandi akun salinan disimpan di /root/uji-salinan/<domain>.env (root 600) dan tidak dicetak.
"""
import os
import re
import secrets
import shlex
import shutil
import subprocess
import sys

SITUS = [  # (domain produksi, domain uji)
    ("stai-ali.ac.id", "uji.stai-ali.ac.id"),
    ("jurnal.stai-ali.ac.id", "uji-jurnal.stai-ali.ac.id"),
    ("library.stai-ali.ac.id", "uji-library.stai-ali.ac.id"),
]
TUJUAN = "/var/www/uji"
RAHASIA = "/root/uji-salinan"
WEBROOT = "/var/www/html"
NGX_AVAIL, NGX_EN = "/etc/nginx/sites-available", "/etc/nginx/sites-enabled"
NGX_IZIN = "/etc/nginx/conf.d/uji-izin.conf"
LOG_UJI = "/var/log/nginx/uji"
LOGROTATE_UJI = "/etc/logrotate.d/nginx-uji"


def sh(cmd, inp=None, cek=True):
    r = subprocess.run(cmd, shell=isinstance(cmd, str), input=inp, capture_output=True, text=True,
                       executable="/bin/bash" if isinstance(cmd, str) else None)
    if cek and r.returncode != 0:
        raise RuntimeError("perintah gagal: %s\n%s" % (cmd if isinstance(cmd, str) else " ".join(cmd), r.stderr.strip()[-800:]))
    return r.stdout


def sql(q, db=None):
    """perintah lewat stdin, supaya kata sandi tidak terlihat di daftar proses"""
    return sh(["mysql", "-N", "-B"] + ([db] if db else []), inp=q)


def info(m): print("  " + m)
def ok(m): print("  [ OK ] " + m)
def warn(m): print("  [WARN] " + m)


# ------------------------------------------------------------------ nginx
def nginx_berkas():
    """{path: isi} dari nginx -T"""
    out = sh("nginx -T 2>/dev/null", cek=False)
    berkas, cur = {}, None
    for line in out.splitlines(keepends=True):
        m = re.match(r"^# configuration file (.+):\s*$", line)
        if m:
            cur = m.group(1); berkas[cur] = ""; continue
        if cur:
            berkas[cur] += line
    return berkas


def blok_server(teks):
    """daftar (awal, akhir) blok 'server { ... }' tingkat atas di sebuah berkas"""
    hasil, i, n = [], 0, len(teks)
    while True:
        m = re.compile(r"(^|\n)\s*server\s*\{").search(teks, i)
        if not m:
            return hasil
        a = m.start() + (1 if m.group(1) else 0); j = m.end(); d = 1; q = None
        while j < n and d:
            c = teks[j]
            if q:
                if c == q and teks[j - 1] != "\\":
                    q = None
            elif c in "\"'":
                q = c
            elif c == "#":
                j = teks.find("\n", j); j = n if j < 0 else j; continue
            elif c == "{":
                d += 1
            elif c == "}":
                d -= 1
            j += 1
        hasil.append((a, j)); i = j


def nama_server(blok):
    s = set()
    for m in re.finditer(r"^\s*server_name\s+([^;]+);", blok, re.M):
        s.update(m.group(1).split())
    return s


def cari_vhost(domain):
    for path, teks in nginx_berkas().items():
        if not path.startswith("/etc/nginx/") or "/uji-" in path:
            continue
        bl = [teks[a:b] for a, b in blok_server(teks) if domain in nama_server(teks[a:b])]
        if bl:
            return path, bl
    return None, []


def ganti_domain(teks, src, dst):
    return re.sub(r"(?<![\w.-])(?:www\.)?" + re.escape(src) + r"(?![\w-])", dst, teks)


def vhost_uji(blok_list, src, dst, src_dir, dst_dir):
    out = []
    for b in blok_list:
        b = re.sub(r"^(\s*)server_name\s+[^;]+;", lambda m: "%sserver_name %s;\n%s# salinan uji: hanya IP yang diizinkan, tidak diindeks mesin pencari\n"
                   "%sif ($uji_boleh = 0) { return 403; }\n%sadd_header X-Robots-Tag \"noindex, nofollow\" always;"
                   % (m.group(1), dst, m.group(1), m.group(1), m.group(1)), b, count=1, flags=re.M)
        b = b.replace(src_dir, dst_dir)
        b = "".join(l if re.match(r"\s*ssl_", l) else ganti_domain(l, src, dst) for l in b.splitlines(keepends=True))
        b = re.sub(r"\s+default_server", "", b)
        b = re.sub(r"(^\s*(?:access|error)_log\s+)(/\S+?)(;|\s)", lambda m: m.group(1) + "%s/%s_%s.log" % (
            LOG_UJI, dst, "access" if "access" in m.group(1) else "error") + m.group(3), b, flags=re.M)
        for jenis in ("access", "error"):  # vhost tanpa direktif log: tetap ditulis terpisah
            if not re.search(r"^\s*%s_log\s" % jenis, b, re.M):
                b = re.sub(r"^(\s*)(server_name [^;]+;)", lambda m: "%s%s\n%s%s_log %s/%s_%s.log;" % (
                    m.group(1), m.group(2), m.group(1), jenis, LOG_UJI, dst, jenis), b, count=1, flags=re.M)
        out.append(b)
    return "# dibuat oleh salin-uji.py dari vhost %s - JANGAN disunting manual, jalankan ulang salin-uji.py\n\n" % src + "\n\n".join(out) + "\n"


def tulis_izin(ips):
    baris = "\n".join("    %s 1;" % ip for ip in ips)
    isi = ("# dibuat oleh salin-uji.py: IP yang boleh membuka situs salinan uji-*.\n"
           "map $http_cf_connecting_ip $uji_boleh {\n    default 0;\n%s\n}\n" % baris)
    open(NGX_IZIN, "w").write(isi)


# ------------------------------------------------------------------ aplikasi
def rx_define(teks, nama):
    m = re.search(r"define\(\s*['\"]%s['\"]\s*,\s*['\"]([^'\"]*)['\"]" % nama, teks)
    return m.group(1) if m else None


def set_define(teks, nama, nilai):
    pola = r"(define\(\s*['\"]%s['\"]\s*,\s*)(['\"])[^'\"]*\2" % nama
    if re.search(pola, teks):
        return re.sub(pola, lambda m: m.group(1) + "'" + nilai + "'", teks, count=1)
    return teks


def rx_larik(teks, kunci):
    m = re.search(r"['\"]%s['\"]\s*=>\s*['\"]([^'\"]*)['\"]" % kunci, teks)
    return m.group(1) if m else None


def set_larik(teks, kunci, nilai):
    return re.sub(r"(['\"]%s['\"]\s*=>\s*)(['\"])[^'\"]*\2" % kunci, lambda m: m.group(1) + "'" + nilai + "'", teks, count=1)


def ini_baca(teks, bagian, kunci):
    cur = None
    for line in teks.splitlines():
        m = re.match(r"^\s*\[([^\]]+)\]", line)
        if m:
            cur = m.group(1).strip(); continue
        if cur == bagian:
            m = re.match(r"^\s*%s\s*=\s*\"?([^\"\r\n]*)\"?" % re.escape(kunci), line)
            if m:
                return m.group(1).strip()
    return None


def ini_tulis(teks, bagian, kunci, nilai):
    out, cur, done = [], None, False
    for line in teks.splitlines(keepends=True):
        m = re.match(r"^\s*\[([^\]]+)\]", line)
        if m:
            cur = m.group(1).strip()
        elif cur == bagian and not done and re.match(r"^\s*%s\s*=" % re.escape(kunci), line):
            eol = "\r\n" if line.endswith("\r\n") else "\n"
            line = '%s = "%s"%s' % (kunci, nilai, eol) if '"' in line else "%s = %s%s" % (kunci, nilai, eol); done = True
        out.append(line)
    return "".join(out)


def kenali(site_dir):
    if os.path.isfile(os.path.join(site_dir, "wp-config.php")):
        t = open(os.path.join(site_dir, "wp-config.php"), errors="replace").read()
        m = re.search(r"\$table_prefix\s*=\s*['\"]([^'\"]+)['\"]", t)
        return {"app": "WordPress", "conf": "wp-config.php", "db": rx_define(t, "DB_NAME"), "prefix": m.group(1) if m else "wp_"}
    if os.path.isfile(os.path.join(site_dir, "config.inc.php")):
        t = open(os.path.join(site_dir, "config.inc.php"), errors="replace").read()
        return {"app": "OJS", "conf": "config.inc.php", "db": ini_baca(t, "database", "name"), "files_dir": ini_baca(t, "files", "files_dir")}
    p = os.path.join(site_dir, "config", "database.php")  # SLiMS 9: return ['nodes' => ['SLiMS' => ['database' => ...]]]
    if os.path.isfile(p):
        t = open(p, errors="replace").read()
        if rx_larik(t, "database"):
            return {"app": "SLiMS", "conf": "config/database.php", "db": rx_larik(t, "database"), "gaya": "larik"}
    for rel in ("config/sysconfig.local.inc.php", "sysconfig.local.inc.php"):  # SLiMS lama: define('DB_NAME', ...)
        p = os.path.join(site_dir, rel)
        if os.path.isfile(p):
            t = open(p, errors="replace").read()
            return {"app": "SLiMS", "conf": rel, "db": rx_define(t, "DB_NAME"), "gaya": "define"}
    return {"app": "?", "conf": None, "db": None}


def ukuran(p):
    try:
        return int(sh(["du", "-sb", p]).split()[0])
    except Exception:
        return 0


def gb(n): return "%.1f GB" % (n / 1e9)


def rencana_situs(src, dst):
    path, bl = cari_vhost(src)
    if not bl:
        return {"src": src, "dst": dst, "galat": "vhost untuk %s tidak ditemukan di nginx -T" % src}
    roots = [m.group(1) for b in bl for m in re.finditer(r"^\s*root\s+([^;]+);", b, re.M)]
    if not roots:
        return {"src": src, "dst": dst, "galat": "vhost %s tidak punya root" % src}
    root = roots[0].strip()
    if not root.startswith(WEBROOT + "/"):
        return {"src": src, "dst": dst, "galat": "root %s di luar %s (sesuaikan manual)" % (root, WEBROOT)}
    site_dir = os.path.join(WEBROOT, root[len(WEBROOT) + 1:].split("/")[0])
    k = kenali(site_dir)
    if k["app"] == "?":
        k = kenali(root)
    if k["app"] == "?":
        cand = sh("find %s -maxdepth 3 -name '*.php' \\( -name 'database.php' -o -name 'sysconfig*' -o -name 'config*.php' \\) "
                  "-not -path '*/vendor/*' 2>/dev/null | head -5" % shlex.quote(site_dir), cek=False).split()
        return {"src": src, "dst": dst, "galat": "aplikasi di %s tidak dikenali. Kandidat berkas konfigurasi: %s" % (site_dir, ", ".join(cand) or "-")}
    r = {"src": src, "dst": dst, "vhost": path, "blok": bl, "root": root, "site_dir": site_dir,
         "dst_dir": os.path.join(TUJUAN, dst), "ukuran": ukuran(site_dir), **k}
    if k.get("files_dir"):
        r["files_ukuran"] = ukuran(k["files_dir"])
        r["files_dst"] = os.path.join(TUJUAN, dst + "-files")
    r["db_uji"] = ("uji_" + re.sub(r"\W", "_", k["db"] or "x"))[:60]
    r["akun_uji"] = ("uji_" + (re.sub(r"\W", "_", re.sub(r"^uji[-_]?", "", dst.split(".")[0])) or "utama"))[:30]
    return r


def ips_izin(tambahan):
    ips = []
    try:
        for line in open("/etc/web-integrity.env"):
            m = re.match(r"^\s*(?:export\s+)?IP_KANTOR(?:_TETAP)?\s*=\s*\"?([^\"\n]*)", line)  # hasil sinkron + IP tetap
            if m:
                ips += m.group(1).split()
    except OSError:
        pass
    ips += tambahan
    return [ip for ip in dict.fromkeys(ips) if re.fullmatch(r"[0-9a-fA-F:.]+(/\d+)?", ip)]


# ------------------------------------------------------------------ eksekusi
def kata_sandi(dst):
    os.makedirs(RAHASIA, mode=0o700, exist_ok=True)
    f = os.path.join(RAHASIA, dst + ".env")
    if os.path.isfile(f):
        for line in open(f):
            if line.startswith("DB_PASSWORD="):
                return line.split("=", 1)[1].strip()
    pw = secrets.token_hex(20)
    fd = os.open(f, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    os.write(fd, ("DB_PASSWORD=%s\n" % pw).encode()); os.close(fd)
    return pw


def salin(r):
    print("\n== %s  ->  %s (%s)" % (r["src"], r["dst"], r["app"]))
    os.makedirs(TUJUAN, mode=0o755, exist_ok=True)
    # 1. berkas
    sh(["rsync", "-aHAX", "--delete", "--exclude=wp-content/cache/", r["site_dir"] + "/", r["dst_dir"] + "/"])
    ok("berkas disalin (rsync) ke %s" % r["dst_dir"])
    if r.get("files_dir"):
        sh(["rsync", "-aHAX", "--delete", r["files_dir"].rstrip("/") + "/", r["files_dst"] + "/"])
        ok("folder berkas OJS disalin ke %s" % r["files_dst"])
    # 2. database
    if not r["db"]:
        raise RuntimeError("nama database tidak terbaca dari %s" % r["conf"])
    pw = kata_sandi(r["dst"]); db, u = r["db_uji"], r["akun_uji"]
    sql("DROP DATABASE IF EXISTS `%s`; CREATE DATABASE `%s` CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci; "
        "CREATE USER IF NOT EXISTS '%s'@'localhost' IDENTIFIED BY '%s'; ALTER USER '%s'@'localhost' IDENTIFIED BY '%s'; "
        "GRANT ALL PRIVILEGES ON `%s`.* TO '%s'@'localhost';" % (db, db, u, pw, u, pw, db, u))
    sh("set -o pipefail; mysqldump --single-transaction --routines --triggers --events --default-character-set=utf8mb4 '%s' | mysql '%s'" % (r["db"], db))
    jml = sql("SELECT COUNT(*) FROM information_schema.TABLES WHERE TABLE_SCHEMA='%s'" % db).strip()
    ok("database %s ditarik ke %s (%s tabel)" % (r["db"], db, jml))
    # 3. konfigurasi
    url = "https://" + r["dst"]
    cf = os.path.join(r["dst_dir"], r["conf"])
    t = open(cf, newline="", errors="replace").read()
    if r["app"] == "WordPress":
        for k_, v in (("DB_NAME", db), ("DB_USER", u), ("DB_PASSWORD", pw), ("DB_HOST", "localhost")):
            t = set_define(t, k_, v)
        t = re.sub(r"^\s*define\(\s*['\"]WP_(HOME|SITEURL)['\"].*\n", "", t, flags=re.M)
        t = t.replace("<?php", "<?php\n/* salinan uji (salin-uji.py) */\ndefine('WP_HOME', '%s');\ndefine('WP_SITEURL', '%s');" % (url, url), 1)
        p = r["prefix"]
        sql("UPDATE `%soptions` SET option_value='%s' WHERE option_name IN ('siteurl','home')" % (p, url), db)
        mu = os.path.join(r["dst_dir"], "wp-content", "mu-plugins")
        os.makedirs(mu, exist_ok=True)
        open(os.path.join(mu, "uji-tanpa-email.php"), "w").write(
            "<?php\n/* salinan uji: semua email keluar dibatalkan (salin-uji.py) */\nadd_filter('pre_wp_mail', '__return_false');\n")
    elif r["app"] == "OJS":
        for k_, v in (("host", "localhost"), ("username", u), ("password", pw), ("name", db)):
            t = ini_tulis(t, "database", k_, v)
        t = ganti_domain(t, r["src"], r["dst"])
        if r.get("files_dst"):
            t = ini_tulis(t, "files", "files_dir", r["files_dst"])
        if ini_baca(t, "email", "default") is not None:
            t = ini_tulis(t, "email", "default", "log")
        for sub in ("cache/t_compile", "cache/fc-locale", "cache/_db"):
            shutil.rmtree(os.path.join(r["dst_dir"], sub), ignore_errors=True)
        for f in os.listdir(os.path.join(r["dst_dir"], "cache")) if os.path.isdir(os.path.join(r["dst_dir"], "cache")) else []:
            if f.endswith(".php"):
                os.remove(os.path.join(r["dst_dir"], "cache", f))
    elif r["app"] == "SLiMS" and r.get("gaya") == "larik":
        for k_, v in (("database", db), ("username", u), ("password", pw), ("host", "localhost")):
            t = set_larik(t, k_, v)
    elif r["app"] == "SLiMS":
        for k_, v in (("DB_NAME", db), ("DB_USERNAME", u), ("DB_PASSWORD", pw), ("DB_HOST", "localhost")):
            t = set_define(t, k_, v)
    open(cf, "w", newline="").write(t)
    # jalur absolut ke folder produksi (Wordfence, cache plugin, .user.ini) diarahkan ke salinan
    for rel in (".user.ini", "wordfence-waf.php", "wp-content/advanced-cache.php", "wp-content/wp-cache-config.php", ".htaccess", r["conf"]):
        p = os.path.join(r["dst_dir"], rel)
        if os.path.isfile(p):
            s = open(p, newline="", errors="replace").read()
            if r["site_dir"] in s:
                open(p, "w", newline="").write(s.replace(r["site_dir"], r["dst_dir"])); info("jalur produksi diganti di %s" % rel)
    ok("konfigurasi %s disesuaikan (database, alamat %s, email keluar dimatikan)" % (r["conf"], url))
    # 4. vhost
    isi = vhost_uji(r["blok"], r["src"], r["dst"], r["site_dir"], r["dst_dir"])
    fa = os.path.join(NGX_AVAIL, "uji-" + r["dst"]); fe = os.path.join(NGX_EN, "uji-" + r["dst"])
    open(fa, "w").write(isi)
    if not os.path.islink(fe):
        os.symlink(fa, fe)
    ok("vhost %s" % fa)


def siapkan_log():
    """folder log salinan + logrotate sendiri (logrotate bawaan hanya memutar /var/log/nginx/*.log)"""
    os.makedirs(LOG_UJI, mode=0o750, exist_ok=True)
    if not os.path.isfile(LOGROTATE_UJI):
        open(LOGROTATE_UJI, "w").write(
            "# dibuat oleh salin-uji.py: log situs salinan uji\n%s/*.log {\n    daily\n    rotate 60\n    missingok\n    notifempty\n"
            "    compress\n    delaycompress\n    create 0640 www-data adm\n    sharedscripts\n    postrotate\n"
            "        [ -s /run/nginx.pid ] && kill -USR1 $(cat /run/nginx.pid)\n    endscript\n}\n" % LOG_UJI)
    ok("log salinan: %s (logrotate: %s)" % (LOG_UJI, LOGROTATE_UJI))


def uji_nginx():
    r = subprocess.run(["nginx", "-t"], capture_output=True, text=True)
    return r.returncode == 0, r.stderr.strip()


def status(rs):
    for r in rs:
        if "galat" in r:
            continue
        c = subprocess.run(["curl", "-sk", "-o", "/dev/null", "-w", "%{http_code}", "-m", "20", "https://%s/?c=%d" % (r["dst"], secrets.randbelow(99999))],
                           capture_output=True, text=True).stdout
        ada = os.path.isdir(r["dst_dir"])
        info("%-28s salinan %-5s HTTP %s %s" % (r["dst"], "ada" if ada else "BELUM", c,
             "(403 = IP Anda tidak diizinkan, itu benar bila dicek dari server)" if c == "403" else ""))


def hapus(dst):
    r = next((x for x in rencana_semua() if x["dst"] == dst), None)
    if not r or "galat" in r:
        sys.exit("domain uji tidak dikenal: %s" % dst)
    for f in (os.path.join(NGX_EN, "uji-" + dst), os.path.join(NGX_AVAIL, "uji-" + dst)):
        if os.path.lexists(f):
            os.remove(f)
    sh(["systemctl", "reload", "nginx"], cek=False)
    for p in (r["dst_dir"], r.get("files_dst")):
        if p and p.startswith(TUJUAN + "/") and os.path.isdir(p):
            shutil.rmtree(p)
    sql("DROP DATABASE IF EXISTS `%s`; DROP USER IF EXISTS '%s'@'localhost';" % (r["db_uji"], r["akun_uji"]))
    f = os.path.join(RAHASIA, dst + ".env")
    if os.path.isfile(f):
        os.remove(f)
    ok("salinan %s dihapus (vhost, berkas, database, akun)" % dst)


def rencana_semua(hanya=None):
    return [rencana_situs(s, d) for s, d in SITUS if not hanya or d == hanya]


def main():
    if os.geteuid() != 0:
        sys.exit("Jalankan sebagai root.")
    a = sys.argv[1:]
    mode = a[0] if a and not a[0].startswith("--") else "rencana"
    hanya = a[a.index("--hanya") + 1] if "--hanya" in a else None
    tambahan = [a[i + 1] for i, x in enumerate(a) if x == "--ip" and i + 1 < len(a)]
    if mode == "hapus":
        return hapus(a[1])
    rs = rencana_semua(hanya)
    if mode == "status":
        return status(rs)
    print("== Rencana salinan uji (produksi hanya dibaca) ==")
    total = 0
    for r in rs:
        if "galat" in r:
            warn("%s: %s" % (r["src"], r["galat"])); continue
        total += r["ukuran"] + r.get("files_ukuran", 0)
        print("\n  %s  ->  %s" % (r["src"], r["dst"]))
        info("aplikasi      : %s (%s)" % (r["app"], r["conf"]))
        info("folder        : %s (%s)  ->  %s" % (r["site_dir"], gb(r["ukuran"]), r["dst_dir"]))
        if r.get("files_dir"):
            info("berkas OJS    : %s (%s)  ->  %s" % (r["files_dir"], gb(r["files_ukuran"]), r["files_dst"]))
        info("database      : %s  ->  %s (akun %s)" % (r["db"], r["db_uji"], r["akun_uji"]))
        info("vhost sumber  : %s (%d blok server)" % (r["vhost"], len(r["blok"])))
        info("log salinan   : %s/%s_access.log (terpisah dari log produksi)" % (LOG_UJI, r["dst"]))
    bebas = shutil.disk_usage(TUJUAN if os.path.isdir(TUJUAN) else "/var/www").free
    print()
    info("butuh sekitar %s, ruang kosong %s" % (gb(total), gb(bebas)))
    ips = ips_izin(tambahan)
    info("IP yang boleh membuka salinan: %s" % (", ".join(ips) if ips else "BELUM ADA (isi IP_KANTOR atau pakai --ip)"))
    if mode != "salin":
        print("\nBelum ada yang diubah. Jalankan: python3 %s salin" % sys.argv[0]); return
    if total * 1.2 > bebas:
        sys.exit("Ruang disk tidak cukup.")
    if not ips:
        warn("tanpa IP yang diizinkan, salinan akan selalu menjawab 403")
    tulis_izin(ips)
    siapkan_log()
    gagal = []
    for r in rs:
        if "galat" in r:
            continue
        try:
            salin(r)
        except Exception as e:
            gagal.append(r["dst"]); warn("%s GAGAL: %s" % (r["dst"], e))
    lulus, pesan = uji_nginx()
    if not lulus:
        for _, d in SITUS:
            f = os.path.join(NGX_EN, "uji-" + d)
            if os.path.islink(f):
                os.remove(f)
        sys.exit("nginx -t GAGAL, vhost uji dilepas lagi (produksi tidak terganggu):\n" + pesan)
    sh(["systemctl", "reload", "nginx"])
    ok("nginx -t lulus dan dimuat ulang")
    print()
    status(rs)
    if gagal:
        sys.exit("Ada salinan yang gagal: " + ", ".join(gagal))


if __name__ == "__main__":
    main()
