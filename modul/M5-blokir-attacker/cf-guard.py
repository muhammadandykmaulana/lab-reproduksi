#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""cf-guard.py - pengelola rule Cloudflare "Auto-Block - Dinamis Hacker" (HANYA rule ini yang diubah).

Isi rule dikelola penuh oleh skrip:
    (not cf.client.bot and ip.src in $hacker)
    or (not cf.client.bot and http.request.uri.path in {"/path-1" "/path-2" ...})

Sumber bukti:
  * /root/ip-behavior-*.csv  (ip-report.sh seksi 11: skor, label, saran per IP)
  * log nginx /var/log/nginx/*access.log* (path yang di-probe IP jahat)
  * Cloudflare WAF events 24 jam (GraphQL firewallEventsAdaptive): IP yang terus ditolak rule 1-4
Keputusan:
  OTOMATIS  IP  : skor >= 100, saran "blokir di Cloudflare", bukan whitelist
            IP  : skor 80-99 DAN sudah ditolak WAF >= 5x dalam 24 jam
            PATH: di-probe >= 3 IP jahat berbeda, tidak pernah dijawab 2xx/3xx ke siapa pun,
                  belum tertangkap rule 1-4
  PERSETUJUAN (T2, lewat satu jalur persetujuan admin di SOC-IR: tombol ber-HMAC, nonce, berlaku 30 menit):
            IP skor 80-99 tanpa bukti WAF; PATH yang di-probe 2 IP jahat, atau pernah dijawab 2xx/3xx
  TIDAK PERNAH: IP seluler/CGNAT, Cloudflare, kantor, privat, admin-subnets, bot terverifikasi

Pemakaian (root):
  cf-guard.py run              DRY-RUN: tampilkan rencana, tidak mengubah apa pun
  cf-guard.py run --apply      terapkan otomatis + ajukan kasus ragu-ragu ke persetujuan admin (SOC-IR)
  cf-guard.py poll [--loop]    bot SOC (perintah /ringkas, /ip, /blok, ...); tidak memproses tombol persetujuan
  cf-guard.py block <ip> --ttl DETIK [--oleh X]   blokir T1 ber-TTL (dipanggil SOC-IR lewat bg-root cf-block)
  cf-guard.py approve <id> | reject <id>          eksekusi/tolak usulan (dipanggil SOC-IR lewat bg-root cf-approve setelah admin setuju)
  cf-guard.py status           entri aktif, pending, riwayat
  cf-guard.py rollback         kembalikan ekspresi rule ke versi sebelumnya
  cf-guard.py remove <ip|path> hapus satu entri (list + rule)
  cf-guard.py freeze           bekukan (FREEZE bersama /var/lib/freeze/FREEZE); cairkan HANYA lewat: freeze.sh off

Pengaman: dry-run default; maks 50 IP & 10 path baru per run (lebih = tidak ada yang diterapkan, alert);
nilai path divalidasi ketat (anti injeksi ekspresi); FREEZE bersama menghentikan semua perubahan; koneksi API CF lewat IPv4.
cf-guard adalah SATU-SATUNYA jalur blokir IP untuk trafik yang lewat Cloudflare (SOC-IR T1 juga memakai jalur ini).
Pesan Telegram dikirim lewat notify-run.sh --pesan (satu pengirim untuk semua modul).
Masa berlaku: blokir PERMANEN secara default. Entri tertua (buatan cg) baru dibuang bila kapasitas penuh:
  - list IP >= 95% dari CG_LIST_MAX (default 10000; sesuaikan dengan batas paket Cloudflare Anda)
  - ekspresi rule > 3800 karakter (path tertua dipangkas)
  Setiap pembuangan dicatat dan dilaporkan ke Telegram. Opsional TTL: CG_IP_TTL_DAYS / CG_PATH_TTL_DAYS (0 = permanen).

Konfigurasi /etc/bodyguard/cloudflare.env (root:root 600):
  CF_AUTH_TOKEN CF_ACCOUNT_ID CF_ZONE_ID CF_RULESET_ID CF_RULE_ID CF_AFTER_RULE CF_LIST_NAME=hacker
  CG_TG_TOKEN=<token bot SOC yang TIDAK di-poll proses lain>  CG_CHAT_ID=<id Telegram Anda>  CG_APPROVER_IDS=<id approver>
  CG_HMAC_KEY=<openssl rand -hex 32>  (kunci Attack ID, yaitu kode pendek IP)
  CG_GERBANG=<perintah untuk mengajukan persetujuan, bawaan: runuser -u guard -- /opt/bodyguard/bin/bodyguard propose cf>
  CG_VIEW_CHATS=<chat id grup SOC, boleh lebih dari satu dipisah koma> (boleh bertanya; blokir hanya CG_APPROVER_IDS)
"""

import argparse
import collections
import csv
import glob
import gzip
import hashlib
import hmac
import ipaddress
import json
import os
import re
import secrets
import shlex
import socket
import subprocess
import ssl
import stat
import sys
import time
import urllib.error
import urllib.request
from datetime import datetime, timedelta, timezone

ENV = "/etc/bodyguard/cloudflare.env"
STATE_DIR = "/var/lib/cf-guard"
STATE = STATE_DIR + "/state.json"
FREEZE = os.environ.get("FREEZE_FILE", "/var/lib/freeze/FREEZE")   # SATU FREEZE untuk semua modul
NOTIFY_RUN = os.environ.get("NOTIFY_RUN", os.path.join(os.path.dirname(os.path.abspath(__file__)), "notify-run.sh"))
GERBANG_BAWAAN = "runuser -u guard -- /opt/bodyguard/bin/bodyguard propose cf"
RID_RE = re.compile(r"\A[0-9a-f]{12}\Z")
LOG = "/var/log/cf-guard.log"
CF_API = "https://api.cloudflare.com/client/v4"
TG_API = "https://api.telegram.org"
TAG = "cg"
LIST_FULL_RATIO = 0.95      # mulai buang entri tertua bila list >= 95% kapasitas
MAX_NEW_IP, MAX_NEW_PATH = 50, 10
EXPR_MAX = 3800
APPROVAL_TTL = 1800          # TTL tombol di gerbang; usulan di state cf-guard sendiri kedaluwarsa setelah PENDING_TTL
PENDING_TTL = 86400
PATH_RE = re.compile(r"\A/[A-Za-z0-9._~/-]{1,120}\Z")
LINE_RE = re.compile(r'^(?P<ip>[0-9A-Fa-f:.]{2,45}) \S+ \S+ \[(?P<t>[^\]]{20,32})\] "(?P<m>[A-Z]{1,12}) (?P<u>[^ "]{1,4096})'
                     r'(?: [^"]{0,24})?" (?P<s>\d{3}) ')
OFFICE = []   # diisi dari CG_OFFICE_IPS di cloudflare.env (IP kantor, dipisah spasi)
PRIVATE = ("10.0.0.0/8 172.16.0.0/12 192.168.0.0/16 127.0.0.0/8 100.64.0.0/10 169.254.0.0/16 "
           "::1/128 fc00::/7 fe80::/10").split()
CF_DEFAULT = ("173.245.48.0/20 103.21.244.0/22 103.22.200.0/22 103.31.4.0/22 141.101.64.0/18 108.162.192.0/18 "
              "190.93.240.0/20 188.114.96.0/20 197.234.240.0/22 198.41.128.0/17 162.158.0.0/15 104.16.0.0/13 "
              "104.24.0.0/14 172.64.0.0/13 131.0.72.0/22 2400:cb00::/32 2606:4700::/32 2803:f800::/32 2405:b500::/32 "
              "2405:8100::/32 2a06:98c0::/29 2c0f:f248::/32").split()
# Path yang tidak boleh masuk rule walau di-probe (halaman sah umum)
NEVER_PATHS = {"/", "/index.php", "/wp-login.php", "/wp-admin/", "/robots.txt", "/favicon.ico", "/sitemap.xml",
               "/wp-json/", "/feed/", "/xmlrpc.php"}


# ---------------------------------------------------------------- util
def now():
    return time.time()


def day(ts=None):
    return time.strftime("%F", time.localtime(ts or now()))


def clean(s, n=120):
    s = "".join(ch if 32 <= ord(ch) < 127 else "?" for ch in str(s))
    return s if len(s) <= n else s[:n] + "..."


def log(msg):
    line = "%s %s" % (time.strftime("%F %T"), msg)
    print(line)
    try:
        with open(LOG, "a") as f:
            f.write(line + "\n")
        os.chmod(LOG, 0o600)
    except OSError:
        pass


def load_env():
    try:
        st = os.stat(ENV)
    except OSError:
        sys.exit("Belum ada %s." % ENV)
    if st.st_uid != 0 or stat.S_IMODE(st.st_mode) & 0o077:
        sys.exit("%s harus milik root dengan mode 600." % ENV)
    env = {}
    for line in open(ENV, encoding="utf-8"):
        m = re.match(r"^\s*([A-Z_]+)\s*=\s*\"?([^\"\n]*)\"?\s*$", line)
        if m:
            env[m.group(1)] = m.group(2).strip()
    miss = [k for k in ("CF_AUTH_TOKEN", "CF_ACCOUNT_ID", "CF_ZONE_ID", "CF_RULESET_ID", "CF_RULE_ID") if not env.get(k)]
    if miss:
        sys.exit("Kurang di %s: %s" % (ENV, ", ".join(miss)))
    env.setdefault("CF_LIST_NAME", "hacker")
    OFFICE[:] = [x if "/" in x else x + ("/128" if ":" in x else "/32") for x in env.get("CG_OFFICE_IPS", "").split()]
    return env


def load_state():
    try:
        with open(STATE) as f:
            s = json.load(f)
    except (OSError, ValueError):
        s = {}
    for k, v in (("ips", {}), ("paths", {}), ("pending", {}), ("history", []), ("tg_offset", 0), ("rejected", {})):
        s.setdefault(k, v)
    return s


def save_state(s):
    os.makedirs(STATE_DIR, mode=0o700, exist_ok=True)
    tmp = STATE + ".tmp"
    with open(tmp, "w") as f:
        json.dump(s, f, indent=1, sort_keys=True)
    os.chmod(tmp, 0o600)
    os.replace(tmp, STATE)


def nets(lines):
    out = []
    for l in lines:
        l = l.split("#")[0].strip()
        if l:
            try:
                out.append(ipaddress.ip_network(l, strict=False))
            except ValueError:
                pass
    return out


def whitelist():
    wl = nets(OFFICE) + nets(PRIVATE)
    if os.path.exists("/etc/bodyguard/admin-subnets.txt"):
        wl += nets(open("/etc/bodyguard/admin-subnets.txt"))
    cfp = "/etc/bodyguard/cloudflare-ips.txt"
    cf = nets(open(cfp)) if os.path.exists(cfp) else []
    return wl + (cf or nets(CF_DEFAULT))


def in_nets(ip, nl):
    a = ipaddress.ip_address(ip)
    return any(a in n for n in nl if n.version == a.version)


def list_value(ip):
    a = ipaddress.ip_address(ip)
    return str(ipaddress.ip_network("%s/64" % ip, strict=False)) if a.version == 6 else str(a)


# ---------------------------------------------------------------- HTTP (CF dipaksa IPv4)
_orig_gai = socket.getaddrinfo


def _gai_v4(host, *a, **k):
    if host == "api.cloudflare.com":
        a = list(a)
        if len(a) >= 2:
            a[1] = socket.AF_INET
        else:
            k["family"] = socket.AF_INET
    return _orig_gai(host, *a, **k)


socket.getaddrinfo = _gai_v4
CTX = ssl.create_default_context()


def http_json(method, url, headers, body=None, timeout=30):
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(url, data=data, method=method, headers=dict(headers, **{"Content-Type": "application/json"}))
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=CTX) as r:
            return json.loads(r.read().decode())
    except urllib.error.HTTPError as e:
        try:
            return json.loads(e.read().decode())
        except Exception:
            return {"success": False, "ok": False, "errors": [{"message": "HTTP %d" % e.code}]}
    except (urllib.error.URLError, OSError, ValueError) as e:
        return {"success": False, "ok": False, "errors": [{"message": e.__class__.__name__}]}


class CF(object):
    def __init__(self, env):
        self.env = env
        self.h = {"Authorization": "Bearer " + env["CF_AUTH_TOKEN"]}

    def call(self, method, path, body=None):
        r = http_json(method, CF_API + path, self.h, body)
        if not r.get("success"):
            raise RuntimeError("CF %s %s: %s" % (method, path.split("?")[0],
                               "; ".join(clean(e.get("message"), 150) for e in r.get("errors", []))))
        return r

    def list_id(self):
        for l in self.call("GET", "/accounts/%s/rules/lists" % self.env["CF_ACCOUNT_ID"]).get("result", []):
            if l.get("name") == self.env["CF_LIST_NAME"] and l.get("kind") == "ip":
                return l["id"]
        raise RuntimeError("list IP '%s' tidak ada" % self.env["CF_LIST_NAME"])

    def list_items(self, lid):
        items, cur = [], None
        while True:
            r = self.call("GET", "/accounts/%s/rules/lists/%s/items?per_page=500%s" % (
                self.env["CF_ACCOUNT_ID"], lid, "&cursor=" + cur if cur else ""))
            items += r.get("result", [])
            cur = ((r.get("result_info") or {}).get("cursors") or {}).get("after")
            if not cur:
                return items

    def add_items(self, lid, items):
        if items:
            self.call("POST", "/accounts/%s/rules/lists/%s/items" % (self.env["CF_ACCOUNT_ID"], lid), items)

    def del_items(self, lid, ids):
        if ids:
            self.call("DELETE", "/accounts/%s/rules/lists/%s/items" % (self.env["CF_ACCOUNT_ID"], lid),
                      {"items": [{"id": i} for i in ids]})

    def rules(self):
        r = self.call("GET", "/zones/%s/rulesets/%s" % (self.env["CF_ZONE_ID"], self.env["CF_RULESET_ID"]))
        return r["result"].get("rules", [])

    def patch_rule(self, expr):
        body = {"description": "Auto-Block - Dinamis Hacker", "expression": expr, "action": "block", "enabled": True}
        if self.env.get("CF_AFTER_RULE"):
            body["position"] = {"after": self.env["CF_AFTER_RULE"]}
        self.call("PATCH", "/zones/%s/rulesets/%s/rules/%s" % (self.env["CF_ZONE_ID"], self.env["CF_RULESET_ID"],
                                                               self.env["CF_RULE_ID"]), body)

    def waf_blocks(self, hours=24):
        """IP -> jumlah ditolak rule custom (selain Auto-Block) dalam N jam. Gagal = {} (tidak menambah keyakinan)."""
        since = (datetime.now(timezone.utc) - timedelta(hours=hours)).strftime("%Y-%m-%dT%H:%M:%SZ")
        q = ('query($z:String!,$s:Time!){viewer{zones(filter:{zoneTag:$z}){firewallEventsAdaptiveGroups('
             'limit:2000,filter:{datetime_geq:$s,action:"block",source:"firewallCustom"},orderBy:[count_DESC])'
             '{count dimensions{clientIP ruleId}}}}}')
        r = http_json("POST", CF_API + "/graphql", self.h, {"query": q, "variables": {"z": self.env["CF_ZONE_ID"], "s": since}})
        out = collections.Counter()
        try:
            for g in r["data"]["viewer"]["zones"][0]["firewallEventsAdaptiveGroups"]:
                if g["dimensions"]["ruleId"] != self.env["CF_RULE_ID"]:
                    out[g["dimensions"]["clientIP"]] += g["count"]
        except (KeyError, IndexError, TypeError):
            pass
        return out


# ---------------------------------------------------------------- Telegram (kirim lewat notify-run.sh; terima untuk bot SOC)
def kirim(text, chat=None):
    """Satu pengirim: notify-run.sh --pesan, token bot SOC dari cloudflare.env. Tidak pernah melempar exception."""
    argv = [NOTIFY_RUN, "--pesan", "--env", ENV, "--token-var", "CG_TG_TOKEN", "--chat-var", "CG_CHAT_ID"]
    if chat:
        argv += ["--chat", str(chat)]
    try:
        r = subprocess.run(argv, input=text[:3900].encode("utf-8", "replace"), stdout=subprocess.DEVNULL,
                           stderr=subprocess.PIPE, timeout=60)
        if r.returncode != 0:
            log("PERINGATAN kirim Telegram gagal: %s" % clean(r.stderr.decode("utf-8", "replace"), 150))
            return False
        return True
    except (OSError, subprocess.SubprocessError) as e:
        log("PERINGATAN notify-run.sh tidak bisa dijalankan: %s" % e.__class__.__name__)
        return False


class TG(object):
    """Hanya untuk MENERIMA perintah bot SOC (getUpdates). Pengiriman lewat kirim()."""
    def __init__(self, env):
        self.token = env.get("CG_TG_TOKEN", "")
        self.chat = env.get("CG_CHAT_ID", "")
        self.approvers = {x for x in re.split(r"[ ,]+", env.get("CG_APPROVER_IDS", "")) if x.isdigit()}
        self.key = (env.get("CG_HMAC_KEY") or "").encode()
        self.ok = bool(self.token and self.chat and self.approvers and len(self.key) >= 32)

    def call(self, method, body, timeout=30):
        r = http_json("POST", "%s/bot%s/%s" % (TG_API, self.token, method), {}, body, timeout)
        if not r.get("ok"):
            # description = jawaban Telegram; errors = galat jaringan dari http_json (timeout, DNS, koneksi putus)
            why = r.get("description") or "; ".join(str(e.get("message", "?")) for e in r.get("errors", [])) or "?"
            raise RuntimeError("Telegram %s: %s" % (method, clean(why, 150)))
        return r.get("result")

    def send(self, text, chat=None):
        return kirim(text, chat)


def ajukan(env, st, kind, value, info):
    """Usulan T2 -> SATU gerbang persetujuan (SOC-IR). Tombol, HMAC, nonce, TTL, dan freeze ditangani gerbang.
    Setelah disetujui, gerbang memanggil 'bg-root cf-approve' yang menjalankan 'cf-guard.py approve <id>'."""
    if any(p["value"] == value and p["kind"] == kind for p in st["pending"].values()):
        return None
    rid = secrets.token_hex(6)
    st["pending"][rid] = {"kind": kind, "value": value, "info": clean(info, 200), "ts": int(now())}
    argv = shlex.split(env.get("CG_GERBANG") or GERBANG_BAWAAN) + [
        "--id", rid, "--jenis", kind, "--nilai", value, "--info", clean(info, 200)]
    try:
        r = subprocess.run(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=60)
        out = r.stdout.decode("utf-8", "replace").strip()
        if r.returncode != 0:
            raise RuntimeError("rc=%d %s" % (r.returncode, clean(r.stderr.decode("utf-8", "replace"), 150)))
        log("DIAJUKAN ke persetujuan admin: %s %s (id %s) %s" % (kind, value, rid, clean(out, 120)))
    except (OSError, subprocess.SubprocessError, RuntimeError) as e:
        log("PERINGATAN jalur persetujuan admin tidak terjangkau (%s). Usulan %s tetap tersimpan; putuskan dari konsol: "
            "cf-guard.py approve %s / reject %s" % (clean(e, 150), value, rid, rid))
    return rid


# ---------------------------------------------------------------- bukti
def load_behavior():
    files = sorted(glob.glob("/root/ip-behavior-*.csv"))
    if not files:
        raise RuntimeError("belum ada /root/ip-behavior-*.csv (jalankan ip-report.sh)")
    if now() - os.path.getmtime(files[-1]) > 2 * 86400:
        raise RuntimeError("%s lebih tua dari 2 hari (jalankan ip-report.sh)" % files[-1])
    rows = {}
    with open(files[-1], encoding="utf-8") as f:
        for r in csv.DictReader(f):
            try:
                ipaddress.ip_address(r["ip"])
                rows[r["ip"]] = {"score": int(r.get("skor") or 0), "label": r.get("label", ""),
                                 "advice": r.get("saran", ""), "accounts": r.get("akun", ""), "isp": r.get("isp", "")}
            except (ValueError, KeyError):
                continue
    return files[-1], rows


def scan_paths(bad_ips, days):
    """path -> {ips:set, ok:bool}. ok=True bila path pernah dijawab 2xx/3xx ke SIAPA PUN."""
    cutoff = now() - days * 86400
    probes = collections.defaultdict(set)
    served = set()
    for fn in glob.glob("/var/log/nginx/*access.log*"):
        try:
            if os.path.getmtime(fn) < cutoff:
                continue
            fh = gzip.open(fn, "rt", errors="replace") if fn.endswith(".gz") else open(fn, errors="replace")
        except OSError:
            continue
        with fh:
            for line in fh:
                m = LINE_RE.match(line)
                if not m:
                    continue
                path = m.group("u").split("?", 1)[0]
                st = m.group("s")
                if st[0] in "23":
                    served.add(path)
                elif m.group("ip") in bad_ips and st in ("403", "404", "410", "444"):
                    probes[path].add(m.group("ip"))
    return {p: {"ips": ips, "ok": p in served} for p, ips in probes.items()}


def covered_by_rules(path, rules, own_id):
    """Perkiraan: path sudah tertangkap rule 1-4 bila literal contains/ends_with/starts_with/eq rule-rule itu cocok."""
    lp = path.lower()
    for ru in rules:
        if ru.get("id") == own_id or ru.get("action") != "block":
            continue
        ex = ru.get("expression", "")
        for lit in re.findall(r'contains\s+"([^"]{2,})"', ex):
            if lit.lower() in lp:
                return True
        for lit in re.findall(r'ends_with\([^,]+,\s*"([^"]+)"\)', ex):
            if lp.endswith(lit.lower()):
                return True
        for lit in re.findall(r'starts_with\([^,]+,\s*"([^"]+)"\)', ex):
            if lp.startswith(lit.lower()):
                return True
        for lit in re.findall(r'uri\.path\s+eq\s+"([^"]+)"', ex):
            if lp == lit.lower():
                return True
    return False


def build_expr(env, paths):
    head = "(not cf.client.bot and ip.src in $%s)" % env["CF_LIST_NAME"]
    ordered = sorted(paths.items(), key=lambda kv: kv[1]["added"])
    while ordered:
        body = " ".join('"%s"' % p for p, _ in ordered)
        expr = head + " or (not cf.client.bot and http.request.uri.path in {%s})" % body
        if len(expr) <= EXPR_MAX:
            return expr, [p for p, _ in ordered]
        ordered.pop(0)
    return head, []


# ---------------------------------------------------------------- perintah
def plan(env, cf, st, rules):
    src, beh = load_behavior()
    wl = whitelist()
    waf = cf.waf_blocks()
    ips_auto, ips_ask, skip = {}, {}, []
    for ip, r in beh.items():
        if r["score"] < 80:
            continue
        if not r["advice"].startswith("blokir di Cloudflare"):
            skip.append((ip, r["score"], clean(r["advice"], 50)))
            continue
        if in_nets(ip, wl):
            skip.append((ip, r["score"], "whitelist"))
            continue
        v = list_value(ip)
        if v in st["ips"] or v in st["rejected"]:
            continue
        info = "skor%d %s %s" % (r["score"], clean(r["label"], 30), clean(r["accounts"], 40))
        if r["score"] >= 100 or waf.get(ip, 0) >= 5:
            ips_auto[v] = info + (" waf%d" % waf[ip] if waf.get(ip) else "")
        else:
            ips_ask[v] = info + " waf%d" % waf.get(ip, 0)
    bad = {ip for ip, r in beh.items() if r["score"] >= 80 and r["advice"].startswith("blokir di Cloudflare")
           and not in_nets(ip, wl)}
    paths_auto, paths_ask = {}, {}
    for p, d in scan_paths(bad, 7).items():
        n = len(d["ips"])
        if n < 2 or p in st["paths"] or p in st["rejected"] or p in NEVER_PATHS or not PATH_RE.match(p):
            continue
        if covered_by_rules(p, rules, env["CF_RULE_ID"]):
            continue
        info = "%d IP jahat%s" % (n, ", PERNAH 2xx/3xx" if d["ok"] else "")
        if n >= 3 and not d["ok"]:
            paths_auto[p] = info
        else:
            paths_ask[p] = info
    return src, ips_auto, ips_ask, paths_auto, paths_ask, skip, len(waf)


def apply_changes(env, cf, st, add_ips, add_paths, reason, ttl_ip=None):
    """add_ips: {value: info}; add_paths: {path: info}. Sinkron list + PATCH rule. ttl_ip (detik) menimpa CG_IP_TTL_DAYS."""
    lid = cf.list_id()
    if ttl_ip is None:
        ttl_ip = int(env.get("CG_IP_TTL_DAYS") or 0) * 86400
    ttl_path = int(env.get("CG_PATH_TTL_DAYS") or 0) * 86400
    if add_ips:
        make_room(env, cf, st, lid, len(add_ips))
        cf.add_items(lid, [{"ip": v, "comment": ("%s %s %s" % (TAG, day(), i))[:500]} for v, i in sorted(add_ips.items())])
        for v, i in add_ips.items():
            st["ips"][v] = {"added": now(), "expires": now() + ttl_ip if ttl_ip else None, "info": i, "by": reason}
    for p, i in add_paths.items():
        st["paths"][p] = {"added": now(), "expires": now() + ttl_path if ttl_path else None, "info": i, "by": reason}
    expr, kept = build_expr(env, st["paths"])
    for p in [p for p in st["paths"] if p not in kept]:
        log("PANGKAS path tertua (ruang ekspresi): %s" % p)
        del st["paths"][p]
    old = next((r.get("expression") for r in cf.rules() if r.get("id") == env["CF_RULE_ID"]), None)
    if old != expr:
        cf.patch_rule(expr)
        st["history"].append({"at": now(), "expr": old, "reason": reason})
        st["history"] = st["history"][-10:]
    log("TERAPKAN (%s): +%d IP, +%d path, rule %d karakter" % (reason, len(add_ips), len(add_paths), len(expr)))


def make_room(env, cf, st, lid, incoming):
    """Buang entri cg tertua HANYA bila list akan melewati 95% kapasitas. Entri manual (non-cg) tidak disentuh."""
    cap = int(env.get("CG_LIST_MAX") or 10000)
    items = cf.list_items(lid)
    limit = int(cap * LIST_FULL_RATIO)
    over = len(items) + incoming - limit
    if over <= 0:
        return
    ours = sorted((i for i in items if (i.get("comment") or "").startswith(TAG + " ")), key=lambda i: i.get("created_on", ""))
    drop = ours[:over + max(1, cap // 100)]
    if len(drop) < over:
        raise RuntimeError("list penuh (%d/%d) dan entri cg tidak cukup untuk dibuang; tidak menambah" % (len(items), cap))
    cf.del_items(lid, [i["id"] for i in drop])
    for i in drop:
        st["ips"].pop(i.get("ip"), None)
    msg = "cf-guard: list $%s hampir penuh (%d/%d), %d entri tertua dibuang (%s s/d %s)" % (
        env["CF_LIST_NAME"], len(items), cap, len(drop), (drop[0].get("created_on") or "")[:10], (drop[-1].get("created_on") or "")[:10])
    log(msg)
    kirim(msg)


def expire(env, cf, st, apply):
    t = now()
    old_ips = [v for v, d in st["ips"].items() if d.get("expires") and d["expires"] < t]
    old_paths = [p for p, d in st["paths"].items() if d.get("expires") and d["expires"] < t]
    for k in [k for k, d in st["rejected"].items() if d < t - 30 * 86400]:
        del st["rejected"][k]
    for rid in [r for r, p in st["pending"].items() if t - p["ts"] > PENDING_TTL]:
        del st["pending"][rid]
    if not (old_ips or old_paths):
        return
    log("KEDALUWARSA: %d IP, %d path%s" % (len(old_ips), len(old_paths), "" if apply else " (dry-run)"))
    if not apply:
        return
    if old_ips:
        lid = cf.list_id()
        ids = [i["id"] for i in cf.list_items(lid) if i.get("ip") in old_ips and (i.get("comment") or "").startswith(TAG + " ")]
        cf.del_items(lid, ids)
        for v in old_ips:
            del st["ips"][v]
    for p in old_paths:
        del st["paths"][p]
    if old_paths:
        expr, _ = build_expr(env, st["paths"])
        cf.patch_rule(expr)


def cmd_run(env, a):
    st = load_state()
    cf, tg = CF(env), TG(env)
    if os.path.exists(FREEZE) and a.apply:
        sys.exit("FREEZE aktif (%s): tidak ada perubahan. Cabut dengan: cf-guard.py unfreeze" % FREEZE)
    rules = cf.rules()
    if not any(r.get("id") == env["CF_RULE_ID"] for r in rules):
        sys.exit("Rule %s tidak ditemukan di ruleset." % env["CF_RULE_ID"])
    src, ia, iq, pa, pq, skip, nwaf = plan(env, cf, st, rules)
    print("Sumber: %s | WAF events: %d IP | entri aktif: %d IP, %d path" % (src, nwaf, len(st["ips"]), len(st["paths"])))
    for title, d in (("OTOMATIS IP", ia), ("OTOMATIS PATH", pa), ("MINTA PERSETUJUAN IP", iq), ("MINTA PERSETUJUAN PATH", pq)):
        print("\n== %s: %d" % (title, len(d)))
        for k, v in sorted(d.items())[:60]:
            print("  %-44s %s" % (clean(k, 44), v))
    print("\n== Dilewati (bukan target blokir): %d" % len(skip))
    for ip, s, why in skip[:15]:
        print("  %-44s skor %3d %s" % (ip, s, why))
    if len(ia) > MAX_NEW_IP or len(pa) > MAX_NEW_PATH:
        msg = "cf-guard ANOMALI: %d IP / %d path otomatis melebihi batas %d/%d. Tidak ada yang diterapkan." % (
            len(ia), len(pa), MAX_NEW_IP, MAX_NEW_PATH)
        log(msg)
        if a.apply:
            tg.send(msg)
        sys.exit(3)
    expr, _ = build_expr(env, dict(st["paths"], **{p: {"added": now()} for p in pa}))
    print("\nEkspresi baru (%d karakter):\n  %s" % (len(expr), expr[:600] + (" ..." if len(expr) > 600 else "")))
    if not a.apply:
        print("\nDRY-RUN: tidak ada yang diubah. Tambah --apply.")
        expire(env, cf, st, False)
        return
    expire(env, cf, st, True)
    if ia or pa:
        apply_changes(env, cf, st, ia, pa, "otomatis")
        tg.send("cf-guard: otomatis diblokir %d IP, %d path.\n%s" % (len(ia), len(pa), "\n".join(
            "- %s  %s" % (clean(k, 50), v) for k, v in list(ia.items())[:15] + list(pa.items())[:10])))
    for kind, d in (("ip", iq), ("path", pq)):
        for v, info in list(d.items())[:10]:
            ajukan(env, st, kind, v, info)
    save_state(st)


# ---------------------------------------------------------------- bot SOC interaktif (satu poller untuk bot SOC)
BOT_CMDS = [
    ("start", "Menu utama"), ("help", "Daftar perintah"),
    ("ringkas", "Ringkasan serangan terbaru"), ("top", "Top IP berbahaya, mis. /top 15"),
    ("ip", "Detail IP, mis. /ip 1.2.3.4"), ("blok", "Blokir IP (perlu konfirmasi), mis. /blok 1.2.3.4"),
    ("unblok", "Lepas blokir IP, mis. /unblok 1.2.3.4"), ("aktif", "Daftar blokir aktif"),
    ("pending", "Permintaan yang menunggu persetujuan"), ("laporan", "Laporan soc_ir terakhir"),
    ("status", "Status cf-guard"), ("freeze", "Bekukan semua perubahan cf-guard"),
]
IP_IN_RE = re.compile(r"\A[0-9A-Fa-f:.]{2,45}\Z")


def help_text():
    return ("Bot SOC kampus.\n\n"
            "Perintah (klik untuk menjalankan):\n" + "\n".join("/%s - %s" % c for c in BOT_CMDS) +
            "\n\nAngka/huruf setelah /ip_ dan /blok_ adalah Attack ID (kode pendek IP), klik saja.\n"
            "Blokir dan lepas blokir diajukan ke persetujuan admin (tombol di bot persetujuan). "
            "Unfreeze hanya dari konsol server.")


def attack_id(key, ip):
    import base64
    return base64.b32encode(hmac.new(key, ip.encode(), hashlib.sha256).digest()).decode().lower()[:6]


def read_rows():
    files = sorted(glob.glob("/root/ip-behavior-*.csv"))
    if not files:
        return None, {}
    rows = {}
    with open(files[-1], encoding="utf-8", errors="replace") as f:
        for r in csv.DictReader(f):
            try:
                ipaddress.ip_address(r.get("ip", ""))
                r["skor"] = int(r.get("skor") or 0)
                rows[r["ip"]] = r
            except ValueError:
                continue
    return files[-1], rows


def strict_ip(arg):
    """Hanya satu alamat IP utuh. Tolak 1.2.3. / 1.2.3 / 01.2.3.4 / CIDR / IPv4-mapped."""
    arg = (arg or "").strip()
    if not IP_IN_RE.match(arg) or arg.endswith(".") or arg.endswith(":") and not arg.endswith("::"):
        return None
    try:
        a = ipaddress.ip_address(arg)
    except ValueError:
        return None
    if a.version == 6 and a.ipv4_mapped:
        return None
    if a.version == 4 and any(len(x) > 1 and x.startswith("0") for x in arg.split(".")):
        return None
    return str(a)


class Bot(object):
    def __init__(self, env, tg):
        self.env, self.tg = env, tg
        self.viewers = {x for x in re.split(r"[ ,]+", env.get("CG_VIEW_CHATS", "")) if re.match(r"\A-?\d+\Z", x)}
        self.viewers.add(tg.chat)
        self.src, self.rows = read_rows()
        self.idmap = {}

    def refresh(self, st):
        self.src, self.rows = read_rows()
        self.idmap = {attack_id(self.tg.key, ip): ip for ip in list(self.rows) + list(st["ips"])}

    def reply(self, chat, text):
        return kirim(text, chat)

    def blocked(self, st, ip):
        return list_value(ip) in st["ips"]

    def line(self, r, st):
        ip = r["ip"]
        return "%s  skor %d  %s  %s%s\n   /ip_%s" % (ip, r["skor"], clean(r.get("label", ""), 30), clean(r.get("isp", ""), 25),
                                                    "  [DIBLOKIR]" if self.blocked(st, ip) else "", attack_id(self.tg.key, ip))

    def ranked(self):
        wl = whitelist()
        out = [r for r in self.rows.values() if not in_nets(r["ip"], wl) and not r.get("saran", "").startswith("IP kantor")]
        return sorted(out, key=lambda r: (-r["skor"], -int(r.get("request") or 0)))

    def resolve(self, arg):
        arg = (arg or "").strip()
        if re.match(r"\A[a-z2-7]{6}\Z", arg.lower()) and arg.lower() in self.idmap:
            return self.idmap[arg.lower()]
        return strict_ip(arg)

    def handle(self, st, m):
        chat = str((m.get("chat") or {}).get("id", ""))
        uid = str((m.get("from") or {}).get("id", ""))
        text = (m.get("text") or "").strip()
        if not text.startswith("/"):
            return
        if chat not in self.viewers and uid not in self.tg.approvers:
            log("bot: pesan dari chat tak dikenal %s user %s diabaikan" % (clean(chat, 20), clean(uid, 20)))
            return
        if now() - float(m.get("date") or 0) > 300:
            return
        head, _, arg = text.partition(" ")
        head = head.split("@", 1)[0].lower()
        m2 = re.match(r"\A/(ip|blok|unblok)_([a-z2-7]{6})\Z", head)
        if m2:
            head, arg = "/" + m2.group(1), m2.group(2)
        self.refresh(st)
        approver = uid in self.tg.approvers
        if head in ("/start", "/help"):
            return self.reply(chat, help_text())
        if head == "/ringkas":
            if not self.rows:
                return self.reply(chat, "Belum ada data ip-report (/root/ip-behavior-*.csv).")
            lab = collections.Counter(r.get("label", "?") for r in self.ranked() if r["skor"] >= 50)
            top = self.ranked()[:10]
            age = (now() - os.path.getmtime(self.src)) / 3600
            txt = ("RINGKASAN SERANGAN (data %s, %.0f jam lalu)\n\nKategori (IP skor>=50):\n%s\n\nTop 10 IP:\n%s\n\n"
                   "Blokir aktif cf-guard: %d IP, %d path. Menunggu persetujuan: %d.\nDetail: klik /ip_... ; laporan AI: /laporan") % (
                os.path.basename(self.src), age, "\n".join("  %3d  %s" % (n, clean(k, 40)) for k, n in lab.most_common(8)) or "  -",
                "\n".join("%d. %s" % (i + 1, self.line(r, st)) for i, r in enumerate(top)) or "-",
                len(st["ips"]), len(st["paths"]), len(st["pending"]))
            return self.reply(chat, txt)
        if head == "/top":
            n = int(arg) if arg.strip().isdigit() else 10
            n = max(1, min(n, 30))
            top = self.ranked()[:n]
            return self.reply(chat, "TOP %d IP\n\n%s" % (n, "\n".join("%d. %s" % (i + 1, self.line(r, st)) for i, r in enumerate(top)) or "-"))
        if head == "/ip":
            ip = self.resolve(arg)
            if not ip:
                return self.reply(chat, "Format: /ip 1.2.3.4 atau klik /ip_kode dari /ringkas. Alamat harus utuh (bukan 1.2.3. atau CIDR).")
            r = self.rows.get(ip)
            aid = attack_id(self.tg.key, ip)
            b = self.blocked(st, ip)
            if not r:
                return self.reply(chat, "%s (ID %s)\nTidak ada di data ip-report terakhir.%s\n%s" % (
                    ip, aid, " Status: DIBLOKIR." if b else "", "/unblok_%s" % aid if b else "/blok_%s" % aid))
            txt = ("IP %s  (Attack ID %s)\nSkor: %d | Label: %s\nISP: %s | AbuseIPDB: %s\nRequest: %s | aktif %s s/d %s\n"
                   "Kategori: recon %s, injeksi %s, login %s, xmlrpc %s, unggah %s, admin %s, php_data %s, webshell %s (sukses %s)\n"
                   "Akun: %s\nSaran: %s\nStatus: %s\n\n%s") % (
                ip, aid, r["skor"], clean(r.get("label"), 40), clean(r.get("isp"), 40), r.get("abuse") or "-",
                r.get("request"), clean(r.get("pertama"), 22), clean(r.get("terakhir"), 22),
                r.get("recon"), r.get("injeksi"), r.get("login"), r.get("xmlrpc"), r.get("unggah"), r.get("admin"),
                r.get("php_data"), r.get("webshell"), r.get("webshell_sukses"), clean(r.get("akun") or "-", 120),
                clean(r.get("saran"), 120), "DIBLOKIR di Cloudflare" if b else "belum diblokir",
                ("Lepas blokir: /unblok_%s" % aid) if b else ("Blokir: /blok_%s" % aid))
            return self.reply(chat, txt)
        if head in ("/blok", "/unblok"):
            if not approver:
                return self.reply(chat, "Hanya approver yang boleh memblokir/melepas blokir.")
            ip = self.resolve(arg)
            if not ip:
                return self.reply(chat, "Format: %s 1.2.3.4 (alamat utuh satu IP; tanpa titik di akhir, tanpa CIDR)." % head)
            if os.path.exists(FREEZE):
                return self.reply(chat, "FREEZE aktif. Tidak ada perubahan sampai unfreeze dari konsol.")
            v = list_value(ip)
            warn = ""
            if head == "/blok":
                if in_nets(ip, whitelist()):
                    return self.reply(chat, "DITOLAK: %s termasuk whitelist (kantor/server/Cloudflare/privat)." % ip)
                if v in st["ips"]:
                    return self.reply(chat, "%s sudah diblokir." % v)
                r = self.rows.get(ip, {})
                warn = ""
                if (r.get("saran") or "").startswith("JANGAN"):
                    warn = "\nPERINGATAN: IP seluler/CGNAT, dipakai banyak orang. Blokir berdampak ke pengguna lain.\n"
                kind, info = "ip", "manual /blok oleh %s: skor %s %s" % (uid, r.get("skor", "-"), clean(r.get("label", ""), 30))
                title = "KONFIRMASI BLOKIR %s%s\n%s\nDampak: semua akses dari %s ke situs kampus diblokir Cloudflare (permanen sampai /unblok)." % (
                    v, " (/64)" if ":" in ip else "", warn, v)
            else:
                if v not in st["ips"]:
                    return self.reply(chat, "%s tidak ada di daftar blokir cf-guard." % v)
                kind, info = "unip", "manual /unblok oleh %s" % uid
                title = "LEPAS BLOKIR %s" % v
            rid = ajukan(self.env, st, kind, v, info + (" " + warn.strip() if warn else ""))
            return self.reply(chat, "%s\nDiajukan ke persetujuan admin (id %s). Tombol Setujui/Tolak muncul di bot persetujuan, "
                                    "berlaku 30 menit." % (title, rid or "sudah ada"))
        if head == "/aktif":
            ips = sorted(st["ips"].items(), key=lambda kv: -kv[1]["added"])[:30]
            return self.reply(chat, "BLOKIR AKTIF: %d IP, %d path\n\n%s\n\nPath:\n%s" % (
                len(st["ips"]), len(st["paths"]),
                "\n".join("%s  %s  /unblok_%s" % (v, day(d["added"]), attack_id(self.tg.key, v.split("/")[0])) for v, d in ips) or "-",
                "\n".join(sorted(st["paths"])[:20]) or "-"))
        if head == "/pending":
            return self.reply(chat, "MENUNGGU PERSETUJUAN: %d\n%s" % (len(st["pending"]), "\n".join(
                "- %s %s (%s)" % (p["kind"], p["value"], clean(p["info"], 60)) for p in st["pending"].values()) or "-"))
        if head == "/laporan":
            fs = sorted(glob.glob("/var/log/soc_ir/laporan-*.txt"))
            if not fs:
                return self.reply(chat, "Belum ada laporan soc_ir.")
            return self.reply(chat, "%s\n\n%s" % (os.path.basename(fs[-1]), open(fs[-1], errors="replace").read()[:3600]))
        if head == "/status":
            last = ""
            try:
                last = "\n".join(open(LOG).read().splitlines()[-5:])
            except OSError:
                pass
            return self.reply(chat, "STATUS cf-guard\nFREEZE: %s\nBlokir: %d IP, %d path\nPending: %d\nData ip-report: %s\n\nLog terakhir:\n%s" % (
                "AKTIF" if os.path.exists(FREEZE) else "tidak", len(st["ips"]), len(st["paths"]), len(st["pending"]),
                os.path.basename(self.src or "-"), clean(last, 900)))
        if head == "/freeze":
            if not approver:
                return self.reply(chat, "Hanya approver.")
            bekukan("Telegram bot SOC oleh %s: %s" % (uid, clean(arg, 100)))
            return self.reply(chat, "FREEZE AKTIF untuk semua modul (cf-guard, SOC-IR T1/T2, M3 --auto). "
                                    "Cabut hanya dari konsol: freeze.sh off \"alasan\"")
        return self.reply(chat, "Perintah tidak dikenal. Ketik /help")


def do_remove(env, st, v):
    cf = CF(env)
    if v in st["paths"]:
        del st["paths"][v]
        cf.patch_rule(build_expr(env, st["paths"])[0])
    else:
        val = list_value(v.split("/")[0]) if "/" in v and ":" in v else list_value(v) if "/" not in v else v
        lid = cf.list_id()
        cf.del_items(lid, [i["id"] for i in cf.list_items(lid) if i.get("ip") == val])
        st["ips"].pop(val, None)
    st["rejected"][v] = now()
    log("REMOVE: %s" % v)


def cmd_poll(env, a):
    tg = TG(env)
    if not tg.ok:
        sys.exit("Konfigurasi bot SOC cf-guard belum lengkap (CG_TG_TOKEN, CG_CHAT_ID, CG_APPROVER_IDS, CG_HMAC_KEY).")
    bot = Bot(env, tg)
    try:
        tg.call("setMyCommands", {"commands": [{"command": c, "description": d} for c, d in BOT_CMDS]})
    except RuntimeError as e:
        log("setMyCommands: %s" % e)
    end = now() + (10 ** 9 if a.loop else 50)
    while now() < end:
        st = load_state()
        try:
            ups = tg.call("getUpdates", {"offset": st["tg_offset"], "timeout": 25,
                                         "allowed_updates": ["message"]}, timeout=40) or []
        except RuntimeError as e:
            log("poll: %s" % e)
            time.sleep(10)
            continue
        for u in ups:
            st["tg_offset"] = u["update_id"] + 1
            if u.get("message"):
                try:
                    bot.handle(st, u["message"])
                except Exception as e:  # satu pesan buruk tidak boleh mematikan bot
                    log("bot: galat %s: %s" % (e.__class__.__name__, clean(e, 150)))
        save_state(st)


def cmd_status(env, a):
    st = load_state()
    print("FREEZE: %s" % ("AKTIF" if os.path.exists(FREEZE) else "tidak"))
    print("\n== IP aktif (%d)" % len(st["ips"]))
    for v, d in sorted(st["ips"].items(), key=lambda kv: kv[1]["added"]):
        print("  %-44s %s  %s [%s]" % (v, "s/d " + day(d["expires"]) if d.get("expires") else "permanen", d["info"], d["by"]))
    print("\n== Path aktif (%d)" % len(st["paths"]))
    for p, d in sorted(st["paths"].items(), key=lambda kv: kv[1]["added"]):
        print("  %-60s %s  %s [%s]" % (p, "s/d " + day(d["expires"]) if d.get("expires") else "permanen", d["info"], d["by"]))
    print("\n== Menunggu persetujuan (%d)" % len(st["pending"]))
    for rid, p in st["pending"].items():
        print("  %s %-5s %s  %s" % (rid, p["kind"], p["value"], p["info"]))
    print("\n== Riwayat ekspresi: %d versi tersimpan (rollback mengembalikan yang terakhir)" % len(st["history"]))


def bekukan(alasan):
    d = os.path.dirname(FREEZE)
    os.makedirs(d, exist_ok=True)
    if not os.path.exists(FREEZE):
        with open(FREEZE, "w") as f:
            f.write("%s oleh cf-guard: %s\n" % (time.strftime("%F %T"), clean(alasan, 200)))
    log("FREEZE: %s" % clean(alasan, 200))


def hasil(obj, code=0):
    print(json.dumps(obj, ensure_ascii=True))
    sys.exit(code)


def cmd_block(env, a):
    """T1 dari SOC-IR (lewat bg-root cf-block): blokir satu IP ber-TTL di daftar hacker Cloudflare."""
    ip = strict_ip(a.ip)
    if not ip:
        hasil({"ok": False, "galat": "alamat IP tidak valid (harus satu alamat utuh)"}, 3)
    if os.path.exists(FREEZE):
        hasil({"ok": False, "galat": "FREEZE aktif"}, 3)
    if in_nets(ip, whitelist()):
        hasil({"ok": False, "galat": "IP termasuk daftar putih"}, 3)
    if not 60 <= a.ttl <= 86400:
        hasil({"ok": False, "galat": "ttl harus 60..86400 detik"}, 3)
    st = load_state()
    v = list_value(ip)
    if v in st["ips"]:
        hasil({"ok": True, "ip": v, "status": "sudah diblokir", "rollback": "cf-guard.py remove %s" % v})
    cf = CF(env)
    apply_changes(env, cf, st, {v: "T1 %s ttl%ds" % (clean(a.oleh, 30), a.ttl)}, {}, "t1:%s" % clean(a.oleh, 30), ttl_ip=a.ttl)
    save_state(st)
    hasil({"ok": True, "ip": v, "ttl": a.ttl, "expires_at": int(now()) + a.ttl, "rollback": "cf-guard.py remove %s" % v})


def cmd_decide(env, a, setuju):
    """Keputusan atas usulan T2. 'approve' hanya dipanggil gerbang setelah tombol sah, atau admin di konsol."""
    if not RID_RE.match(a.id):
        hasil({"ok": False, "galat": "id tidak valid"}, 2)
    st = load_state()
    p = st["pending"].get(a.id)
    if not p:
        hasil({"ok": False, "galat": "usulan tidak ada atau sudah diproses"}, 3)
    if setuju and os.path.exists(FREEZE):
        hasil({"ok": False, "galat": "FREEZE aktif, tidak diterapkan"}, 3)
    del st["pending"][a.id]
    if not setuju:
        if p["kind"] in ("ip", "path"):
            st["rejected"][p["value"]] = now()
        save_state(st)
        log("DITOLAK (%s): %s %s" % (clean(a.oleh, 40), p["kind"], p["value"]))
        hasil({"ok": True, "status": "ditolak", "nilai": p["value"]})
    try:
        if p["kind"] == "unip":
            do_remove(env, st, p["value"])
            rollback = "cf-guard.py block %s --ttl 86400" % p["value"].split("/")[0]
        else:
            add = {p["value"]: "%s disetujui %s" % (p["info"], clean(a.oleh, 40))}
            apply_changes(env, CF(env), st, add if p["kind"] == "ip" else {}, add if p["kind"] == "path" else {},
                          "disetujui:%s" % clean(a.oleh, 40))
            rollback = "cf-guard.py remove %s" % p["value"]
    except RuntimeError as e:
        st["pending"][a.id] = p
        save_state(st)
        log("GAGAL %s %s: %s" % (p["kind"], p["value"], e))
        hasil({"ok": False, "galat": clean(e, 200)}, 5)
    save_state(st)
    hasil({"ok": True, "status": "diterapkan", "jenis": p["kind"], "nilai": p["value"], "rollback": rollback})


def cmd_rollback(env, a):
    st = load_state()
    if not st["history"]:
        sys.exit("Tidak ada riwayat.")
    h = st["history"].pop()
    CF(env).patch_rule(h["expr"] or "(ip.src in $%s)" % env["CF_LIST_NAME"])
    save_state(st)
    log("ROLLBACK ekspresi ke versi %s (%s)" % (time.strftime("%F %T", time.localtime(h["at"])), h["reason"]))
    print("Catatan: entri di state tidak diubah; jalankan 'remove' untuk entri yang ingin dibuang permanen.")


def cmd_remove(env, a):
    st = load_state()
    do_remove(env, st, a.value)
    save_state(st)


def main():
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="cmd")
    r = sub.add_parser("run")
    r.add_argument("--apply", action="store_true")
    p = sub.add_parser("poll")
    p.add_argument("--loop", action="store_true")
    sub.add_parser("status")
    sub.add_parser("rollback")
    rm = sub.add_parser("remove")
    rm.add_argument("value")
    b = sub.add_parser("block")
    b.add_argument("ip")
    b.add_argument("--ttl", type=int, required=True)
    b.add_argument("--oleh", default="soc-ir")
    for n in ("approve", "reject"):
        d = sub.add_parser(n)
        d.add_argument("id")
        d.add_argument("--oleh", default="konsol")
    sub.add_parser("freeze")
    sub.add_parser("unfreeze")
    argv = sys.argv[1:]
    if not argv or argv[0].startswith("-") and argv[0] not in ("-h", "--help"):
        argv = ["run"] + argv          # "cf-guard.py --apply" == "cf-guard.py run --apply"
    a = ap.parse_args(argv)
    if os.geteuid() != 0:
        sys.exit("Jalankan sebagai root.")
    os.umask(0o077)
    if a.cmd == "freeze":
        return bekukan("konsol")
    if a.cmd == "unfreeze":
        sys.exit("FREEZE bersama dicairkan HANYA dari konsol dengan: freeze.sh off \"alasan\"")
    env = load_env()
    try:
        {"run": cmd_run, "poll": cmd_poll, "status": cmd_status, "rollback": cmd_rollback, "remove": cmd_remove,
         "block": cmd_block, "approve": lambda e, x: cmd_decide(e, x, True), "reject": lambda e, x: cmd_decide(e, x, False),
         }.get(a.cmd or "run")(env, a if a.cmd else argparse.Namespace(apply=False))
    except RuntimeError as e:
        log("GAGAL (tidak ada perubahan lanjutan): %s" % e)
        sys.exit(1)


if __name__ == "__main__":
    main()
