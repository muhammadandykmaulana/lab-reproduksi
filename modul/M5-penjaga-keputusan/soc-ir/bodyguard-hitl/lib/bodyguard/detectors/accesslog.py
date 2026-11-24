# -*- coding: utf-8 -*-
"""T0: pemindai log akses nginx (inkremental, tahan rotasi) untuk mengusulkan blokir IP T1.

PENTING soal sumber IP: kolom IP HARUS berasal dari $remote_addr nginx. Bila situs di belakang Cloudflare,
aktifkan real_ip (set_real_ip_from <rentang Cloudflare>; real_ip_header CF-Connecting-IP). JANGAN pakai
X-Forwarded-For mentah: header itu dikendalikan penyerang dan bisa dipakai untuk "memfitnah" IP lain.
Tanpa real_ip, IP yang tercatat adalah IP Cloudflare -> otomatis ditolak whitelist (aman, tapi tidak efektif).

Skor per IP per siklus (tiap aturan+URI dihitung sekali): critical POST sukses = 10, critical GET sukses = 3,
critical gagal = 1, high = 3, medium = 1.
Ambang (default): >=3 medium (TTL 1 jam), >=6 high (6 jam), >=10 critical (24 jam).
"""

import os
import time

from ..model import Finding
from ..sanitizer import clean
from ..whitelist import parse_ip

POINTS = {"critical": 10, "high": 3, "medium": 1, "low": 0, "info": 0}
# Anti "fitnah": halaman/email bisa membuat browser pengunjung (atau NAT kampus, crawler) mengirim GET ke URL
# webshell lewat <img src>. Karena itu hanya POST sukses yang bernilai penuh; GET sukses & permintaan gagal
# bernilai kecil, dan tiap (aturan, URI) hanya dihitung SEKALI per IP per siklus.
CRITICAL_GET_OK_POINTS = 3
CRITICAL_FAILED_POINTS = 1
MAX_URI = 2048


class AccessLogScanner(object):
    def __init__(self, cfg, store, rules, clock=time.time):
        self.cfg = cfg
        self.store = store
        self.rules = rules
        self.clock = clock

    def scan(self):
        per_ip = {}
        out = []
        for path in self.cfg.access_logs:
            try:
                for line in self._new_lines(path):
                    self._consume(line, per_ip)
            except OSError as e:
                out.append(Finding("ACCESSLOG_UNREADABLE", "medium", path, detail={
                    "error": e.__class__.__name__, "note": "deteksi IP penyerang tidak berjalan untuk log ini"},
                    source="accesslog"))
        for ip in sorted(per_ip):
            agg = per_ip[ip]
            score = agg["score"]
            if score >= self.cfg.score_critical:
                sev = "critical"
            elif score >= self.cfg.score_high:
                sev = "high"
            elif score >= self.cfg.score_medium:
                sev = "medium"
            else:
                continue
            out.append(Finding("ATTACKER_IP", sev, ip, rules=sorted(agg["rules"]),
                               detail={"score": score, "hits": agg["hits"], "samples": agg["samples"],
                                       "statuses": agg["statuses"]}, source="accesslog"))
            agg.pop("_seen", None)
        return out

    def _consume(self, raw, per_ip):
        line = raw.decode("utf-8", "replace")
        m = self.cfg.access_line_re.match(line)
        if not m:
            return
        try:
            ip = str(parse_ip(m.group("ip")))
            status = int(m.group("status"))
        except (ValueError, TypeError):
            return
        uri = m.group("uri")[:MAX_URI]  # batasi biaya regex pada URI sangat panjang
        method = m.group("method") if "method" in m.re.groupindex else "?"
        hits = self.rules.uri_hits(uri)
        if not hits:
            return
        agg = per_ip.setdefault(ip, {"score": 0, "hits": 0, "rules": set(), "samples": [], "statuses": {},
                                     "_seen": set()})
        ok = 200 <= status < 400
        for r in hits:
            key = (r["id"], uri.split("?", 1)[0])
            if key in agg["_seen"]:
                continue
            agg["_seen"].add(key)
            pts = POINTS.get(r["severity"], 0)
            if r["severity"] == "critical":
                pts = POINTS["critical"] if (ok and method == "POST") else (CRITICAL_GET_OK_POINTS if ok else CRITICAL_FAILED_POINTS)
            agg["score"] += pts
            agg["rules"].add(r["id"])
        agg["hits"] += 1
        agg["statuses"][str(status)] = agg["statuses"].get(str(status), 0) + 1
        if len(agg["samples"]) < 3:
            agg["samples"].append(clean("%s %s -> %d" % (method, uri, status), 200))

    def _read(self, path, start, limit):
        with open(path, "rb") as f:
            f.seek(start)
            return f.read(limit)

    def _new_lines(self, path):
        with open(path, "rb") as f:
            st = os.fstat(f.fileno())
        rec = self.store.conn.execute("SELECT ino, offset FROM log_offsets WHERE path=?", (path,)).fetchone()
        prefix = b""
        first_run = rec is None
        if first_run:
            start = max(0, st.st_size - self.cfg.access_initial_tail)
        elif rec["ino"] != st.st_ino:
            rotated = path + ".1"
            try:
                ost = os.stat(rotated)
                if ost.st_ino == rec["ino"] and ost.st_size > rec["offset"]:
                    prefix = self._read(rotated, rec["offset"], self.cfg.access_max_bytes)
                    cut = prefix.rfind(b"\n")
                    prefix = prefix[:cut + 1] if cut >= 0 else b""
            except OSError:
                pass
            start = 0
        elif st.st_size < rec["offset"]:
            start = 0
        else:
            start = rec["offset"]
        data = self._read(path, start, self.cfg.access_max_bytes)
        cut = data.rfind(b"\n")
        consumed = cut + 1 if cut >= 0 else (len(data) if len(data) >= self.cfg.access_max_bytes else 0)
        with self.store.tx() as c:
            c.execute("INSERT OR REPLACE INTO log_offsets(path, ino, offset, updated_at) VALUES (?,?,?,?)",
                      (path, st.st_ino, start + consumed, self.clock()))
        lines = (prefix + data[:consumed]).split(b"\n")
        if first_run and start > 0 and lines:
            lines = lines[1:]  # baris pertama kemungkinan terpotong
        return [l for l in lines if l]
