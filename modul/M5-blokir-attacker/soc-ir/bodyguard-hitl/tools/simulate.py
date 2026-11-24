#!/usr/bin/python3 -I
# -*- coding: utf-8 -*-
"""Simulasi dry-run Circuit Breaker + HMAC Telegram (aman dijalankan di server produksi).

Tidak memakai sudo, tidak menyentuh /var/www, tidak mengirim Telegram. Semua terjadi di direktori sementara
dengan jam palsu, memakai kode Bodyguard yang SAMA dengan produksi (T1Executor mode dry-run, Signer, Store).

    python3 /opt/bodyguard/tools/simulate.py
"""

import logging
import os
import shutil
import sys
import tempfile

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.realpath(__file__))), "lib"))

from bodyguard.breaker import CircuitBreaker  # noqa: E402
from bodyguard.config import config_from_string  # noqa: E402
from bodyguard.model import Finding, Proposal  # noqa: E402
from bodyguard.notifier import Notifier  # noqa: E402
from bodyguard.signing import Signer, new_nonce, parse_callback  # noqa: E402
from bodyguard.store import Store  # noqa: E402
from bodyguard.t1 import T1Executor  # noqa: E402
from bodyguard.whitelist import Whitelist  # noqa: E402

CF = ["173.245.48.0/20", "103.21.244.0/22", "104.16.0.0/13", "2606:4700::/32"]


class Clock(object):
    def __init__(self):
        self.t = 1793750000.0

    def __call__(self):
        return self.t


def line(ok, text):
    print("  [%s] %s" % ("LULUS" if ok else "GAGAL", text))
    return ok


def main():
    logging.getLogger("bodyguard").addHandler(logging.NullHandler())
    logging.getLogger("bodyguard").propagate = False
    tmp = tempfile.mkdtemp(prefix="bg-sim-")
    results = []
    try:
        up = os.path.join(tmp, "www", "s", "wp-content", "uploads")
        os.makedirs(up)
        cfg = config_from_string("[general]\nmode = dry-run\nstate_dir = %s\n[ioc]\ndata_dirs = %s\n" % (tmp, up))
        clock = Clock()
        store = Store(os.path.join(tmp, "sim.db"), clock=clock)
        notifier = Notifier("log", store, clock=clock)
        wl = Whitelist([("cloudflare", n) for n in CF])
        t1 = T1Executor(cfg, store, notifier, "dry-run", lambda: wl, clock=clock)
        inc = "INC-20261104-000000-0000"

        print("== Circuit breaker: 25 IP penyerang dalam 10 menit (batas 20/jam)")
        statuses = []
        for i in range(25):
            ip = "45.33.%d.%d" % (i // 200, i % 200 + 1)
            f = Finding("ATTACKER_IP", "critical", ip)
            statuses.append(t1.block_ip(inc, Proposal("T1", "BLOCK_IP", ip, {"ip": ip, "ttl": 86400}, f))["status"])
            clock.t += 24
        results.append(line(statuses[:20] == ["DRYRUN"] * 20, "20 blokir pertama disimulasikan (DRYRUN)"))
        results.append(line(statuses[20:] == ["SKIPPED"] * 5, "blokir ke-21..25 tidak dieksekusi (SKIPPED)"))
        urgent = [m for m in notifier.sent if m["urgent"]]
        results.append(line(len(urgent) == 1, "alert darurat breaker terkirim tepat sekali"))
        cf = t1.block_ip(inc, Proposal("T1", "BLOCK_IP", "104.16.5.5", {"ip": "104.16.5.5", "ttl": 3600},
                                       Finding("ATTACKER_IP", "critical", "104.16.5.5")))
        results.append(line(cf["status"] == "SKIPPED_WHITELIST", "IP Cloudflare tidak pernah diblokir (%s)" % cf["status"]))

        print("== Latch: 2 jam kemudian breaker tetap trip sampai reset manual")
        clock.t += 7200
        br = CircuitBreaker(store, cfg.limits, "dryrun", clock=clock)
        results.append(line(not br.acquire("chmod", "x").allowed, "masih T0 (amati saja) setelah 2 jam"))
        br.reset("simulasi", "uji reset")
        results.append(line(br.acquire("chmod", "x").allowed, "pulih setelah reset konsol"))
        results.append(line(CircuitBreaker(store, cfg.limits, "live", clock=clock).status()["t1_enabled"],
                            "namespace live tidak tersentuh simulasi"))

        print("== Circuit breaker: 7 file PHP liar (batas chmod 5/jam)")
        br.reset("simulasi", "mulai uji chmod")
        clock.t += 3601
        st = []
        for i in range(7):
            path = os.path.join(up, "s%d.php" % i)
            st.append(t1.contain(inc, Proposal("T1", "CONTAIN_FILE", path, {"path": path},
                                               Finding("PHP_IN_DATA_DIR", "critical", path, detail={"sha256": "%064d" % i})))["status"])
        results.append(line(st == ["DRYRUN"] * 5 + ["SKIPPED"] * 2, "5 disimulasikan, ke-6 memicu trip: %s" % st))

        print("== HMAC tombol Telegram")
        s = Signer(os.urandom(32))
        nonce, ts, req, sha, chat = new_nonce(), 1793750000, "REQ-0123456789ab", "a" * 64, -1001234567890
        a = s.make_callback("A", nonce, ts, req, sha, chat)
        results.append(line(len(a.encode()) <= 64, "callback_data %d byte (batas Telegram 64)" % len(a.encode())))
        results.append(line(s.verify(parse_callback(a), req, sha, chat, ts, ts + 60).ok, "tanda tangan sah diterima"))
        swapped = a.replace("1.A.", "1.R.", 1)
        results.append(line(s.verify(parse_callback(swapped), req, sha, chat, ts, ts + 60).status == "BAD_SIG",
                            "tukar Setujui<->Tolak terdeteksi"))
        results.append(line(s.verify(parse_callback(a), req, "b" * 64, chat, ts, ts + 60).status == "BAD_SIG",
                            "aksi diubah setelah pesan terbit terdeteksi"))
        results.append(line(s.verify(parse_callback(a), req, sha, chat, ts, ts + 1801).status == "EXPIRED",
                            "lewat 30 menit = EXPIRED (dianggap DITOLAK)"))
        results.append(line(Signer(os.urandom(32)).verify(parse_callback(a), req, sha, chat, ts, ts + 60).status == "BAD_SIG",
                            "kunci lain menolak"))
        print("   (anti-replay nonce sekali pakai diuji end-to-end di tests/test_gatekeeper.py)")
        store.close()
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
    ok = all(results)
    print("\nHASIL: %d/%d LULUS" % (sum(1 for r in results if r), len(results)))
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
