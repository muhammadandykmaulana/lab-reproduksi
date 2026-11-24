# -*- coding: utf-8 -*-
"""Circuit Breaker anti self-DoS untuk aksi T1.

* Jendela geser 3600 detik per jenis aksi: ip_block (default maks 20/jam), chmod (default maks 5/jam).
* Percobaan yang MELEBIHI batas tidak dieksekusi; breaker "trip" dan T1 dialihkan ke mode
  T0 (amati saja) untuk SEMUA jenis aksi. Trip bersifat LATCHED: tidak pulih otomatis, harus
  di-reset manual oleh admin dari konsol (bodyguard reset-breaker).
* Kill-switch /freeze (global) juga menolak semua aksi.
* Galat apa pun saat mengecek (DB terkunci/rusak, dsb.) = TOLAK (fail-safe ke alert/log).
* Namespace "dryrun" punya penghitung & status trip sendiri: simulasi tidak pernah mengubah status live.
* Cek-dan-catat atomik antar-proses (SQLite BEGIN IMMEDIATE), jadi beberapa proses paralel tetap
  tidak bisa melampaui batas.
"""

import collections
import os
import time

from .store import kv_del, kv_get, kv_set

WINDOW_SECONDS = 3600
KINDS = ("ip_block", "chmod")
FREEZE_KEY = "freeze"


def freeze_file():
    """SATU FREEZE untuk semua modul (freeze.sh): berkas ini juga dibaca cf-guard dan persistence-killer."""
    return os.environ.get("FREEZE_FILE", "/var/lib/freeze/FREEZE")
NAMESPACES = ("live", "dryrun")

Decision = collections.namedtuple("Decision", "allowed reason count limit tripped_now")


class CircuitBreaker(object):
    def __init__(self, store, limits, namespace="live", clock=time.time):
        if namespace not in NAMESPACES:
            raise ValueError("namespace harus live/dryrun")
        self.limits = {}
        for k in KINDS:
            v = int(limits[k])
            if v < 1:
                raise ValueError("batas %s harus >= 1" % k)
            self.limits[k] = v
        self.store = store
        self.ns = namespace
        self.clock = clock

    @property
    def tripped_key(self):
        return "breaker:%s:tripped" % self.ns

    def _count(self, c, kind, now):
        row = c.execute(
            "SELECT COUNT(*) FROM breaker_events WHERE ns=? AND kind=? AND ts>?",
            (self.ns, kind, now - WINDOW_SECONDS),
        ).fetchone()
        return int(row[0])

    def acquire(self, kind, target):
        """Minta izin satu aksi T1. Izin langsung dicatat (pesimistis) bila diberikan."""
        if kind not in self.limits:
            return Decision(False, "jenis aksi tidak dikenal: %r" % (kind,), 0, 0, False)
        limit = self.limits[kind]
        try:
            with self.store.tx() as c:
                frozen = kv_get(c, FREEZE_KEY)
                if frozen is not None:
                    return Decision(False, "FROZEN (kill-switch): %s" % frozen.get("reason", "?"), -1, limit, False)
                tripped = kv_get(c, self.tripped_key)
                if tripped is not None:
                    return Decision(False, "BREAKER_TRIPPED: %s" % tripped.get("reason", "?"), -1, limit, False)
                now = self.clock()
                if int(now) % 97 == 0:
                    c.execute("DELETE FROM breaker_events WHERE ts < ?", (now - 7 * 86400,))
                n = self._count(c, kind, now)
                if n >= limit:
                    reason = ("batas %s %d/jam terlampaui (percobaan ke-%d dalam 60 menit) - T1 dialihkan ke "
                              "T0 (amati saja)" % (kind, limit, n + 1))
                    kv_set(c, self.tripped_key, {
                        "at": now, "kind": kind, "count": n, "limit": limit,
                        "reason": reason, "target": str(target)[:200],
                    }, now)
                    self.store.audit("breaker", "TRIPPED", {"ns": self.ns, "kind": kind, "count": n, "limit": limit}, conn=c)
                    return Decision(False, reason, n, limit, True)
                c.execute(
                    "INSERT INTO breaker_events(ns, kind, target, ts) VALUES (?,?,?,?)",
                    (self.ns, kind, str(target)[:512], now),
                )
                return Decision(True, "ok", n + 1, limit, False)
        except Exception as e:  # fail-safe: galat = tolak
            return Decision(False, "BREAKER_ERROR (fail-safe, aksi ditolak): %s" % e.__class__.__name__, -1, limit, False)

    def status(self):
        now = self.clock()
        try:
            c = self.store.conn
            frozen = kv_get(c, FREEZE_KEY)
            tripped = kv_get(c, self.tripped_key)
            counts = dict((k, self._count(c, k, now)) for k in KINDS)
            return {"namespace": self.ns, "frozen": frozen, "tripped": tripped, "counts_last_hour": counts,
                    "limits": dict(self.limits), "t1_enabled": frozen is None and tripped is None}
        except Exception as e:
            return {"namespace": self.ns, "error": e.__class__.__name__, "t1_enabled": False}

    def reset(self, actor, reason):
        """Pulihkan breaker yang trip (hanya dari konsol). Tidak mencabut freeze."""
        with self.store.tx() as c:
            prev = kv_get(c, self.tripped_key)
            kv_del(c, self.tripped_key)
            self.store.audit(actor, "BREAKER_RESET", {"ns": self.ns, "reason": reason, "prev": prev}, conn=c)
        return prev


def freeze(store, actor, reason, clock=time.time):
    """Kill-switch: bekukan seluruh eksekusi otomatis. Idempoten."""
    with store.tx() as c:
        cur = kv_get(c, FREEZE_KEY)
        if cur is None:
            kv_set(c, FREEZE_KEY, {"at": clock(), "by": str(actor)[:64], "reason": str(reason)[:300]}, clock())
        store.audit(actor, "FREEZE", {"reason": reason, "already": cur is not None}, conn=c)
    try:  # FREEZE bersama; gagal menulis berkas tidak membatalkan freeze di store
        path = freeze_file()
        if not os.path.exists(path):
            with open(path, "w") as fh:
                fh.write("%s oleh soc-ir %s: %s\n" % (time.strftime("%F %T", time.localtime(clock())),
                                                      str(actor)[:64], str(reason)[:200].replace("\n", " ")))
    except OSError:
        pass
    return cur is None


def unfreeze(store, actor, reason):
    with store.tx() as c:
        cur = kv_get(c, FREEZE_KEY)
        kv_del(c, FREEZE_KEY)
        store.audit(actor, "UNFREEZE", {"reason": reason, "prev": cur}, conn=c)
    try:
        os.unlink(freeze_file())
    except OSError:
        pass
    return cur


def is_frozen(store):
    """True bila beku ATAU status tidak bisa dibaca (fail-safe)."""
    if os.path.exists(freeze_file()):
        return True
    try:
        return kv_get(store.conn, FREEZE_KEY) is not None
    except Exception:
        return True
