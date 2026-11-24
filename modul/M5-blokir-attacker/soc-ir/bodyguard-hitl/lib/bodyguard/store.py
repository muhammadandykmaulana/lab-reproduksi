# -*- coding: utf-8 -*-
"""Penyimpanan status (SQLite, WAL, transaksi BEGIN IMMEDIATE untuk operasi cek-lalu-tulis atomik).

Lokasi produksi: /var/lib/bodyguard/state.db (guard:guard 0600).
"""

import contextlib
import json
import os
import sqlite3
import time

SCHEMA_VERSION = 1

SCHEMA = (
    "CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT)",
    "CREATE TABLE IF NOT EXISTS kv (key TEXT PRIMARY KEY, value TEXT NOT NULL, updated_at REAL NOT NULL)",
    "CREATE TABLE IF NOT EXISTS breaker_events (id INTEGER PRIMARY KEY AUTOINCREMENT, ns TEXT NOT NULL,"
    " kind TEXT NOT NULL, target TEXT, ts REAL NOT NULL)",
    "CREATE INDEX IF NOT EXISTS ix_breaker ON breaker_events(ns, kind, ts)",
    "CREATE TABLE IF NOT EXISTS incidents (id TEXT PRIMARY KEY, created_at REAL NOT NULL, mode TEXT NOT NULL,"
    " summary_json TEXT NOT NULL)",
    "CREATE TABLE IF NOT EXISTS findings (id INTEGER PRIMARY KEY AUTOINCREMENT, incident_id TEXT NOT NULL,"
    " kind TEXT NOT NULL, severity TEXT NOT NULL, target TEXT, site TEXT, rules TEXT, detail_json TEXT,"
    " created_at REAL NOT NULL)",
    "CREATE INDEX IF NOT EXISTS ix_findings_inc ON findings(incident_id)",
    "CREATE TABLE IF NOT EXISTS actions (id INTEGER PRIMARY KEY AUTOINCREMENT, incident_id TEXT,"
    " tier TEXT NOT NULL, kind TEXT NOT NULL, target TEXT NOT NULL, status TEXT NOT NULL, ns TEXT NOT NULL,"
    " detail_json TEXT, rollback TEXT, created_at REAL NOT NULL, updated_at REAL NOT NULL, expires_at REAL)",
    "CREATE INDEX IF NOT EXISTS ix_actions_target ON actions(kind, target, ns, status)",
    "CREATE TABLE IF NOT EXISTS approvals (request_id TEXT PRIMARY KEY, incident_id TEXT,"
    " action_kind TEXT NOT NULL, action_json TEXT NOT NULL, action_sha256 TEXT NOT NULL,"
    " dedupe_key TEXT NOT NULL, status TEXT NOT NULL, nonce TEXT UNIQUE, issued_ts INTEGER,"
    " expires_ts INTEGER, chat_id INTEGER, message_id INTEGER, decided_by INTEGER, decided_at REAL,"
    " decision_payload TEXT, result_json TEXT, created_at REAL NOT NULL, updated_at REAL NOT NULL)",
    "CREATE INDEX IF NOT EXISTS ix_appr_status ON approvals(status)",
    "CREATE INDEX IF NOT EXISTS ix_appr_dedupe ON approvals(dedupe_key)",
    "CREATE TABLE IF NOT EXISTS audit (id INTEGER PRIMARY KEY AUTOINCREMENT, ts REAL NOT NULL,"
    " actor TEXT NOT NULL, event TEXT NOT NULL, detail_json TEXT)",
    "CREATE TABLE IF NOT EXISTS file_cache (path BLOB PRIMARY KEY, sig TEXT NOT NULL, verdict TEXT NOT NULL,"
    " scanned_at REAL NOT NULL)",
    "CREATE TABLE IF NOT EXISTS log_offsets (path TEXT PRIMARY KEY, ino INTEGER NOT NULL,"
    " offset INTEGER NOT NULL, updated_at REAL NOT NULL)",
    "CREATE TABLE IF NOT EXISTS notify_events (id INTEGER PRIMARY KEY AUTOINCREMENT, ts REAL NOT NULL,"
    " kind TEXT NOT NULL)",
    "CREATE TABLE IF NOT EXISTS alert_seen (fp TEXT PRIMARY KEY, first_seen REAL NOT NULL,"
    " last_alerted REAL NOT NULL)",
)


def kv_get(conn, key):
    row = conn.execute("SELECT value FROM kv WHERE key=?", (key,)).fetchone()
    if row is None:
        return None
    try:
        return json.loads(row[0])
    except ValueError:
        # Nilai rusak diperlakukan sebagai "ada" agar status keamanan (freeze/tripped) tidak hilang.
        return {"corrupt": True}


def kv_set(conn, key, value, now=None):
    # INSERT OR REPLACE (bukan UPSERT) agar jalan di SQLite lama (< 3.24, mis. Ubuntu 18.04).
    conn.execute(
        "INSERT OR REPLACE INTO kv(key, value, updated_at) VALUES (?,?,?)",
        (key, json.dumps(value, ensure_ascii=True, sort_keys=True), time.time() if now is None else now),
    )


def kv_del(conn, key):
    conn.execute("DELETE FROM kv WHERE key=?", (key,))


class Store(object):
    def __init__(self, path, clock=time.time):
        self.path = path
        self.clock = clock
        new_file = not os.path.exists(path)
        self.conn = sqlite3.connect(path, timeout=30, isolation_level=None, check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        if new_file:
            try:
                os.chmod(path, 0o660)  # grup guard: pemindai + gatekeeper
            except OSError:
                pass
        self.conn.execute("PRAGMA busy_timeout=30000")
        self.conn.execute("PRAGMA journal_mode=WAL")
        self.conn.execute("PRAGMA synchronous=FULL")
        self._migrate()

    def _migrate(self):
        with self.tx() as c:
            for stmt in SCHEMA:
                c.execute(stmt)
            row = c.execute("SELECT value FROM meta WHERE key='schema_version'").fetchone()
            if row is None:
                c.execute("INSERT INTO meta(key, value) VALUES ('schema_version', ?)", (str(SCHEMA_VERSION),))

    @contextlib.contextmanager
    def tx(self):
        """Transaksi BEGIN IMMEDIATE: mengunci penulis lain sehingga cek-lalu-tulis atomik antar proses."""
        self.conn.execute("BEGIN IMMEDIATE")
        try:
            yield self.conn
        except BaseException:
            self.conn.execute("ROLLBACK")
            raise
        else:
            self.conn.execute("COMMIT")

    def close(self):
        try:
            self.conn.close()
        except Exception:
            pass

    # ---- audit -----------------------------------------------------------------------------
    def audit(self, actor, event, detail=None, conn=None):
        c = conn or self.conn
        c.execute(
            "INSERT INTO audit(ts, actor, event, detail_json) VALUES (?,?,?,?)",
            (self.clock(), str(actor)[:64], str(event)[:64], json.dumps(detail or {}, ensure_ascii=True, default=str)),
        )

    # ---- kv shortcut -------------------------------------------------------------------------
    def get(self, key):
        return kv_get(self.conn, key)

    def set(self, key, value):
        with self.tx() as c:
            kv_set(c, key, value, self.clock())

    # ---- actions -----------------------------------------------------------------------------
    def add_action(self, incident_id, tier, kind, target_key, status, ns, detail=None, rollback=None, expires_at=None):
        now = self.clock()
        with self.tx() as c:
            cur = c.execute(
                "INSERT INTO actions(incident_id, tier, kind, target, status, ns, detail_json, rollback, created_at,"
                " updated_at, expires_at) VALUES (?,?,?,?,?,?,?,?,?,?,?)",
                (incident_id, tier, kind, target_key, status, ns,
                 json.dumps(detail or {}, ensure_ascii=True, default=str), rollback, now, now, expires_at),
            )
            return cur.lastrowid

    def find_action(self, kind, target_key, ns, statuses, active_at=None):
        q = "SELECT * FROM actions WHERE kind=? AND target=? AND ns=? AND status IN (%s)" % ",".join("?" * len(statuses))
        args = [kind, target_key, ns] + list(statuses)
        if active_at is not None:
            q += " AND (expires_at IS NULL OR expires_at > ?)"
            args.append(active_at)
        q += " ORDER BY id DESC LIMIT 1"
        return self.conn.execute(q, args).fetchone()

    def expire_blocks(self, now=None):
        now = self.clock() if now is None else now
        with self.tx() as c:
            c.execute(
                "UPDATE actions SET status='EXPIRED', updated_at=? WHERE kind='BLOCK_IP' AND status IN ('BLOCKED','DRYRUN')"
                " AND expires_at IS NOT NULL AND expires_at <= ?", (now, now))

    # ---- approvals -----------------------------------------------------------------------------
    def approval_by_dedupe(self, dedupe_key, statuses, since=None):
        q = "SELECT * FROM approvals WHERE dedupe_key=? AND status IN (%s)" % ",".join("?" * len(statuses))
        args = [dedupe_key] + list(statuses)
        if since is not None:
            q += " AND updated_at >= ?"
            args.append(since)
        q += " ORDER BY created_at DESC LIMIT 1"
        return self.conn.execute(q, args).fetchone()

    def insert_approval(self, request_id, incident_id, action_kind, action_json, action_sha256, dedupe_key, status):
        now = self.clock()
        with self.tx() as c:
            c.execute(
                "INSERT INTO approvals(request_id, incident_id, action_kind, action_json, action_sha256, dedupe_key,"
                " status, created_at, updated_at) VALUES (?,?,?,?,?,?,?,?,?)",
                (request_id, incident_id, action_kind, action_json, action_sha256, dedupe_key, status, now, now),
            )

    def approval(self, request_id):
        return self.conn.execute("SELECT * FROM approvals WHERE request_id=?", (request_id,)).fetchone()

    def approval_by_nonce(self, nonce):
        return self.conn.execute("SELECT * FROM approvals WHERE nonce=?", (nonce,)).fetchone()

    def approvals_with_status(self, statuses, limit=50):
        q = "SELECT * FROM approvals WHERE status IN (%s) ORDER BY created_at ASC LIMIT ?" % ",".join("?" * len(statuses))
        return self.conn.execute(q, list(statuses) + [limit]).fetchall()

    # ---- notify rate limit --------------------------------------------------------------------
    def notify_count(self, kind, since):
        return self.conn.execute("SELECT COUNT(*) FROM notify_events WHERE kind=? AND ts>?", (kind, since)).fetchone()[0]

    def notify_record(self, kind, now):
        with self.tx() as c:
            c.execute("INSERT INTO notify_events(ts, kind) VALUES (?,?)", (now, kind))
            c.execute("DELETE FROM notify_events WHERE ts < ?", (now - 7 * 86400,))

    # ---- cache pindai file ----------------------------------------------------------------------
    def cache_get(self, path_b):
        row = self.conn.execute("SELECT sig, verdict FROM file_cache WHERE path=?", (path_b,)).fetchone()
        return (row[0], row[1]) if row else (None, None)

    def cache_put_many(self, items, now):
        """items: list (path_b, sig, verdict). Ditulis per batch agar cepat untuk ratusan ribu file."""
        if not items:
            return
        with self.tx() as c:
            c.executemany("INSERT OR REPLACE INTO file_cache(path, sig, verdict, scanned_at) VALUES (?,?,?,?)",
                          [(p, s, v, now) for p, s, v in items])

    # ---- alert de-dup --------------------------------------------------------------------------
    def should_alert(self, fp, now, realert_after):
        """True bila sidik jari temuan belum pernah dialertkan atau sudah lewat realert_after detik."""
        with self.tx() as c:
            row = c.execute("SELECT last_alerted FROM alert_seen WHERE fp=?", (fp,)).fetchone()
            if row is None:
                c.execute("INSERT INTO alert_seen(fp, first_seen, last_alerted) VALUES (?,?,?)", (fp, now, now))
                return True
            if now - row[0] >= realert_after:
                c.execute("UPDATE alert_seen SET last_alerted=? WHERE fp=?", (now, fp))
                return True
            return False
