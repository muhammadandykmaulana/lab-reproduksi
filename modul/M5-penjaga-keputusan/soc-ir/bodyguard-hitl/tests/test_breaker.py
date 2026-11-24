# -*- coding: utf-8 -*-
"""Uji Circuit Breaker: 20 blokir IP/jam, 5 chmod/jam, latch ke T0, isolasi dry-run, atomik antar-proses."""

import multiprocessing
import os
import unittest

import _common
from bodyguard import breaker as B
from bodyguard.store import Store, kv_set

LIMITS = {"ip_block": 20, "chmod": 5}


def _worker(args):
    db, n = args
    st = Store(db)
    br = B.CircuitBreaker(st, LIMITS, "live")
    allowed = sum(1 for i in range(n) if br.acquire("ip_block", "198.51.100.%d" % i).allowed)
    st.close()
    return allowed


class TestBreaker(unittest.TestCase):
    def setUp(self):
        self.tmp = _common.make_tmpdir()
        self.db = os.path.join(self.tmp, "state.db")
        self.clock = _common.FakeClock()
        self.store = Store(self.db, clock=self.clock)
        self.live = B.CircuitBreaker(self.store, LIMITS, "live", clock=self.clock)

    def tearDown(self):
        self.store.close()
        _common.rmtree(self.tmp)

    def test_twenty_ip_blocks_then_trip_on_21st(self):
        for i in range(20):
            d = self.live.acquire("ip_block", "203.0.113.%d" % i)
            self.assertTrue(d.allowed, d.reason)
            self.assertEqual(d.count, i + 1)
        d = self.live.acquire("ip_block", "203.0.113.200")
        self.assertFalse(d.allowed)
        self.assertTrue(d.tripped_now, "trip harus terjadi tepat pada percobaan ke-21")
        self.assertIn("T0", d.reason)
        d2 = self.live.acquire("ip_block", "203.0.113.201")
        self.assertFalse(d2.allowed)
        self.assertFalse(d2.tripped_now, "alert darurat hanya sekali per trip")
        self.assertTrue(d2.reason.startswith("BREAKER_TRIPPED"))

    def test_five_chmod_then_trip_on_6th_and_whole_t1_goes_t0(self):
        for i in range(5):
            self.assertTrue(self.live.acquire("chmod", "/x/%d.php" % i).allowed)
        d = self.live.acquire("chmod", "/x/6.php")
        self.assertFalse(d.allowed)
        self.assertTrue(d.tripped_now)
        # Seluruh T1 beralih ke T0: blokir IP pun ditolak.
        self.assertFalse(self.live.acquire("ip_block", "203.0.113.1").allowed)
        self.assertFalse(self.live.status()["t1_enabled"])

    def test_sliding_window(self):
        for i in range(19):
            self.assertTrue(self.live.acquire("ip_block", "a%d" % i).allowed)
        self.clock.advance(1800)
        self.assertTrue(self.live.acquire("ip_block", "b").allowed)          # ke-20 dalam 60 menit
        self.assertTrue(self.live.acquire("ip_block", "c").tripped_now)      # ke-21 -> trip

    def test_window_expiry_without_trip(self):
        for i in range(20):
            self.assertTrue(self.live.acquire("ip_block", "a%d" % i).allowed)
        self.clock.advance(3601)
        d = self.live.acquire("ip_block", "baru")
        self.assertTrue(d.allowed, d.reason)
        self.assertEqual(d.count, 1)

    def test_trip_is_latched_until_manual_reset(self):
        for i in range(6):
            self.live.acquire("chmod", "f%d" % i)
        self.clock.advance(7 * 3600)
        self.assertFalse(self.live.acquire("chmod", "nanti").allowed, "trip tidak boleh pulih sendiri")
        prev = self.live.reset("admin-konsol", "sudah diverifikasi")
        self.assertIsNotNone(prev)
        self.assertTrue(self.live.acquire("chmod", "setelah-reset").allowed)

    def test_dryrun_namespace_isolated(self):
        dry = B.CircuitBreaker(self.store, LIMITS, "dryrun", clock=self.clock)
        for i in range(6):
            dry.acquire("chmod", "f%d" % i)
        self.assertFalse(dry.status()["t1_enabled"])
        self.assertTrue(self.live.status()["t1_enabled"], "simulasi tidak boleh mengubah status live")
        self.assertTrue(self.live.acquire("chmod", "live").allowed)

    def test_freeze_blocks_everything_and_persists(self):
        self.assertTrue(B.freeze(self.store, "tg:123", "uji"))
        self.assertFalse(B.freeze(self.store, "tg:123", "uji lagi"))  # idempoten
        self.assertTrue(B.is_frozen(self.store))
        dry = B.CircuitBreaker(self.store, LIMITS, "dryrun", clock=self.clock)
        self.assertTrue(self.live.acquire("ip_block", "x").reason.startswith("FROZEN"))
        self.assertFalse(dry.acquire("chmod", "x").allowed)
        other = Store(self.db)  # proses lain melihat status yang sama
        self.assertTrue(B.is_frozen(other))
        other.close()
        B.unfreeze(self.store, "konsol", "aman")
        self.assertTrue(self.live.acquire("ip_block", "x").allowed)

    def test_corrupt_state_fails_closed(self):
        with self.store.tx() as c:
            kv_set(c, self.live.tripped_key, "x")
            c.execute("UPDATE kv SET value='{rusak' WHERE key=?", (self.live.tripped_key,))
        self.assertFalse(self.live.acquire("ip_block", "x").allowed)

    def test_db_error_fails_closed(self):
        self.store.conn.close()
        d = self.live.acquire("ip_block", "x")
        self.assertFalse(d.allowed)
        self.assertIn("BREAKER_ERROR", d.reason)
        self.assertTrue(B.is_frozen(self.store), "status tak terbaca harus dianggap beku")
        self.store = Store(self.db)

    def test_concurrent_processes_never_exceed_limit(self):
        ctx = multiprocessing.get_context("fork")
        with ctx.Pool(8) as pool:
            results = pool.map(_worker, [(self.db, 10)] * 8)
        self.assertEqual(sum(results), 20, "80 percobaan paralel -> tepat 20 yang diizinkan")
        st = Store(self.db)
        self.assertIsNotNone(st.get("breaker:live:tripped"))
        st.close()


if __name__ == "__main__":
    unittest.main()
