# -*- coding: utf-8 -*-
"""Uji HMAC callback Telegram: valid, tamper, replay-binding, kedaluwarsa = TOLAK, batas 64 byte."""

import os
import unittest

import _common  # noqa: F401
from bodyguard import signing as G

KEY = bytes(range(32))
REQ = "REQ-0123456789ab"
SHA = "a" * 64
CHAT = -1001234567890
TS = 1800000000


class TestSigning(unittest.TestCase):
    def setUp(self):
        self.s = G.Signer(KEY)
        self.nonce = G.new_nonce()

    def cb(self, decision="A", ts=TS):
        return self.s.make_callback(decision, self.nonce, ts, REQ, SHA, CHAT)

    def verify(self, data, req=REQ, sha=SHA, chat=CHAT, issued=TS, now=TS + 60, signer=None):
        return (signer or self.s).verify(G.parse_callback(data), req, sha, chat, issued, now)

    def test_key_requirements(self):
        with self.assertRaises(ValueError):
            G.parse_key("abcd")
        with self.assertRaises(ValueError):
            G.parse_key("zz" * 32)
        self.assertEqual(len(G.parse_key("ab" * 32)), 32)
        with self.assertRaises(ValueError):
            G.Signer(b"pendek")

    def test_fits_telegram_limit_and_format(self):
        for d in ("A", "R"):
            data = self.cb(d)
            self.assertLessEqual(len(data.encode()), 64)
            self.assertIsNotNone(G.parse_callback(data))

    def test_valid_approve_and_reject(self):
        self.assertTrue(self.verify(self.cb("A")).ok)
        self.assertTrue(self.verify(self.cb("R")).ok)

    def test_decision_swap_detected(self):
        a = self.cb("A")
        forged = a.replace("1.A.", "1.R.", 1)
        self.assertEqual(self.verify(forged).status, "BAD_SIG")
        r = self.cb("R")
        self.assertEqual(self.verify(r.replace("1.R.", "1.A.", 1)).status, "BAD_SIG")

    def test_field_tampering_detected(self):
        a = self.cb("A")
        parts = a.split(".")
        other_nonce = G.new_nonce()
        self.assertEqual(self.verify(".".join(parts[:2] + [other_nonce] + parts[3:])).status, "BAD_SIG")
        self.assertEqual(self.verify(".".join(parts[:3] + ["%010d" % (TS + 1)] + parts[4:]), issued=TS + 1).status, "BAD_SIG")
        sig = parts[4]
        flipped = ("B" if sig[0] != "B" else "C") + sig[1:]
        self.assertEqual(self.verify(".".join(parts[:4] + [flipped])).status, "BAD_SIG")

    def test_binding_to_request_action_chat_and_key(self):
        a = self.cb("A")
        self.assertEqual(self.verify(a, req="REQ-ffffffffffff").status, "BAD_SIG")
        self.assertEqual(self.verify(a, sha="b" * 64).status, "BAD_SIG", "aksi diubah setelah terbit")
        self.assertEqual(self.verify(a, chat=CHAT + 1).status, "BAD_SIG")
        self.assertEqual(self.verify(a, signer=G.Signer(os.urandom(32))).status, "BAD_SIG")

    def test_ttl_expiry_is_reject(self):
        a = self.cb("A")
        self.assertTrue(self.verify(a, now=TS + 1800).ok)
        r = self.verify(a, now=TS + 1801)
        self.assertFalse(r.ok)
        self.assertEqual(r.status, "EXPIRED")

    def test_future_and_mismatched_timestamp(self):
        a = self.cb("A")
        self.assertEqual(self.verify(a, now=TS - 120).status, "FUTURE_TS")
        self.assertEqual(self.verify(a, issued=TS - 5).status, "TS_MISMATCH")
        self.assertEqual(self.verify(a, issued=None).status, "TS_MISMATCH")

    def test_signature_checked_before_time(self):
        forged = self.cb("A").replace("1.A.", "1.R.", 1)
        self.assertEqual(self.verify(forged, now=TS + 99999).status, "BAD_SIG")

    def test_malformed_payloads(self):
        good = self.cb("A")
        for bad in ("", "1.X." + good[4:], good + "x", good.replace(".", ":"), "2" + good[1:],
                    good[:-1] + "=", "1.A.\u00e9" + good[5:], "A" * 65, None, 123):
            self.assertIsNone(G.parse_callback(bad), repr(bad))
        self.assertEqual(self.s.verify(None, REQ, SHA, CHAT, TS, TS).status, "MALFORMED")

    def test_nonce_entropy_and_uniqueness(self):
        seen = set(G.new_nonce() for _ in range(2000))
        self.assertEqual(len(seen), 2000)


if __name__ == "__main__":
    unittest.main()
