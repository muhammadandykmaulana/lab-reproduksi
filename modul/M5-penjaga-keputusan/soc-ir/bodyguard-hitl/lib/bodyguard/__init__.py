# -*- coding: utf-8 -*-
"""Bodyguard HITL - penjaga server produksi STAI Ali.

Sistem deterministik berjenjang T0-T3:
  T0 amati (selalu jalan), T1 otomatis ber-TTL & reversibel (dibatasi circuit breaker),
  T2 butuh persetujuan 1 orang via bot Telegram terpisah, T3 manual (checklist saja).

Hanya memakai pustaka standar Python 3 (target minimum 3.6) agar tidak perlu pip di server.
LLM (bila dipakai) HANYA penasihat read-only: tidak ada jalur dari keluaran LLM ke eksekusi.
"""

__version__ = "1.0.2"
