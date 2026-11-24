# -*- coding: utf-8 -*-
"""Notifikasi alert (bot ALERT - terpisah dari bot approval). Tidak pernah melempar exception.

Backend:
  telegram : Bot API langsung (BG_ALERT_BOT_TOKEN, BG_ALERT_CHAT_ID dari env systemd).
  command  : notify-run.sh --pesan (SATU pengirim Telegram untuk semua modul; bawaan lab reproduksi).
             Pesan teks polos (sudah disanitasi + defang) dikirim via STDIN, tidak pernah sebagai argumen.
             Token alert (BG_ALERT_BOT_TOKEN/BG_ALERT_CHAT_ID dari env systemd) diteruskan lewat environment,
             tidak lewat argumen, sehingga tidak terlihat di daftar proses.
  log      : hanya log JSON.
Semua pesan juga selalu dicatat ke log. Rate limit mencegah banjir alert.
"""

import logging
import os
import time

from .config import parse_chat_id
from .sanitizer import html_to_plain
from .telegram import TelegramAPI
from .util import SAFE_ENV, log_event, redact, run_argv


class Notifier(object):
    def __init__(self, backend, store, api=None, chat_id=None, command=None, max_per_hour=30, urgent_max=20,
                 clock=time.time, runner=run_argv):
        self.backend = backend
        self.store = store
        self.api = api
        self.chat_id = chat_id
        self.command = list(command or [])
        self.max_per_hour = max_per_hour
        self.urgent_max = urgent_max
        self.clock = clock
        self.runner = runner
        self.sent = []  # jejak in-memory (berguna untuk dry-run/tes)

    @classmethod
    def from_config(cls, cfg, store, environ=None, clock=time.time):
        environ = os.environ if environ is None else environ
        backend, api, chat = cfg.notify_backend, None, None
        if backend == "telegram":
            try:
                api = TelegramAPI(environ.get("BG_ALERT_BOT_TOKEN", ""))
                chat = parse_chat_id(environ.get("BG_ALERT_CHAT_ID", ""), "BG_ALERT_CHAT_ID")
            except Exception as e:
                log_event(logging.WARNING, "alert Telegram nonaktif, jatuh ke log", err=redact(str(e))[:200])
                backend = "log"
        return cls(backend, store, api, chat, cfg.notify_command, cfg.notify_max_per_hour,
                   cfg.notify_urgent_max_per_hour, clock)

    def send(self, html_text, urgent=False):
        kind = "urgent" if urgent else "normal"
        now = self.clock()
        plain = html_to_plain(html_text)
        self.sent.append({"urgent": urgent, "text": plain})
        try:
            limit = self.urgent_max if urgent else self.max_per_hour
            if self.store.notify_count(kind, now - 3600) >= limit:
                log_event(logging.WARNING, "notifikasi ditahan rate-limit", kind=kind, text=plain[:500])
                return False
            self.store.notify_record(kind, now)
        except Exception as e:
            log_event(logging.WARNING, "rate-limit notifikasi tak terbaca; tetap mencoba kirim", err=e.__class__.__name__)
        log_event(logging.WARNING if urgent else logging.INFO, "notifikasi", urgent=urgent, text=plain[:1500])
        try:
            if self.backend == "telegram" and self.api is not None:
                self.api.send_message(self.chat_id, html_text)
                return True
            if self.backend == "command" and self.command:
                env = dict(SAFE_ENV)
                for k in ("BG_ALERT_BOT_TOKEN", "BG_ALERT_CHAT_ID", "TELEGRAM_API_BASE"):
                    if os.environ.get(k):
                        env[k] = os.environ[k]
                rc, _out, err = self.runner(self.command, timeout=60, input_bytes=plain.encode("utf-8"), env=env)
                if rc != 0:
                    log_event(logging.WARNING, "notify command rc!=0", rc=rc, err=redact(err[-200:].decode("utf-8", "replace")))
                return rc == 0
        except Exception as e:
            log_event(logging.WARNING, "notifikasi gagal terkirim", err=redact(str(e))[:200])
        return False
