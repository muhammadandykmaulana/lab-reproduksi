#!/usr/bin/python3 -I
# -*- coding: utf-8 -*-
"""gatekeeper_bot.py - Telegram Approval Gatekeeper Bodyguard HITL (bot TERPISAH dari bot alert).

Dijalankan systemd (bodyguard-gatekeeper.service) sebagai user `guard` dengan
EnvironmentFile=/etc/bodyguard/gatekeeper.env (root:root 0600) yang berisi:
  BG_APPROVAL_BOT_TOKEN  token bot approval (BUKAN token bot alert)
  BG_APPROVAL_CHAT_ID    chat/grup tempat permintaan T2 dikirim
  BG_APPROVER_IDS        allowlist user_id Telegram yang boleh menyetujui (dipisah koma)
  BG_HMAC_KEY            kunci HMAC hex >= 64 karakter (openssl rand -hex 32)

Opsi:
  --check   validasi konfigurasi & rahasia lalu keluar (tanpa jaringan)
  --once    satu putaran polling (untuk uji)
"""

import argparse
import logging
import os
import signal
import sys
import time

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.realpath(__file__))), "lib"))

from bodyguard.config import check_env_file, load_config, parse_approvers, parse_chat_id  # noqa: E402
from bodyguard.gatekeeper import Gatekeeper  # noqa: E402
from bodyguard.signing import Signer, parse_key  # noqa: E402
from bodyguard.store import Store  # noqa: E402
from bodyguard.t2 import T2Executor  # noqa: E402
from bodyguard.telegram import TelegramAPI  # noqa: E402
from bodyguard.util import LOG, log_event, redact, setup_logging  # noqa: E402

EX_CONFIG = 78
_STOP = [False]


def _load_secrets(cfg):
    check_env_file(cfg.gatekeeper_env_file)
    env = os.environ
    token = env.get("BG_APPROVAL_BOT_TOKEN", "")
    alert_token = env.get("BG_ALERT_BOT_TOKEN", "")
    if alert_token and alert_token == token:
        raise ValueError("bot approval WAJIB berbeda dari bot alert")
    chat_id = parse_chat_id(env.get("BG_APPROVAL_CHAT_ID", ""), "BG_APPROVAL_CHAT_ID")
    approvers = parse_approvers(env.get("BG_APPROVER_IDS", ""))
    if not approvers:
        raise ValueError("BG_APPROVER_IDS kosong - tidak ada yang boleh menyetujui (fail-closed)")
    key = parse_key(env.get("BG_HMAC_KEY", ""))
    for name in ("BG_APPROVAL_BOT_TOKEN", "BG_HMAC_KEY", "BG_APPROVER_IDS", "BG_ALERT_BOT_TOKEN"):
        env.pop(name, None)  # kurangi paparan rahasia di environment proses
    return token, chat_id, approvers, key


def main(argv=None):
    ap = argparse.ArgumentParser(description="Telegram Approval Gatekeeper (Bodyguard HITL)")
    ap.add_argument("--config", default="/etc/bodyguard/bodyguard.conf")
    ap.add_argument("--check", action="store_true")
    ap.add_argument("--once", action="store_true")
    args = ap.parse_args(argv)
    os.umask(0o007)  # state/log dibagi grup guard (pemindai + gatekeeper), tertutup untuk lainnya

    try:
        cfg = load_config(args.config)
    except Exception as e:
        sys.stderr.write("config tidak valid: %s\n" % redact(str(e)))
        return EX_CONFIG
    setup_logging(cfg.log_file)
    try:
        token, chat_id, approvers, key = _load_secrets(cfg)
        api = TelegramAPI(token, timeout=cfg.poll_timeout + 20)
    except Exception as e:
        LOG.critical("gatekeeper menolak start: %s", redact(str(e)))
        return EX_CONFIG
    if args.check:
        log_event(logging.INFO, "konfigurasi gatekeeper valid", approvers=len(approvers), mode=cfg.mode)
        return 0

    store = Store(os.path.join(cfg.state_dir, "state.db"))
    gk = Gatekeeper(cfg, store, api, Signer(key), approvers, chat_id, T2Executor(cfg, store))
    gk.recover_after_restart()
    signal.signal(signal.SIGTERM, lambda *_: _STOP.__setitem__(0, True))
    log_event(logging.INFO, "gatekeeper aktif", approvers=len(approvers), mode=cfg.mode, ttl=cfg.t2_ttl)
    backoff = 1
    while not _STOP[0]:
        try:
            n = gk.poll_once()
            backoff = 1 if n >= 0 else min(backoff * 2, 60)
            if n < 0:
                time.sleep(backoff)
        except Exception as e:
            LOG.error("putaran gatekeeper gagal: %s", e.__class__.__name__)
            time.sleep(5)
        if args.once:
            break
    store.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
