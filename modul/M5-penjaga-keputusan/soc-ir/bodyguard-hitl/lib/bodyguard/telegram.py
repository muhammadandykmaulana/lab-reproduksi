# -*- coding: utf-8 -*-
"""Klien minimal Telegram Bot API (urllib stdlib, TLS terverifikasi).

* Token tidak pernah masuk ke pesan galat/log (URL berisi token tidak pernah dicetak).
* Transport bisa disuntikkan untuk pengujian tanpa jaringan.
"""

import json
import re
import socket
import ssl
import urllib.error
import urllib.request

from .util import redact

API_BASE = "https://api.telegram.org"
TOKEN_RE = re.compile(r"\A\d{5,15}:[A-Za-z0-9_-]{30,64}\Z")
MAX_TEXT = 4096


class TelegramError(Exception):
    pass


def _u16len(text):
    return len(text.encode("utf-16-le", "surrogatepass")) // 2


def _fit(text):
    """Telegram membatasi 4096 unit UTF-16 (emoji = 2). Jaring pengaman terakhir dengan margin."""
    if _u16len(text) <= MAX_TEXT - 96:
        return text, "HTML"
    plain = re.sub(r"<[^>]{1,40}>", "", text)
    while _u16len(plain) > MAX_TEXT - 96:
        plain = plain[:int(len(plain) * 0.9)]
    return plain + "\n...[dipotong]", None


class TelegramAPI(object):
    def __init__(self, token, timeout=30, transport=None):
        if transport is None and (not token or not TOKEN_RE.match(token)):
            raise TelegramError("token bot kosong atau formatnya tidak valid")
        self._token = token
        self._timeout = timeout
        self._transport = transport or self._http
        self._ctx = ssl.create_default_context()

    def _http(self, method, params, timeout):
        url = "%s/bot%s/%s" % (API_BASE, self._token, method)
        data = json.dumps(params, ensure_ascii=True).encode("utf-8")
        req = urllib.request.Request(url, data=data, headers={"Content-Type": "application/json"}, method="POST")
        try:
            with urllib.request.urlopen(req, timeout=timeout, context=self._ctx) as r:
                body = r.read(4 * 1024 * 1024)
        except urllib.error.HTTPError as e:
            try:
                body = e.read(65536)
            except Exception:
                raise TelegramError("HTTP %d" % e.code)
        except (urllib.error.URLError, socket.timeout, ssl.SSLError, OSError) as e:
            raise TelegramError("jaringan: %s" % e.__class__.__name__)
        try:
            return json.loads(body.decode("utf-8"))
        except ValueError:
            raise TelegramError("respons bukan JSON")

    def call(self, method, params, timeout=None):
        resp = self._transport(method, params, timeout or self._timeout)
        if not isinstance(resp, dict) or not resp.get("ok"):
            desc = resp.get("description", "?") if isinstance(resp, dict) else "?"
            raise TelegramError("%s gagal: %s" % (method, redact(desc)[:200]))
        return resp.get("result")

    def get_updates(self, offset, timeout=25):
        res = self.call("getUpdates", {"offset": int(offset), "timeout": int(timeout),
                                       "allowed_updates": ["message", "callback_query"]}, timeout=timeout + 15)
        return res if isinstance(res, list) else []

    def send_message(self, chat_id, text, reply_markup=None):
        text, mode = _fit(text)
        p = {"chat_id": chat_id, "text": text, "disable_web_page_preview": True}
        if mode:
            p["parse_mode"] = mode
        if reply_markup is not None:
            p["reply_markup"] = reply_markup
        return self.call("sendMessage", p)

    def edit_message_text(self, chat_id, message_id, text, reply_markup=None):
        text, mode = _fit(text)
        p = {"chat_id": chat_id, "message_id": message_id, "text": text, "disable_web_page_preview": True}
        if mode:
            p["parse_mode"] = mode
        if reply_markup is not None:
            p["reply_markup"] = reply_markup
        return self.call("editMessageText", p)

    def answer_callback(self, callback_query_id, text, alert=False):
        return self.call("answerCallbackQuery", {"callback_query_id": callback_query_id,
                                                 "text": text[:190], "show_alert": bool(alert)})
