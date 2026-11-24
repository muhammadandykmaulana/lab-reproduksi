# -*- coding: utf-8 -*-
"""Aturan IOC deterministik. Default di sini; /etc/bodyguard/ioc_rules.json (milik root) bisa
menambah/menimpa aturan berdasarkan `id` atau menonaktifkannya lewat "disable": [id, ...].

Regex dijalankan pada data penyerang: tulis pola TANPA quantifier bersarang (hindari ReDoS);
panjang data selalu dibatasi oleh pemindai.
"""

import json
import os
import re

from ..model import SEV_RANK
from ..util import BodyguardError, check_file_secure

DEFAULT_RULES = {
    "content": [
        {"id": "IOC-0XNIX", "severity": "critical", "pattern": r"(?i)0x\s?nix",
         "files": ["php", "image", "other"], "where": ["data", "code"], "desc": "penanda kelompok 0x" "Nix"},
        {"id": "IOC-YOIBRE", "severity": "critical", "pattern": r"(?i)yoi" r"bre",
         "files": ["php", "image", "other"], "where": ["data", "code"], "desc": "penanda yoi" "bre"},
        {"id": "WS-EVAL-DECODE", "severity": "critical",
         "pattern": r"(?i)\b(?:eval|assert)\s*\(\s*(?:@\s*)?(?:base64" r"_decode|gzin" r"flate|gzuncompress|gzdecode|str_rot13|strrev|hex2bin|convert_uudecode)\s*\(",
         "files": ["php", "image", "other"], "where": ["data", "code"], "desc": "eval atas payload ter-encode"},
        {"id": "WS-INPUT-EXEC", "severity": "critical",
         "pattern": r"(?i)\b(?:system|shell" r"_exec|pass" r"thru|exec|popen|proc_open|pcntl_exec|assert|eval)\s*\(\s*(?:@\s*)?\$_(?:GET|POST|REQUEST|COOKIE|SERVER)\b",
         "files": ["php", "image", "other"], "where": ["data", "code"], "desc": "eksekusi langsung dari input HTTP"},
        {"id": "WS-VARFUNC", "severity": "high", "pattern": r"\$_(?:GET|POST|REQUEST|COOKIE)\s*\[[^\]\n]{0,64}\]\s*\(",
         "files": ["php"], "where": ["data", "code"], "desc": "pemanggilan fungsi dari input HTTP"},
        {"id": "WS-FAMILY", "severity": "critical",
         "pattern": r"(?i)(?:File" r"sMan|b3" r"74k|WSO\s?[0-9]|c99s" r"hell|r57s" r"hell|IndoX" r"ploit|Mis" r"ter\s?Spy|Anonym" r"ousFox|0byt" r"3m1n1|alfa\s?team|tinyfilemanager)",
         "files": ["php", "image", "other"], "where": ["data", "code"], "desc": "penanda keluarga webshell"},
        {"id": "WS-UPLOADER", "severity": "high", "pattern": r"(?i)move_uplo" r"aded_file\s*\(\s*\$_FILES",
         "files": ["php"], "where": ["data"], "desc": "uploader di folder data"},
        {"id": "WS-HALT-COMPILER", "severity": "high", "pattern": r"(?i)__halt_" r"compiler\s*\(",
         "files": ["php"], "where": ["data"], "desc": "stub phar di folder data"},
        {"id": "WS-LONG-B64", "severity": "medium", "pattern": r"(?<![A-Za-z0-9+/])[A-Za-z0-9+/]{3000}",
         "files": ["php"], "where": ["data"], "desc": "blob base64 panjang di PHP folder data"},
        # --- IOC insiden STAI Ali (dari web-integrity-cek.sh, webscan-wp.sh, kumpulkan-bukti.sh) ---
        {"id": "IOC-STAI-TOKEN-SHELL", "severity": "critical",
         "pattern": r"(?i)287d723bf150786316df3ec9457cadb4|hash_" r"equals\s*\([^)\n]{0,80}\$_(?:GET|POST|REQUEST)|<<S>>|<<E>>|GH_R0" r"_EXEC|SSInjection|wordpress-svc\.internal",
         "files": ["php", "image", "other"], "where": ["data", "code"], "desc": "webshell token/marker insiden Juli 2026"},
        {"id": "IOC-STAI-0XNIX-ENC", "severity": "critical",
         "pattern": r"(?i)0x" r"Nix Encrypted Code|SPLIT&ENCRYPTed|yoi" r"bre\.com|aHR0cHM6Ly95b2li",
         "files": ["php", "image", "other"], "where": ["data", "code"], "desc": "loader terenkripsi 0x" "Nix/yoi" "bre"},
        {"id": "IOC-STAI-BACKDOOR-NET", "severity": "critical", "pattern": r"(?i)gs-netcat|gsocket",
         "files": ["php", "other"], "where": ["data", "code"], "desc": "backdoor gsocket"},
        {"id": "IOC-STAI-JUDOL", "severity": "high", "pattern": r"(?i)slot\s?gacor|togel",
         "files": ["php"], "where": ["data", "code"], "desc": "injeksi SEO judi"},
        {"id": "WS-CREATE-FUNC", "severity": "high",
         "pattern": r"(?i)create_" r"function\s*\(\s*['\"]['\"]\s*,\s*(?:base64" r"_decode|gzin" r"flate|\$_)",
         "files": ["php"], "where": ["data", "code"], "desc": "create_" "function dengan payload"},
    ],
    "filename": [
        {"id": "FN-DOUBLE-EXT", "severity": "high", "pattern": r"(?i)\.(?:php[0-9]?|phtml|phar|pht)\.[a-z0-9]{1,5}$",
         "desc": "ekstensi ganda .php.xxx"},
        {"id": "FN-IOC", "severity": "critical", "pattern": r"(?i)(?:0xnix|yoi" r"bre)", "desc": "nama file ber-IOC"},
    ],
    "username": [
        {"id": "IOC-WPSVC-ADMIN", "severity": "critical", "pattern": r"(?i)^wpsvc_", "desc": "admin samaran wpsvc_*"},
        {"id": "IOC-USER-STR", "severity": "critical", "pattern": r"(?i)(?:0xnix|yoi" r"bre)", "desc": "username ber-IOC"},
        {"id": "IOC-SVC-LOGIN", "severity": "critical", "pattern": r"(?i)^svc_", "desc": "admin samaran svc_*"},
        {"id": "IOC-EMAIL-INTERNAL", "severity": "critical", "pattern": r"(?i)\.internal$",
         "desc": "email domain .internal (wordpress-svc.internal)"},
    ],
    "plugin": [
        {"id": "IOC-SECHDR-MGR", "severity": "critical", "pattern": r"(?i)^security-headers-manager-[a-z0-9_-]+$",
         "desc": "plugin samaran security-headers-manager-*"},
        {"id": "IOC-PLUGIN-STR", "severity": "critical", "pattern": r"(?i)(?:0xnix|yoi" r"bre)", "desc": "nama plugin ber-IOC"},
        {"id": "IOC-PLUGIN-HEX6", "severity": "high", "pattern": r"^[a-z0-9-]+-[0-9a-f]{6}$",
         "desc": "folder plugin berakhiran hex acak 6 digit (pola samaran insiden)"},
    ],
    "uri": [
        {"id": "ATK-UPLOAD-PHP", "severity": "critical",
         "pattern": r"(?i)/wp-content/uploads/[^?#]*\.(?:php[0-9]?|phtml|phar|pht)(?:[/?#]|$)", "desc": "akses PHP di uploads"},
        {"id": "ATK-DATA-PHP", "severity": "high",
         "pattern": r"(?i)/(?:fonts|ijazah|public|files)/[^?#]*\.(?:php[0-9]?|phtml|phar|pht)(?:[/?#]|$)",
         "desc": "akses PHP di folder data"},
        {"id": "ATK-IOC", "severity": "critical", "pattern": r"(?i)(?:0xnix|yoi" r"bre)", "desc": "string IOC di URI"},
        {"id": "ATK-SECHDR-PLUGIN", "severity": "critical", "pattern": r"(?i)/wp-content/plugins/security-headers-manager-",
         "desc": "akses plugin samaran"},
        {"id": "ATK-SHELL-NAME", "severity": "medium",
         "pattern": r"(?i)/(?:wso|alfa|b3" r"74k|r57|c99|shell|cmd|uploader|bypass|wp-confiq|marijuana|xleet|tinyfilemanager)[a-z0-9_-]{0,16}\.php",
         "desc": "nama webshell umum"},
        {"id": "ATK-STAI-IOC-PATH", "severity": "critical",
         "pattern": r"(?i)asbarin|/shell_[0-9]+\.php|blank\.php\?c=|287d723bf150786316df3ec9457cadb4|GH_R0" r"_EXEC|wpsvc_",
         "desc": "path/parameter IOC insiden STAI Ali"},
        {"id": "ATK-CMD-PARAM", "severity": "medium", "pattern": r"(?i)[?&](?:cmd|exec|command|shell)=", "desc": "parameter perintah"},
    ],
    "php_extensions": [".php", ".php3", ".php4", ".php5", ".php7", ".php8", ".phtml", ".phar", ".pht", ".phps", ".pgif", ".inc"],
    "image_extensions": [".jpg", ".jpeg", ".png", ".gif", ".webp", ".bmp", ".ico", ".tif", ".tiff", ".svg", ".heic", ".avif"],
    "benign_sha256": [],
}

_LISTS = ("content", "filename", "username", "plugin", "uri")
_FILES = frozenset(("php", "image", "other"))
_WHERE = frozenset(("data", "code"))


class RulesError(BodyguardError):
    pass


def _merge(base, extra):
    out = json.loads(json.dumps(base))
    disabled = set(extra.get("disable", []))
    for key in _LISTS:
        by_id = dict((r["id"], r) for r in out.get(key, []))
        order = [r["id"] for r in out.get(key, [])]
        for r in extra.get(key, []):
            if r.get("id") not in by_id:
                order.append(r.get("id"))
            by_id[r.get("id")] = r
        out[key] = [by_id[i] for i in order if i not in disabled]
    for key in ("php_extensions", "image_extensions"):
        if key in extra:
            out[key] = list(extra[key])
    out["benign_sha256"] = list(out.get("benign_sha256", [])) + list(extra.get("benign_sha256", []))
    return out


class RuleSet(object):
    def __init__(self, raw):
        self.raw = raw
        self.content, self.filename, self.username, self.plugin, self.uri = [], [], [], [], []
        for key in _LISTS:
            for r in raw.get(key, []):
                rid = r.get("id")
                if not isinstance(rid, str) or not re.match(r"\A[A-Z0-9-]{3,40}\Z", rid):
                    raise RulesError("id aturan tidak valid: %r" % (rid,))
                if r.get("severity") not in SEV_RANK:
                    raise RulesError("severity aturan %s tidak valid" % rid)
                try:
                    pat = r["pattern"]
                    rx = re.compile(pat.encode("utf-8")) if key == "content" else re.compile(pat)
                except (re.error, KeyError, AttributeError) as e:
                    raise RulesError("regex aturan %s tidak valid: %s" % (rid, e))
                entry = {"id": rid, "severity": r["severity"], "rx": rx, "desc": r.get("desc", "")}
                if key == "content":
                    entry["files"] = frozenset(r.get("files", ["php"])) & _FILES
                    entry["where"] = frozenset(r.get("where", ["data", "code"])) & _WHERE
                getattr(self, key).append(entry)
        self.php_ext = frozenset(e.lower() for e in raw.get("php_extensions", []))
        self.image_ext = frozenset(e.lower() for e in raw.get("image_extensions", []))
        self.benign_sha256 = frozenset(s.lower() for s in raw.get("benign_sha256", []) if re.match(r"\A[0-9a-fA-F]{64}\Z", s))

    def content_hits(self, data, klass, where):
        hits = []
        for r in self.content:
            if klass in r["files"] and where in r["where"]:
                m = r["rx"].search(data)
                if m:
                    hits.append((r, m))
        return hits

    @staticmethod
    def _text_hits(rules, text):
        return [r for r in rules if r["rx"].search(text or "")]

    def filename_hits(self, name):
        return self._text_hits(self.filename, name)

    def username_hits(self, name):
        return self._text_hits(self.username, name)

    def plugin_hits(self, name):
        return self._text_hits(self.plugin, name)

    def uri_hits(self, uri):
        return self._text_hits(self.uri, uri)


def load_rules(path=None, check_perms=True):
    """Muat default + file tambahan. File tidak ada = default saja. File tak aman/rusak = RulesError."""
    raw = DEFAULT_RULES
    if path:
        if os.path.exists(path):
            if check_perms:
                check_file_secure(path, owner_uid=0, forbid_bits=0o022)
            try:
                with open(path, "r", encoding="utf-8") as f:
                    extra = json.load(f)
            except ValueError as e:
                raise RulesError("ioc_rules.json bukan JSON valid: %s" % e)
            if not isinstance(extra, dict):
                raise RulesError("ioc_rules.json harus objek JSON")
            raw = _merge(DEFAULT_RULES, extra)
    return RuleSet(raw)
