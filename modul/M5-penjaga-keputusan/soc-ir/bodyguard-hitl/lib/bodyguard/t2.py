# -*- coding: utf-8 -*-
"""Eksekutor T2 - HANYA dipanggil gatekeeper setelah persetujuan Telegram ber-HMAC terverifikasi.

Setiap aksi memvalidasi ULANG parameternya (jangan percaya isi DB begitu saja) dan reversibel:
  QUARANTINE_FILE       -> bg-root quarantine (terikat SHA256 yang disetujui; rename tanpa .php; root:root 000)
  DISABLE_PLUGIN        -> bg-root plugin-disable (rename folder plugin; isi tidak dihapus)
  DISABLE_WP_USER       -> cabut role (wp_capabilities = a:0:{}), user_level 0, hapus sesi aktif
  DISABLE_OJS_USER      -> users.disabled = 1 (+ opsional logout sesi)
  ACCEPT_INTEGRITY_BASELINE -> bg-root integrity-accept (perintah tetap di root.conf), hanya bila set
                             perubahan masih sama dengan saat diusulkan
  CF_APPROVE            -> bg-root cf-approve -> cf-guard.py approve <id> (usulan blokir/lepas blokir dari cf-guard;
                           gerbang ini satu-satunya tempat persetujuan T2 untuk semua modul)
  NOOP_TEST             -> uji alur persetujuan end-to-end tanpa aksi
Tidak ada DELETE/DROP/rm. Setiap hasil menyimpan perintah rollback untuk admin.
"""

import logging
import os
import re
import time

from .mysqlcli import HEX_RE, MySQLCLI
from .rootcall import call_bg_root
from .sanitizer import clean
from .util import INCIDENT_RE, BodyguardError, SecurityError, log_event, run_argv

SHA256_RE = re.compile(r"\A[0-9a-f]{64}\Z")
LOGIN_MAX = 120

ACTION_LABELS = {
    "QUARANTINE_FILE": "Karantina permanen file",
    "DISABLE_PLUGIN": "Matikan plugin (rename folder)",
    "DISABLE_WP_USER": "Nonaktifkan akun WordPress",
    "DISABLE_OJS_USER": "Nonaktifkan akun OJS",
    "ACCEPT_INTEGRITY_BASELINE": "Terima baseline integritas baru",
    "CF_APPROVE": "Terapkan usulan cf-guard (blokir/lepas blokir Cloudflare)",
    "NOOP_TEST": "Uji alur persetujuan (tanpa aksi)",
}
CF_ID_RE = re.compile(r"\A[0-9a-f]{12}\Z")
CF_JENIS = ("ip", "path", "unip")


def _uid(value):
    if isinstance(value, bool) or not isinstance(value, int):
        if isinstance(value, str) and re.match(r"\A\d{1,18}\Z", value):
            value = int(value)
        else:
            raise ValueError("user_id harus bilangan bulat")
    if value <= 0:
        raise ValueError("user_id harus positif")
    return value


class T2Executor(object):
    def __init__(self, cfg, store, runner=run_argv, mysql=None, clock=time.time):
        self.cfg = cfg
        self.store = store
        self.runner = runner
        self.clock = clock
        self.mysql = mysql or MySQLCLI(cfg.mysql_bin, cfg.mysql_t2_cnf, runner=runner)

    def execute(self, request_id, action):
        kind = action.get("kind")
        params = action.get("params") or {}
        incident = action.get("incident") or ""
        handler = {
            "QUARANTINE_FILE": self._quarantine,
            "DISABLE_PLUGIN": self._plugin,
            "DISABLE_WP_USER": self._wp_user,
            "DISABLE_OJS_USER": self._ojs_user,
            "ACCEPT_INTEGRITY_BASELINE": self._accept_baseline,
            "CF_APPROVE": self._cf_approve,
            "NOOP_TEST": self._noop,
        }.get(kind)
        if handler is None:
            res = {"ok": False, "summary": "jenis aksi tidak dikenal"}
        elif not INCIDENT_RE.match(incident):
            res = {"ok": False, "summary": "ID insiden tidak valid"}
        else:
            try:
                res = handler(incident, params)
            except (BodyguardError, SecurityError, ValueError, KeyError, TypeError) as e:
                res = {"ok": False, "summary": clean("%s: %s" % (e.__class__.__name__, e), 300)}
        log_event(logging.WARNING, "eksekusi T2", request=request_id, kind=kind, ok=res.get("ok"),
                  summary=res.get("summary"))
        return res

    # ---- file & plugin (lewat bg-root) ---------------------------------------------------------
    def _quarantine(self, incident, params):
        path, sha = params["path"], params["sha256"]
        if not SHA256_RE.match(sha or ""):
            raise ValueError("sha256 tidak valid")
        if self.cfg.data_root_of(path) is None:
            raise SecurityError("path di luar [ioc] data_dirs")
        ok, res = call_bg_root(self.cfg, self.runner, ["quarantine", "--incident", incident, "--expect-sha256", sha,
                                                       "--", os.fsencode(path)])
        summary = ("dikarantina sebagai %s" % clean(res.get("quarantined_as"), 300)) if ok else clean(res.get("detail") or res.get("error"), 300)
        return {"ok": ok, "summary": summary, "rollback": res.get("rollback"), "detail": res}

    def _plugin(self, incident, params):
        path = params["path"]
        pdir = self.cfg.plugin_dir_of(path)
        if pdir is None or os.path.realpath(os.fsdecode(path) if isinstance(path, bytes) else path) != pdir:
            raise SecurityError("bukan entri plugin tingkat-1 di wp-content/plugins")
        ok, res = call_bg_root(self.cfg, self.runner, ["plugin-disable", "--incident", incident, "--", os.fsencode(pdir)])
        summary = ("plugin dimatikan: %s" % clean(res.get("disabled_as"), 300)) if ok else clean(res.get("detail") or res.get("error"), 300)
        return {"ok": ok, "summary": summary, "rollback": res.get("rollback"), "detail": res}

    def _accept_baseline(self, incident, params):
        current = self.store.get("integrity:changeset") or {}
        if not params.get("changeset") or current.get("sha256") != params.get("changeset"):
            raise SecurityError("laporan integritas berubah sejak usulan dibuat - dibatalkan, tunggu usulan baru")
        ok, res = call_bg_root(self.cfg, self.runner, ["integrity-accept", "--incident", incident], timeout=900)
        return {"ok": ok, "summary": "baseline baru diterima" if ok else clean(res.get("detail") or res.get("error"), 300),
                "detail": res}

    def _cf_approve(self, incident, params):
        rid, jenis = str(params.get("pending_id", "")), params.get("jenis")
        if not CF_ID_RE.match(rid) or jenis not in CF_JENIS:
            raise ValueError("usulan cf-guard tidak valid")
        ok, res = call_bg_root(self.cfg, self.runner, ["cf-approve", "--incident", incident, "--id", rid], timeout=120)
        summary = ("cf-guard: %s %s" % (clean(res.get("status"), 40), clean(res.get("nilai"), 80))) if ok \
            else clean(res.get("detail") or res.get("galat") or res.get("error"), 300)
        return {"ok": ok, "summary": summary, "rollback": res.get("rollback"), "detail": res}

    def _noop(self, incident, params):
        return {"ok": True, "summary": "uji alur persetujuan berhasil (tidak ada aksi yang dijalankan)"}

    # ---- akun (MySQL, hak kolom terbatas) -----------------------------------------------------
    def _site(self, name, typ):
        site = self.cfg.site_by_name(name)
        if site is None or site.type != typ or not site.db:
            raise SecurityError("situs %s (%s) tidak terdaftar di config" % (clean(name, 40), typ))
        return site

    def _wp_user(self, incident, params):
        site = self._site(params["site"], "wordpress")
        uid = _uid(params["user_id"])
        login = str(params["user_login"])[:LOGIN_MAX]
        p = site.prefix  # sudah divalidasi ^[A-Za-z0-9_]+$
        rows = self.mysql.query(site.db, "SELECT user_login FROM `%susers` WHERE ID=%d" % (p, uid))
        if not rows or rows[0][0] != login:
            raise SecurityError("user_login di DB tidak cocok dengan yang disetujui - dibatalkan")
        cap_key, lvl_key = p + "capabilities", p + "user_level"
        rows = self.mysql.query(site.db, "SELECT meta_key, HEX(meta_value) FROM `%susermeta` WHERE user_id=%d AND "
                                         "meta_key IN ('%s','%s')" % (p, uid, cap_key, lvl_key))
        rollback = []
        for key, hexval in rows:
            if key in (cap_key, lvl_key) and hexval is not None and HEX_RE.match(hexval):
                rollback.append("UPDATE `%susermeta` SET meta_value=UNHEX('%s') WHERE user_id=%d AND meta_key='%s';"
                                % (p, hexval, uid, key))
        sql = ("UPDATE `%(p)susermeta` SET meta_value='a:0:{}' WHERE user_id=%(u)d AND meta_key='%(c)s'; "
               "UPDATE `%(p)susermeta` SET meta_value='0' WHERE user_id=%(u)d AND meta_key='%(l)s'; "
               "UPDATE `%(p)susermeta` SET meta_value='a:0:{}' WHERE user_id=%(u)d AND meta_key='session_tokens';"
               % {"p": p, "u": uid, "c": cap_key, "l": lvl_key})
        self.mysql.execute(site.db, sql)
        check = self.mysql.query(site.db, "SELECT meta_value FROM `%susermeta` WHERE user_id=%d AND meta_key='%s'"
                                 % (p, uid, cap_key))
        ok = bool(check) and check[0][0] == "a:0:{}"
        return {"ok": ok, "summary": ("role akun WP '%s' (ID %d) dicabut & sesi diputus" % (clean(login, 60), uid))
                if ok else "verifikasi gagal - periksa manual",
                "rollback": " ".join(rollback) or "-"}

    def _ojs_user(self, incident, params):
        site = self._site(params["site"], "ojs")
        uid = _uid(params["user_id"])
        username = str(params["username"])[:LOGIN_MAX]
        rows = self.mysql.query(site.db, "SELECT username, disabled, HEX(IFNULL(disabled_reason,'')) FROM users "
                                         "WHERE user_id=%d" % uid)
        if not rows or rows[0][0] != username:
            raise SecurityError("username di DB tidak cocok dengan yang disetujui - dibatalkan")
        prev_disabled = 1 if rows[0][1] == "1" else 0
        prev_reason = rows[0][2] or ""
        if not HEX_RE.match(prev_reason):
            prev_reason = ""
        sql = "UPDATE users SET disabled=1, disabled_reason='bodyguard %s' WHERE user_id=%d;" % (incident, uid)
        if self.cfg.ojs_logout_sessions:
            sql += " UPDATE sessions SET user_id=NULL WHERE user_id=%d;" % uid
        self.mysql.execute(site.db, sql)
        check = self.mysql.query(site.db, "SELECT disabled FROM users WHERE user_id=%d" % uid)
        ok = bool(check) and check[0][0] == "1"
        rollback = "UPDATE users SET disabled=%d, disabled_reason=%s WHERE user_id=%d;" % (
            prev_disabled, ("UNHEX('%s')" % prev_reason) if prev_reason else "NULL", uid)
        return {"ok": ok, "summary": ("akun OJS '%s' (ID %d) dinonaktifkan" % (clean(username, 60), uid))
                if ok else "verifikasi gagal - periksa manual", "rollback": rollback}
