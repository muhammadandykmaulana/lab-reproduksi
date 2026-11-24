# -*- coding: utf-8 -*-
"""T0: audit akun istimewa WordPress (administrator) & OJS (site admin=1, manager=16), read-only.

* Username cocok pola IOC (wpsvc_*, dsb.) -> critical, selalu dilaporkan.
* Akun istimewa yang tidak ada di baseline -> high (baseline diterima admin dari konsol:
  `bodyguard accounts accept`). Sebelum ada baseline, hanya IOC yang dilaporkan.
Kredensial DB read-only di /etc/bodyguard/mysql-ro.cnf (root:guard 0640, hanya hak SELECT).
"""

import time

from ..model import Finding, max_sev
from ..mysqlcli import MySQLCLI
from ..sanitizer import clean

OJS_ROLES = {"1": "site-admin", "16": "manager"}


class AccountAuditor(object):
    def __init__(self, cfg, store, rules, mysql=None, clock=time.time):
        self.cfg = cfg
        self.store = store
        self.rules = rules
        self.mysql = mysql or MySQLCLI(cfg.mysql_bin, cfg.mysql_ro_cnf)
        self.clock = clock

    def audit(self):
        out = []
        for site in self.cfg.sites:
            if not site.db:
                continue
            try:
                accounts = self._wordpress(site) if site.type == "wordpress" else self._ojs(site)
            except Exception as e:
                out.append(Finding("ACCOUNT_AUDIT_ERROR", "low", site.name, site=site.name,
                                   detail={"error": clean("%s: %s" % (e.__class__.__name__, e), 200)}, source="accounts"))
                continue
            out.extend(self._compare(site, accounts))
        return out

    def _wordpress(self, site):
        p = site.prefix
        rows = self.mysql.query(site.db, (
            "SELECT u.ID, u.user_login, u.user_email, u.user_registered FROM `%susers` u "
            "JOIN `%susermeta` m ON m.user_id=u.ID AND m.meta_key='%scapabilities' "
            "WHERE m.meta_value LIKE '%%\"administrator\"%%'") % (p, p, p))
        accounts = []
        for r in rows:
            if len(r) >= 4 and (r[0] or "").isdigit():
                accounts.append({"id": int(r[0]), "login": r[1] or "", "email": r[2] or "",
                                 "registered": r[3] or "", "roles": ["administrator"]})
        return accounts

    def _ojs(self, site):
        rows = self.mysql.query(site.db, (
            "SELECT u.user_id, u.username, u.email, u.date_registered, u.disabled, ug.role_id FROM users u "
            "JOIN user_user_groups uug ON uug.user_id=u.user_id "
            "JOIN user_groups ug ON ug.user_group_id=uug.user_group_id WHERE ug.role_id IN (1,16)"))
        by_id = {}
        for r in rows:
            if len(r) < 6 or not (r[0] or "").isdigit() or r[4] == "1":
                continue  # akun yang sudah disabled tidak perlu dilaporkan
            a = by_id.setdefault(int(r[0]), {"id": int(r[0]), "login": r[1] or "", "email": r[2] or "",
                                             "registered": r[3] or "", "roles": []})
            role = OJS_ROLES.get(r[5], r[5])
            if role not in a["roles"]:
                a["roles"].append(role)
        return [by_id[k] for k in sorted(by_id)]

    def _compare(self, site, accounts):
        key = "accounts:%s" % site.name
        baseline = self.store.get(key + ":baseline")
        current = sorted("%d:%s" % (a["id"], a["login"]) for a in accounts)
        self.store.set(key + ":current", {"at": self.clock(), "accounts": current})
        known = set((baseline or {}).get("accounts", []))
        prefix = "WP_ADMIN" if site.type == "wordpress" else "OJS_PRIV"
        out = []
        for a in accounts:
            ident = "%d:%s" % (a["id"], a["login"])
            hits = self.rules.username_hits(a["login"]) + [
                r for r in self.rules.username_hits(a["email"]) if r["id"] == "IOC-EMAIL-INTERNAL"]
            detail = {"user_id": a["id"], "login": clean(a["login"], 80), "email": clean(a["email"], 120),
                      "registered": clean(a["registered"], 40), "roles": a["roles"], "_login": a["login"]}
            target = "%s/user/%d" % (site.name, a["id"])
            if hits:
                out.append(Finding(prefix + "_IOC", max_sev(*[r["severity"] for r in hits]), target, site=site.name,
                                   rules=[r["id"] for r in hits], detail=detail, source="accounts"))
            elif baseline is not None and ident not in known:
                out.append(Finding(prefix + "_NEW", "high", target, site=site.name, rules=["ACC-NOT-IN-BASELINE"],
                                   detail=detail, source="accounts"))
        if baseline is None and accounts:
            out.append(Finding("ACCOUNTS_NO_BASELINE", "info", site.name, site=site.name,
                               detail={"count": len(accounts)}, source="accounts"))
        return out


def accept_accounts(store, site_names, actor="konsol"):
    """Jadikan snapshot akun terkini sebagai baseline (aksi konsol admin, diaudit)."""
    done = []
    for name in site_names:
        cur = store.get("accounts:%s:current" % name)
        if not cur:
            continue
        store.set("accounts:%s:baseline" % name, {"accounts": cur.get("accounts", []), "accepted_by": actor,
                                                  "at": time.time()})
        store.audit(actor, "ACCOUNTS_BASELINE_ACCEPTED", {"site": name, "count": len(cur.get("accounts", []))})
        done.append(name)
    return done
