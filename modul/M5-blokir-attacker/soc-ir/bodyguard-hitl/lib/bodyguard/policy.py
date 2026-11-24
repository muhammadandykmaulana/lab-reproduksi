# -*- coding: utf-8 -*-
"""Policy engine deterministik: temuan T0 -> usulan aksi T0/T1/T2/T3.

Tabel keputusan (tidak ada heuristik tersembunyi, tidak ada LLM):

  Temuan                       T0 alert  T1 otomatis           T2 persetujuan             T3 checklist
  PHP_IN_DATA_DIR              ya        CONTAIN_FILE          QUARANTINE_FILE (terikat SHA)  ya
  POLYGLOT_FILE                ya        CONTAIN_FILE          QUARANTINE_FILE            ya
  CONTAINED_FILE (mode 000)    -         -                     QUARANTINE_FILE bila SHA tercatat
  SYMLINK_IN_DATA_DIR          ya        -                     -                          ya
  IOC_IN_CODE                  ya        -                     DISABLE_PLUGIN (bila di plugin) ya
  SUSPICIOUS_PLUGIN            ya        -                     DISABLE_PLUGIN             ya
  WP_ADMIN_IOC / WP_ADMIN_NEW  ya        -                     DISABLE_WP_USER            ya (IOC)
  OJS_PRIV_IOC / OJS_PRIV_NEW  ya        -                     DISABLE_OJS_USER           ya (IOC)
  ATTACKER_IP                  ya        BLOCK_IP (TTL 1-24 j) -                          -
  INTEGRITY_CHANGES            ya        -                     ACCEPT_BASELINE (bila 0 IOC) -
  lainnya (galat, info)        ya/-      -                     -                          -
Kode (tema/plugin/core) TIDAK pernah dikenai aksi T1: risiko merusak situs terlalu besar.
"""

from .model import Proposal

T3_KINDS = frozenset(("PHP_IN_DATA_DIR", "POLYGLOT_FILE", "SYMLINK_IN_DATA_DIR", "IOC_IN_CODE", "SUSPICIOUS_PLUGIN",
                      "WP_ADMIN_IOC", "OJS_PRIV_IOC"))


def decide(findings, cfg, lookup_contained=None):
    props = []
    for f in findings:
        k = f.kind
        if f.severity != "info":
            props.append(Proposal("T0", "ALERT", f.target, finding=f))
        if k in ("PHP_IN_DATA_DIR", "POLYGLOT_FILE"):
            props.append(Proposal("T1", "CONTAIN_FILE", f.target, {"path": f.target}, f))
            if f.detail.get("sha256"):
                # Tanpa SHA (file tak terbaca guard) usulan T2 menunggu: setelah T1 mengunci file, SHA dari
                # bg-root dipakai lewat temuan CONTAINED_FILE pada siklus berikutnya.
                props.append(Proposal("T2", "QUARANTINE_FILE", f.target, {"path": f.target, "sha256": f.detail["sha256"]}, f))
        elif k == "CONTAINED_FILE":
            sha = lookup_contained(f.target) if lookup_contained else None
            if sha:
                props.append(Proposal("T2", "QUARANTINE_FILE", f.target, {"path": f.target, "sha256": sha}, f))
        elif k == "IOC_IN_CODE":
            pdir = f.detail.get("plugin_dir")
            if pdir:
                props.append(Proposal("T2", "DISABLE_PLUGIN", pdir, {"path": pdir}, f))
        elif k == "SUSPICIOUS_PLUGIN":
            props.append(Proposal("T2", "DISABLE_PLUGIN", f.target, {"path": f.target}, f))
        elif k in ("WP_ADMIN_IOC", "WP_ADMIN_NEW"):
            props.append(Proposal("T2", "DISABLE_WP_USER", f.target, {
                "site": f.site, "user_id": f.detail["user_id"], "user_login": f.detail["_login"]}, f))
        elif k in ("OJS_PRIV_IOC", "OJS_PRIV_NEW"):
            props.append(Proposal("T2", "DISABLE_OJS_USER", f.target, {
                "site": f.site, "user_id": f.detail["user_id"], "username": f.detail["_login"]}, f))
        elif k == "ATTACKER_IP":
            ttl = cfg.ip_ttl.get(f.severity, cfg.ip_ttl["medium"])
            props.append(Proposal("T1", "BLOCK_IP", f.target, {"ip": f.target, "ttl": ttl}, f))
        elif k == "INTEGRITY_CHANGES":
            if not f.detail.get("ioc_hits") and f.detail.get("changeset"):
                props.append(Proposal("T2", "ACCEPT_INTEGRITY_BASELINE", "web-integrity-cek",
                                      {"changeset": f.detail["changeset"]}, f))
    kinds = sorted(set(f.kind for f in findings if f.kind in T3_KINDS))
    if kinds:
        props.append(Proposal("T3", "CHECKLIST", "insiden", {"kinds": kinds}))
    return props
