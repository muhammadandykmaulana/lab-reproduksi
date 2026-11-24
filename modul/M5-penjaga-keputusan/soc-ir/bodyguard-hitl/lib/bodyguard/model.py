# -*- coding: utf-8 -*-
"""Model data: Finding (hasil T0) dan Proposal (usulan aksi bertingkat)."""

import os

from .util import canonical_json, sha256_hex

SEVERITIES = ("info", "low", "medium", "high", "critical")
SEV_RANK = dict((s, i) for i, s in enumerate(SEVERITIES))
TIERS = ("T0", "T1", "T2", "T3")


def max_sev(*sevs):
    best = "info"
    for s in sevs:
        if s in SEV_RANK and SEV_RANK[s] > SEV_RANK[best]:
            best = s
    return best


class Finding(object):
    """Temuan T0. `target` str (path via os.fsdecode, IP, username, dsb.). `detail` hanya data tersanitasi
    kecuali field berawalan '_' (data mentah untuk eksekusi, tidak pernah ditampilkan)."""

    __slots__ = ("kind", "severity", "target", "site", "rules", "detail", "source")

    def __init__(self, kind, severity, target, site=None, rules=(), detail=None, source=""):
        if severity not in SEV_RANK:
            raise ValueError("severity tidak dikenal: %r" % severity)
        if isinstance(target, bytes):
            target = os.fsdecode(target)
        self.kind = kind
        self.severity = severity
        self.target = target
        self.site = site
        self.rules = list(rules)
        self.detail = dict(detail or {})
        self.source = source

    def fingerprint(self):
        return sha256_hex(canonical_json([self.kind, self.target, self.detail.get("sha256", "")]).encode("ascii"))

    def to_dict(self):
        return {"kind": self.kind, "severity": self.severity, "target": self.target, "site": self.site,
                "rules": self.rules, "detail": dict((k, v) for k, v in self.detail.items() if not k.startswith("_")),
                "source": self.source}

    def __repr__(self):
        return "Finding(%s,%s,%r)" % (self.kind, self.severity, self.target)


class Proposal(object):
    __slots__ = ("tier", "action", "target", "params", "finding", "note")

    def __init__(self, tier, action, target, params=None, finding=None, note=""):
        if tier not in TIERS:
            raise ValueError("tier tidak dikenal")
        self.tier = tier
        self.action = action
        self.target = target
        self.params = dict(params or {})
        self.finding = finding
        self.note = note

    def __repr__(self):
        return "Proposal(%s,%s,%r)" % (self.tier, self.action, self.target)
