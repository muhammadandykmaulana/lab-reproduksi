# -*- coding: utf-8 -*-
"""Whitelist IP ketat (sisi guard). Sisi root (bg-root) mengecek ULANG secara independen.

Aturan (urut):
  1. IP harus valid dan global-routable (privat/loopback/link-local/CGNAT/multicast/reserved TIDAK
     pernah diblokir - mencegah memotong akses admin via VPN/LAN).
  2. Tidak termasuk daftar selalu-dilindungi (127.0.0.0/8, ::1, 0.0.0.0/8).
  3. Tidak termasuk file whitelist (Cloudflare, subnet kantor/admin, tambahan).
Gagal memuat whitelist = WhitelistError. Pemanggil wajib fail-closed: tidak memblokir apa pun.
"""

import ipaddress
import re

from .util import BodyguardError

ALWAYS_PROTECTED = (
    ("loopback", "127.0.0.0/8"),
    ("loopback", "::1/128"),
    ("this-network", "0.0.0.0/8"),
)
_IP_CHARS_RE = re.compile(r"\A[0-9A-Fa-f:.]{2,45}\Z")


class WhitelistError(BodyguardError):
    pass


def parse_ip(value):
    """Parse IP secara ketat; IPv4-mapped IPv6 (::ffff:a.b.c.d) dinormalkan ke IPv4."""
    if isinstance(value, bytes):
        value = value.decode("ascii", "replace")
    s = str(value)  # sengaja TIDAK di-strip: input harus persis IP
    if not _IP_CHARS_RE.match(s):
        raise ValueError("format IP tidak valid")
    ip = ipaddress.ip_address(s)
    if ip.version == 6 and ip.ipv4_mapped is not None:
        ip = ip.ipv4_mapped
    return ip


class Whitelist(object):
    def __init__(self, entries):
        self.entries = []
        for label, net in entries:
            if not isinstance(net, (ipaddress.IPv4Network, ipaddress.IPv6Network)):
                net = ipaddress.ip_network(net, strict=False)
            self.entries.append((label, net))

    @classmethod
    def from_files(cls, sources, extra=(), require_labels=("cloudflare",)):
        """sources: list (label, path). Label pada require_labels wajib menghasilkan >=1 entri."""
        entries = list(ALWAYS_PROTECTED)
        counts = {}
        for label, path in sources:
            try:
                with open(path, "r", encoding="utf-8") as f:
                    lines = f.readlines()
            except OSError as e:
                raise WhitelistError("tidak bisa membaca whitelist %s (%s): %s" % (label, path, e.__class__.__name__))
            for lineno, line in enumerate(lines, 1):
                item = line.split("#", 1)[0].strip()
                if not item:
                    continue
                try:
                    net = ipaddress.ip_network(item, strict=False)
                except ValueError:
                    raise WhitelistError("baris %d di %s tidak valid: %r" % (lineno, path, item[:60]))
                entries.append((label, net))
                counts[label] = counts.get(label, 0) + 1
        for item in extra:
            item = item.strip()
            if item:
                try:
                    entries.append(("config", ipaddress.ip_network(item, strict=False)))
                except ValueError:
                    raise WhitelistError("entri whitelist tambahan tidak valid: %r" % item[:60])
        for label in require_labels:
            if counts.get(label, 0) == 0:
                raise WhitelistError("whitelist '%s' kosong \u2014 blokir IP dimatikan (fail-closed)" % label)
        return cls(entries)

    def check(self, ip_value):
        """Kembalikan (boleh_diblokir: bool, alasan: str)."""
        try:
            ip = parse_ip(ip_value)
        except ValueError:
            return False, "ip-tidak-valid"
        if (not ip.is_global or ip.is_multicast or ip.is_unspecified or ip.is_reserved
                or ip.is_loopback or ip.is_link_local or ip.is_private):
            return False, "bukan-ip-global"
        for label, net in self.entries:
            if ip.version == net.version and ip in net:
                return False, "whitelist:%s:%s" % (label, net)
        return True, "ok"

    def summary(self):
        out = {}
        for label, _net in self.entries:
            out[label] = out.get(label, 0) + 1
        return out
