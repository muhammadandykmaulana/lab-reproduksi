# -*- coding: utf-8 -*-
"""Akses MySQL/MariaDB lewat klien `mysql` (tanpa pustaka pihak ketiga).

Kredensial di file --defaults-extra-file (root:guard 0640), bukan di argv/env.
Keamanan injeksi: SQL di modul pemanggil hanya pernah menyisipkan nilai bertipe ketat
(integer, prefix tabel ^[A-Za-z0-9_]+$, ID insiden ^INC-...$, hex). Tidak ada teks penyerang di SQL.
"""

import re

from .config import DBNAME_RE
from .sanitizer import clean
from .util import BodyguardError, run_argv

HEX_RE = re.compile(r"\A[0-9A-F]*\Z")


class MySQLError(BodyguardError):
    pass


def _unescape(field):
    if field == "NULL":
        return None
    out, i, n = [], 0, len(field)
    while i < n:
        ch = field[i]
        if ch == "\\" and i + 1 < n:
            nxt = field[i + 1]
            out.append({"n": "\n", "t": "\t", "0": "\x00", "\\": "\\"}.get(nxt, nxt))
            i += 2
        else:
            out.append(ch)
            i += 1
    return "".join(out)


def parse_batch(output):
    """Parse keluaran `mysql --batch --skip-column-names` (tab-separated, ter-escape)."""
    text = output.decode("utf-8", "replace") if isinstance(output, bytes) else output
    rows = []
    for line in text.split("\n"):
        if line == "":
            continue
        rows.append([_unescape(f) for f in line.split("\t")])
    return rows


class MySQLCLI(object):
    def __init__(self, mysql_bin, defaults_file, runner=run_argv, timeout=30):
        self.mysql_bin = mysql_bin
        self.defaults_file = defaults_file
        self.runner = runner
        self.timeout = timeout

    def _run(self, db, sql):
        if not DBNAME_RE.match(db or ""):
            raise MySQLError("nama database tidak valid")
        argv = [self.mysql_bin, "--defaults-extra-file=" + self.defaults_file, "--batch", "--skip-column-names",
                "--database=" + db, "--execute=" + sql]
        rc, out, err = self.runner(argv, timeout=self.timeout)
        if rc != 0:
            raise MySQLError("mysql rc=%d: %s" % (rc, clean(err[-300:], 300)))
        return out

    def query(self, db, sql):
        return parse_batch(self._run(db, sql))

    def execute(self, db, sql):
        self._run(db, sql)
