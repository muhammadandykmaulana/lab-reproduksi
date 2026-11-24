#!/usr/bin/env bash
# Salin data TERBARU ke /var/lib/soc_ir/data (root:soc_ir 640). soc_ir tidak pernah membaca sumber asli.
set -uo pipefail
D=/var/lib/soc_ir/data
cp1() { [ -n "${1:-}" ] && [ -f "$1" ] && install -m 0640 -o root -g soc_ir "$1" "$D/$2"; }
SRC_BEH="$(ls -t /root/ip-behavior-*.csv 2>/dev/null | head -1)"
cp1 "$SRC_BEH" ip-behavior-30hari.csv
if [ -n "$SRC_BEH" ] && [ -f "$SRC_BEH" ]; then
python3 - "$SRC_BEH" "$D/ip-behavior.csv" <<'PY'
import csv, sys, datetime
src, dst = sys.argv[1], sys.argv[2]
batas = datetime.datetime.now() - datetime.timedelta(days=3)
with open(src, newline="") as f:
    r = csv.DictReader(f)
    kolom = r.fieldnames
    baris = []
    for x in r:
        if "kantor" in (x.get("saran") or "").lower():
            continue
        try:
            t = datetime.datetime.strptime((x.get("terakhir") or "")[:16], "%Y-%m-%d %H:%M")
        except ValueError:
            continue
        if t >= batas:
            baris.append(x)
with open(dst, "w", newline="") as f:
    w = csv.DictWriter(f, fieldnames=kolom)
    w.writeheader()
    w.writerows(baris)
PY
chown root:soc_ir "$D/ip-behavior.csv"; chmod 640 "$D/ip-behavior.csv"
fi
cp1 "$(ls -t /root/ip-report-*.txt 2>/dev/null | head -1)"  ip-report.txt
cp1 "$(ls -t /root/cek-all-*.txt /var/log/audit-run/cek-semua-*.log 2>/dev/null | head -1)"    cek-all.txt
cp1 /var/log/cf-guard.log cf-guard.log
if [ -f /var/opt/script/tools/cf-guard.py ]; then
  python3 /var/opt/script/tools/cf-guard.py status > "$D/cf-guard-status.txt" 2>&1
  chown root:soc_ir "$D/cf-guard-status.txt"; chmod 640 "$D/cf-guard-status.txt"
fi
if [ -x /opt/bodyguard/bin/bodyguard ]; then
  sudo -u guard /opt/bodyguard/bin/bodyguard status > "$D/bodyguard-status.txt" 2>&1
  chown root:soc_ir "$D/bodyguard-status.txt"; chmod 640 "$D/bodyguard-status.txt"
fi
cp1 "$(ls -t /var/log/soc_ir/laporan-*.txt 2>/dev/null | head -1)" laporan-sebelumnya.txt
exit 0
