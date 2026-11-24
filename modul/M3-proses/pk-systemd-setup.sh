#!/bin/bash
# pk-systemd-setup.sh - pasang timer M3 (tiap menit) lewat notify-run.sh
# Pakai: pk-systemd-setup.sh dry|auto|off|sweep-on|sweep-off
set -euo pipefail
[ "$(id -u)" -eq 0 ] || { echo "jalankan sebagai root"; exit 1; }
PK=/var/opt/script/tools/persistence-killer.sh
NR=/var/opt/script/tools/notify-run.sh   # pembungkus: log, deduplikasi temuan, satu pengirim Telegram
[ -x "$PK" ] || { echo "tidak ada / tidak executable: $PK"; exit 1; }
MODE="${1:-dry}"

write_units() {  # $1 = argumen script
cat > /etc/systemd/system/persistence-killer.service <<UNIT
[Unit]
Description=persistence-killer ($1)
After=network.target

[Service]
Type=oneshot
ExecStart=$NR persistence $PK $1
SuccessExitStatus=0 1
Nice=10
IOSchedulingClass=idle
UNIT
cat > /etc/systemd/system/persistence-killer.timer <<UNIT
[Unit]
Description=persistence-killer tiap menit

[Timer]
OnBootSec=2min
OnUnitActiveSec=1min
AccuracySec=5s

[Install]
WantedBy=timers.target
UNIT
}

case "$MODE" in
  dry)  write_units "--dry-run --no-notify"
        bash /var/opt/script/tools/penjaga.sh siapkan >/dev/null
        systemctl daemon-reload; systemctl enable --now persistence-killer.timer
        echo "MODE DRY-RUN aktif. Lihat: journalctl -u persistence-killer -n 50 --no-pager" ;;
  auto) write_units "--auto"
        bash /var/opt/script/tools/penjaga.sh siapkan >/dev/null
        systemctl daemon-reload; systemctl enable --now persistence-killer.timer
        echo "MODE AUTO-KILL aktif. Hentikan darurat (semua modul): penjaga.sh freeze "alasan"" ;;
  off)  systemctl disable --now persistence-killer.timer || true
        echo "timer dimatikan" ;;
  sweep-on)
cat > /etc/systemd/system/persistence-killer-sweep.service <<UNIT
[Unit]
Description=persistence-killer sweep dropper

[Service]
Type=oneshot
ExecStart=$NR persistence-sweep $PK --auto --sweep
SuccessExitStatus=0 1
Nice=10
IOSchedulingClass=idle
UNIT
cat > /etc/systemd/system/persistence-killer-sweep.timer <<UNIT
[Unit]
Description=persistence-killer sweep tiap 15 menit

[Timer]
OnBootSec=5min
OnUnitActiveSec=15min

[Install]
WantedBy=timers.target
UNIT
        systemctl daemon-reload; systemctl enable --now persistence-killer-sweep.timer
        echo "sweep timer aktif" ;;
  sweep-off)
        systemctl disable --now persistence-killer-sweep.timer || true
        echo "sweep timer dimatikan" ;;
  *) echo "pakai: dry|auto|off|sweep-on|sweep-off"; exit 1 ;;
esac
systemctl list-timers 'persistence-killer*' --no-pager
