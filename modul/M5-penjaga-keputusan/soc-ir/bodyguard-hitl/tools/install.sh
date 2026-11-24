#!/bin/bash
# tools/install.sh - pemasang Bodyguard HITL (idempoten, tidak destruktif).
#
#   bash tools/install.sh --plan    (default) hanya MENAMPILKAN rencana, tidak mengubah apa pun
#   bash tools/install.sh --apply   menjalankan rencana (butuh root)
#
# Yang TIDAK dilakukan installer (sengaja, harus keputusan admin):
#   * tidak mengaktifkan/menyalakan timer & service systemd
#   * tidak mengubah fw.sh / iptables / nginx
#   * tidak menimpa config atau file rahasia yang sudah ada
#   * tidak menambahkan user guard ke grup apa pun
set -euo pipefail

MODE="${1:---plan}"
case "$MODE" in --plan|--apply) ;; *) echo "pemakaian: $0 [--plan|--apply]"; exit 2 ;; esac
SRC="$(cd "$(dirname "$0")/.." && pwd)"
PREFIX=/opt/bodyguard
ETC=/etc/bodyguard
STATE=/var/lib/bodyguard
LOGDIR=/var/log/bodyguard
EVID=/var/lib/bodyguard-evidence
ROOTSTATE=/var/lib/bodyguard-root
SBIN=/usr/local/sbin/bg-root
SUDOERS=/etc/sudoers.d/guard-bodyguard
UNITDIR=/etc/systemd/system
WARN=0

say()  { printf '%s\n' "$*"; }
warn() { printf 'PERINGATAN: %s\n' "$*"; WARN=$((WARN+1)); }
run()  { if [ "$MODE" = "--apply" ]; then printf '+ %s\n' "$*"; "$@"; else printf '[rencana] %s\n' "$*"; fi; }

if [ "$MODE" = "--apply" ] && [ "$(id -u)" -ne 0 ]; then
  echo "--apply harus dijalankan sebagai root"; exit 1
fi

say "== Pemeriksaan awal (read-only)"
python3 -c 'import sys; sys.exit(0 if sys.version_info >= (3, 6) else 1)' \
  || { echo "Python >= 3.6 dibutuhkan"; exit 1; }
python3 -c 'import sqlite3, ssl, ipaddress' || { echo "modul sqlite3/ssl/ipaddress Python tidak tersedia"; exit 1; }
say "python3: $(python3 -c 'import sys; print(sys.version.split()[0])')"
for c in sudo visudo systemctl; do command -v "$c" >/dev/null || { echo "perintah '$c' tidak ditemukan"; exit 1; }; done
[ -x /var/opt/script/tools/cf-guard.py ] || warn "cf-guard.py belum terpasang di /var/opt/script/tools: blokir IP T1 akan selalu gagal (aman, tapi tidak efektif)"
command -v mysql >/dev/null || warn "klien mysql tidak ditemukan: audit akun & aksi T2 akun tidak bisa jalan"
NOLOGIN="$(command -v nologin || echo /usr/sbin/nologin)"

say ""
say "== 1. User sistem: guard (pemindai, T1) & guard-approve (gatekeeper, T2) - tanpa login"
if id guard >/dev/null 2>&1; then say "sudah ada: $(id guard)"
else run useradd --system --home-dir "$STATE" --no-create-home --shell "$NOLOGIN" guard; fi
if id guard-approve >/dev/null 2>&1; then say "sudah ada: $(id guard-approve)"
else run useradd --system --home-dir "$STATE" --no-create-home --shell "$NOLOGIN" --groups guard guard-approve; fi

say ""
say "== 2. Direktori & kepemilikan"
run install -d -m 0755 -o root -g root "$PREFIX" "$PREFIX/bin" "$PREFIX/lib" "$PREFIX/lib/bodyguard" "$PREFIX/lib/bodyguard/detectors" "$PREFIX/tools" "$PREFIX/etc"
run install -d -m 0750 -o root -g guard "$ETC"
run install -d -m 2770 -o guard -g guard "$STATE"
run install -d -m 2770 -o guard -g guard "$LOGDIR"
run install -d -m 0700 -o root -g root "$EVID" "$ROOTSTATE"

say ""
say "== 3. Kode (milik root; user guard TIDAK bisa mengubah kodenya sendiri)"
for f in "$SRC"/lib/bodyguard/*.py; do run install -m 0644 -o root -g root "$f" "$PREFIX/lib/bodyguard/"; done
for f in "$SRC"/lib/bodyguard/detectors/*.py; do run install -m 0644 -o root -g root "$f" "$PREFIX/lib/bodyguard/detectors/"; done
run install -m 0755 -o root -g root "$SRC/bin/bodyguard" "$SRC/bin/gatekeeper_bot.py" "$PREFIX/bin/"
run install -m 0755 -o root -g root "$SRC/tools/gen_grants.py" "$SRC/tools/simulate.py" "$SRC/tools/bg-survey.sh" "$SRC/tools/update-cloudflare-ips.sh" "$PREFIX/tools/"
run install -m 0644 -o root -g root "$SRC/README.md" "$PREFIX/"
for f in "$SRC"/etc/*.example; do run install -m 0644 -o root -g root "$f" "$PREFIX/etc/"; done
run install -m 0755 -o root -g root "$SRC/sbin/bg-root" "$SBIN"

say ""
say "== 4. Konfigurasi (hanya dibuat bila BELUM ada; tidak pernah menimpa)"
install_once() { # sumber tujuan mode pemilik grup
  if [ -e "$2" ]; then say "sudah ada, dibiarkan: $2"
  else run install -m "$3" -o "$4" -g "$5" "$1" "$2"; fi
}
install_once "$SRC/etc/bodyguard.conf.example"      "$ETC/bodyguard.conf"      0640 root guard
install_once "$SRC/etc/root.conf.example"           "$ETC/root.conf"           0644 root root
install_once "$SRC/etc/cloudflare-ips.txt"          "$ETC/cloudflare-ips.txt"  0644 root root
install_once "$SRC/etc/admin-subnets.txt.example"   "$ETC/admin-subnets.txt"   0644 root root
install_once "$SRC/etc/alert.env.example"           "$ETC/alert.env"           0600 root root
install_once "$SRC/etc/gatekeeper.env.example"      "$ETC/gatekeeper.env"      0600 root root
if [ -e "$ETC/cloudflare-ips.txt" ] && ! cmp -s "$SRC/etc/cloudflare-ips.txt" "$ETC/cloudflare-ips.txt"; then
  warn "$ETC/cloudflare-ips.txt berbeda dari versi paket; periksa: diff $SRC/etc/cloudflare-ips.txt $ETC/cloudflare-ips.txt"
fi

say ""
say "== 5. Sudoers (divalidasi visudo SEBELUM dipasang)"
TMP_SUDO="$(mktemp)"
trap 'rm -f "$TMP_SUDO"' EXIT
cp "$SRC/etc/sudoers.d/guard-bodyguard" "$TMP_SUDO"
if visudo -cf "$TMP_SUDO" >/dev/null; then
  say "visudo: sintaks OK"
  if [ -e "$SUDOERS" ] && cmp -s "$TMP_SUDO" "$SUDOERS"; then say "sudah terpasang identik: $SUDOERS"
  else run install -m 0440 -o root -g root "$TMP_SUDO" "$SUDOERS"; fi
else
  echo "visudo menolak file sudoers - instalasi dihentikan"; exit 1
fi

say ""
say "== 6. Unit systemd (dipasang, TIDAK diaktifkan)"
for u in bodyguard-scan.service bodyguard-scan.timer bodyguard-gatekeeper.service; do
  run install -m 0644 -o root -g root "$SRC/etc/systemd/$u" "$UNITDIR/$u"
done
run systemctl daemon-reload

say ""
say "== 7. Pemeriksaan rahasia (nilai tidak pernah dicetak)"
val() { [ -r "$1" ] && sed -n "s/^$2=//p" "$1" | tail -1 || true; }
if [ -r "$ETC/alert.env" ] && [ -r "$ETC/gatekeeper.env" ]; then
  A="$(val "$ETC/alert.env" BG_ALERT_BOT_TOKEN)"; G="$(val "$ETC/gatekeeper.env" BG_APPROVAL_BOT_TOKEN)"
  [ -n "$A" ] && [ "$A" = "$G" ] && warn "token bot ALERT sama dengan bot APPROVAL - wajib dua bot berbeda"
  [ -z "$G" ] && warn "BG_APPROVAL_BOT_TOKEN belum diisi di $ETC/gatekeeper.env"
  K="$(val "$ETC/gatekeeper.env" BG_HMAC_KEY)"
  [ "${#K}" -lt 64 ] && warn "BG_HMAC_KEY belum diisi/kurang dari 64 hex (buat: openssl rand -hex 32)"
  for f in "$ETC/alert.env" "$ETC/gatekeeper.env"; do
    [ "$(stat -c '%U:%a' "$f")" = "root:600" ] || warn "$f harus root:root 0600"
  done
else
  say "(file env belum ada atau tidak terbaca; jalankan sebagai root setelah --apply)"
fi

say ""
say "== Selesai ($MODE). Peringatan: $WARN"
say "Langkah berikut (manual, lihat README):"
say "  1) isi $ETC/bodyguard.conf, root.conf, admin-subnets.txt, *.env"
say "  2) siapkan FREEZE bersama: /var/opt/script/tools/penjaga.sh siapkan"
say "  3) beri guard akses baca log nginx (mis. setfacl) dan buat user DB: $PREFIX/tools/gen_grants.py"
say "  4) sudo -u guard $PREFIX/bin/bodyguard selftest"
say "  5) mode dry-run dulu: systemctl enable --now bodyguard-scan.timer"
