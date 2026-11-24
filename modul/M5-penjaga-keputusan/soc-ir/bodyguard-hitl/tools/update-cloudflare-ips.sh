#!/bin/bash
# Bandingkan /etc/bodyguard/cloudflare-ips.txt dengan daftar resmi Cloudflare.
#   update-cloudflare-ips.sh           cek & tampilkan diff (read-only)
#   update-cloudflare-ips.sh --apply   tulis file baru (atomik) bila daftar resmi lolos validasi
# Daftar usang berbahaya: rentang Cloudflare baru yang tidak dikenal bisa ikut terblokir (self-DoS).
# Setelah --apply, perbarui juga set_real_ip_from di nginx (lihat etc/nginx-realip-cloudflare.conf.example).
set -euo pipefail
DEST=/etc/bodyguard/cloudflare-ips.txt
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

curl -fsS --max-time 20 https://www.cloudflare.com/ips-v4/ -o "$TMP/v4"
curl -fsS --max-time 20 https://www.cloudflare.com/ips-v6/ -o "$TMP/v6"
python3 - "$TMP/v4" "$TMP/v6" > "$TMP/new" <<'EOF'
import ipaddress, sys, time
nets = []
for path, ver in ((sys.argv[1], 4), (sys.argv[2], 6)):
    for line in open(path):
        line = line.strip()
        if not line:
            continue
        net = ipaddress.ip_network(line, strict=True)   # entri tidak valid = berhenti, file lama tetap
        if net.version != ver:
            raise SystemExit("versi IP tidak sesuai di %s" % path)
        nets.append(str(net))
v4 = [n for n in nets if ":" not in n]
v6 = [n for n in nets if ":" in n]
if len(v4) < 10 or len(v6) < 5:
    raise SystemExit("daftar terlalu pendek (%d v4, %d v6) - dibatalkan" % (len(v4), len(v6)))
print("# Rentang IP Cloudflare - diambil %s dari https://www.cloudflare.com/ips-v4/ dan /ips-v6/" % time.strftime("%Y-%m-%d"))
print("\n".join(v4 + v6))
EOF

if diff <(grep -v '^#' "$DEST" | sort) <(grep -v '^#' "$TMP/new" | sort); then
  echo "tidak ada perubahan"
  exit 0
fi
if [ "${1:-}" = "--apply" ]; then
  install -m 0644 -o root -g root "$TMP/new" "$DEST.new"
  mv -f "$DEST.new" "$DEST"
  echo "diperbarui: $DEST  (ingat: perbarui juga set_real_ip_from di nginx, lalu nginx -t && systemctl reload nginx)"
else
  echo "ada perbedaan; jalankan dengan --apply untuk menulis"
fi
