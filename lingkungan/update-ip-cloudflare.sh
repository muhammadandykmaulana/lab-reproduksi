#!/bin/bash
set -u
CF=/etc/nginx/cloudflare.conf
TMP=$(mktemp)
V4=$(curl -fsS -m 20 https://www.cloudflare.com/ips-v4) || { echo "gagal ambil v4"; exit 1; }
V6=$(curl -fsS -m 20 https://www.cloudflare.com/ips-v6) || { echo "gagal ambil v6"; exit 1; }
{
  echo "# Cloudflare IP ranges - dibuat $(date -Is)"
  for ip in $V4 $V6; do echo "set_real_ip_from $ip;"; done
} > "$TMP"
[ "$(grep -c set_real_ip_from "$TMP")" -ge 10 ] || { echo "hasil tidak valid"; rm -f "$TMP"; exit 1; }
cp -p "$CF" "$CF.bak" 2>/dev/null
mv "$TMP" "$CF"
if nginx -t 2>/dev/null; then systemctl reload nginx; else echo "nginx -t gagal, rollback"; mv "$CF.bak" "$CF"; fi
