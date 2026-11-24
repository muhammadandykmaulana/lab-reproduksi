#!/usr/bin/env bash
# atur-token.sh - isi atau ubah token kapan saja (interaktif). Token TIDAK disimpan di folder lab.
#
#   sudo bash atur-token.sh               menu
#   sudo bash atur-token.sh telegram      token bot + chat id (alert SOC dan laporan backup)
#   sudo bash atur-token.sh cloudflare    token API Cloudflare + zona + rule dinamis (untuk cf-guard.py)
#   sudo bash atur-token.sh persetujuan   bot persetujuan terpisah: SATU gerbang tombol Setujui/Tolak T2 (SOC-IR), juga untuk usulan cf-guard
#   sudo bash atur-token.sh semua         ketiganya berurutan
#   sudo bash atur-token.sh cek           uji token yang tersimpan (tanpa mencetak token)
# Tiap pertanyaan ditunggu 60 detik. Tidak dijawab = dilewati; jalankan lagi skrip ini kapan saja.
# Disimpan di: /etc/web-integrity.env dan /etc/cek-disk.env (Telegram), /etc/bodyguard/cloudflare.env (Cloudflare) - root 600.
set -uo pipefail
DIR="$(cd "$(dirname "$0")" && pwd)"
. "$DIR/lib/umum.sh"
perlu_root

api_json() {  # api_json URL [header...] -> cetak JSON (stdout), kosong bila gagal
  local u=$1; shift; local h=(); for x in "$@"; do h+=(-H "$x"); done
  curl -sS -m 20 "${h[@]}" "$u" 2>/dev/null
}
py() { python3 -I -c "$1" 2>/dev/null; }

# ------------------------------------------------------------------ Telegram
telegram() {
  judul "Telegram (bot notifikasi)"
  cat <<'EOF'
Cara membuat bot dan mendapatkan token:
  1. Di Telegram, buka @BotFather -> kirim /newbot -> beri nama -> salin token (bentuk 123456789:AAH...).
  2. Buat grup "SOC Kampus", undang bot itu, lalu kirim satu pesan apa saja di grup (mis. "halo bot").
  3. Chat id grup akan dicari otomatis lewat:  https://api.telegram.org/bot<TOKEN>/getUpdates
     (bisa juga dibuka manual di browser; cari "chat":{"id":-100...}. Chat id grup selalu diawali tanda minus.)
EOF
  local tok chat cur
  cur=$(get_kv "$ENV_WI" TELEGRAM_BOT_TOKEN)
  tanya tok "Token bot Telegram${cur:+ (sudah ada; Enter = pertahankan)}" "" 1
  [ -z "$tok" ] && tok=$cur
  if [ -z "$tok" ]; then peringatan "token Telegram dilewati. Isi nanti: sudo bash $0 telegram"; status_set TELEGRAM belum; return 0; fi
  case "$tok" in [0-9]*:*) ;; *) galat "format token tidak cocok (harus angka:huruf)"; status_set TELEGRAM belum; return 1;; esac
  nama=$(api_json "https://api.telegram.org/bot$tok/getMe" | py 'import json,sys; d=json.load(sys.stdin); print(d["result"]["username"] if d.get("ok") else "")')
  [ -n "$nama" ] && sukses "token valid: bot @$nama" || { galat "token ditolak Telegram atau tidak ada internet"; status_set TELEGRAM gagal; return 1; }
  info "mencari chat id dari pesan terbaru ke bot (getUpdates)..."
  daftar=""
  for i in 1 2 3 4 5 6; do
    daftar=$(api_json "https://api.telegram.org/bot$tok/getUpdates" | py '
import json,sys
d=json.load(sys.stdin); seen={}
for u in d.get("result",[]):
    m=u.get("message") or u.get("channel_post") or u.get("my_chat_member") or {}
    c=m.get("chat") or {}
    if c.get("id") is not None: seen[c["id"]]=(c.get("type",""), c.get("title") or c.get("username") or c.get("first_name",""))
for k,(t,n) in seen.items(): print("%s\t%s\t%s"%(k,t,n))')
    [ -n "$daftar" ] && break
    [ "$OTOMATIS" = 1 ] && break
    [ $i -eq 1 ] && echo "   Belum ada pesan. Kirim satu pesan di grup yang berisi bot sekarang; dicek ulang tiap 10 detik (maks. 1 menit)..."
    sleep 10
  done
  cur=$(get_kv "$ENV_WI" TELEGRAM_CHAT_ID)
  if [ -n "$daftar" ]; then
    echo "   Chat yang ditemukan:"; echo "$daftar" | awk -F'\t' '{printf "     %-16s %-11s %s\n",$1,$2,$3}'
    bawaan=$(echo "$daftar" | awk -F'\t' '$2 ~ /group/ {print $1; exit}'); bawaan=${bawaan:-$(echo "$daftar" | head -1 | cut -f1)}
  else
    peringatan "belum ada pesan masuk (atau bot memakai webhook). Isi chat id manual."
    bawaan=$cur
  fi
  tanya chat "Chat id tujuan notifikasi" "$bawaan"
  if [ -z "$chat" ]; then peringatan "chat id dilewati"; status_set TELEGRAM sebagian; chat=""; fi
  for f in "$ENV_WI" "$ENV_CD"; do set_kv "$f" TELEGRAM_BOT_TOKEN "$tok"; [ -n "$chat" ] && set_kv "$f" TELEGRAM_CHAT_ID "$chat"; done
  sukses "tersimpan di $ENV_WI dan $ENV_CD (600)"
  if [ -n "$chat" ] && ya_tidak "Kirim pesan uji ke chat $chat?" y; then
    kode=$(curl -s -m 20 -o /dev/null -w '%{http_code}' "https://api.telegram.org/bot$tok/sendMessage" -d chat_id="$chat" \
           --data-urlencode "text=✅ Lab reproduksi $(hostname): notifikasi Telegram berfungsi")
    [ "$kode" = 200 ] && { sukses "pesan uji terkirim"; status_set TELEGRAM ok; } || { galat "pesan uji gagal (HTTP $kode): pastikan bot ada di grup"; status_set TELEGRAM gagal; }
  fi
}

# ------------------------------------------------------------------ Cloudflare
cloudflare() {
  judul "Cloudflare (untuk cf-guard.py: daftar IP blokir + rule dinamis)"
  cat <<'EOF'
Cara membuat token API (dashboard Cloudflare):
  My Profile -> API Tokens -> Create Token -> Custom token, izin MINIMAL:
    Account | Account Filter Lists | Edit        (daftar IP "hacker")
    Zone    | Zone WAF             | Edit        (rule "Auto-Block - Dinamis Hacker")
    Zone    | Analytics            | Read        (WAF events)
  Batasi ke zona kampus Anda saja. Buat dulu satu custom rule bernama "Auto-Block - Dinamis Hacker" di
  Security -> WAF -> Custom rules (aksi Block), isinya akan dikelola cf-guard.py.
EOF
  local tok cur zone acc
  cur=$(get_kv "$ENV_CF" CF_AUTH_TOKEN)
  tanya tok "Token API Cloudflare${cur:+ (sudah ada; Enter = pertahankan)}" "" 1
  [ -z "$tok" ] && tok=$cur
  [ -n "$tok" ] || { peringatan "token Cloudflare dilewati. Isi nanti: sudo bash $0 cloudflare"; status_set CLOUDFLARE belum; return 0; }
  local CFH="Authorization: Bearer $tok"   # jangan pakai nama H: itu variabel warna di lib/umum.sh
  st=$(api_json https://api.cloudflare.com/client/v4/user/tokens/verify "$CFH" | py 'import json,sys; d=json.load(sys.stdin); print(d.get("result",{}).get("status",""))')
  [ "$st" = active ] && sukses "token Cloudflare aktif" || { galat "token Cloudflare tidak aktif/ditolak (status: ${st:-tidak ada respons})"; status_set CLOUDFLARE gagal; return 1; }
  mkdir -p /etc/bodyguard; chmod 750 /etc/bodyguard
  set_kv "$ENV_CF" CF_AUTH_TOKEN "$tok"
  zonas=$(api_json "https://api.cloudflare.com/client/v4/zones?per_page=50" "$CFH" | py '
import json,sys
for z in json.load(sys.stdin).get("result",[]): print("%s\t%s\t%s"%(z["id"],z["account"]["id"],z["name"]))')
  [ -n "$zonas" ] && { echo "   Zona yang bisa diakses token:"; echo "$zonas" | awk -F'\t' '{printf "     %-22s %s\n",$3,$1}'; }
  local dom; tanya dom "Domain utama kampus (zona)" "$(echo "$zonas" | head -1 | cut -f3)"
  zone=$(echo "$zonas" | awk -F'\t' -v d="$dom" '$3==d{print $1}'); acc=$(echo "$zonas" | awk -F'\t' -v d="$dom" '$3==d{print $2}')
  [ -n "$zone" ] || { tanya zone "Zone ID (Overview -> kanan bawah)" "$(get_kv "$ENV_CF" CF_ZONE_ID)"; tanya acc "Account ID" "$(get_kv "$ENV_CF" CF_ACCOUNT_ID)"; }
  [ -n "$zone" ] && set_kv "$ENV_CF" CF_ZONE_ID "$zone"; [ -n "$acc" ] && set_kv "$ENV_CF" CF_ACCOUNT_ID "$acc"
  if [ -n "$zone" ]; then
    rules=$(api_json "https://api.cloudflare.com/client/v4/zones/$zone/rulesets/phases/http_request_firewall_custom/entrypoint" "$CFH" | py '
import json,sys
r=json.load(sys.stdin).get("result") or {}
for x in r.get("rules",[]): print("%s\t%s\t%s"%(r.get("id",""),x.get("id",""),x.get("description","")))')
    if [ -n "$rules" ]; then
      echo "   Custom rule di zona ini:"; echo "$rules" | awk -F'\t' '{printf "     %d. %s\n",NR,$3}'
      pilih=$(echo "$rules" | awk -F'\t' 'tolower($3) ~ /dinamis|hacker/ {print NR; exit}')
      local no; tanya no "Nomor rule yang dikelola cf-guard (HANYA rule ini yang diubah)" "${pilih:-}"
      if [ -n "$no" ]; then
        set_kv "$ENV_CF" CF_RULESET_ID "$(echo "$rules" | sed -n "${no}p" | cut -f1)"
        set_kv "$ENV_CF" CF_RULE_ID "$(echo "$rules" | sed -n "${no}p" | cut -f2)"
        sukses "rule terpilih: $(echo "$rules" | sed -n "${no}p" | cut -f3)"
      fi
    else peringatan "belum ada custom rule (atau izin Zone WAF Read belum diberikan). Buat rule-nya lalu jalankan lagi."; fi
  fi
  set_kv "$ENV_CF" CF_LIST_NAME "$(get_kv "$ENV_CF" CF_LIST_NAME | grep . || echo hacker)"
  set_kv "$ENV_CF" CG_OFFICE_IPS "$(get_kv "$ENV_WI" IP_KANTOR)"
  [ -n "$(get_kv "$ENV_CF" CG_HMAC_KEY)" ] || set_kv "$ENV_CF" CG_HMAC_KEY "$(openssl rand -hex 32)"
  local kurang=(); for k in CF_AUTH_TOKEN CF_ACCOUNT_ID CF_ZONE_ID CF_RULESET_ID CF_RULE_ID; do [ -n "$(get_kv "$ENV_CF" $k)" ] || kurang+=("$k"); done
  if [ ${#kurang[@]} -eq 0 ]; then sukses "Cloudflare lengkap di $ENV_CF. Uji aman: python3 $TOOLS/cf-guard.py run   (dry-run)"; status_set CLOUDFLARE ok
  else peringatan "masih kosong: ${kurang[*]} (jalankan lagi: sudo bash $0 cloudflare)"; status_set CLOUDFLARE sebagian; fi
}

# ------------------------------------------------------------------ bot persetujuan (terpisah dari bot notifikasi)
persetujuan() {
  judul "Bot persetujuan (tombol Setujui/Tolak)"
  echo "Pakai bot KEDUA dari @BotFather. Bot ini hanya di-poll oleh gerbang persetujuan SOC-IR (gatekeeper), satu-satunya"
  echo "tempat persetujuan T2 untuk semua modul. Bot notifikasi tetap dipakai notify-run.sh dan bot SOC cf-guard."
  echo "ID Telegram Anda (approver) bisa dilihat dengan mengirim pesan ke bot itu lalu membuka .../bot<TOKEN>/getUpdates -> \"from\":{\"id\":...}."
  local tok idp
  tanya tok "Token bot persetujuan" "" 1
  [ -n "$tok" ] || { peringatan "dilewati. Isi nanti: sudo bash $0 persetujuan"; status_set PERSETUJUAN belum; return 0; }
  idp=$(api_json "https://api.telegram.org/bot$tok/getUpdates" | py '
import json,sys
ids={str((u.get("message") or {}).get("from",{}).get("id")) for u in json.load(sys.stdin).get("result",[]) if (u.get("message") or {}).get("from")}
print(" ".join(sorted(ids)))')
  [ -n "$idp" ] && info "id pengirim yang terlihat: $idp"
  local ap; tanya ap "ID Telegram approver (pisahkan koma)" "${idp// /,}"
  mkdir -p /etc/bodyguard; chmod 750 /etc/bodyguard
  local GK=/etc/bodyguard/gatekeeper.env
  [ -f "$GK" ] || install -m 600 -o root -g root /dev/null "$GK"
  set_kv "$GK" BG_APPROVAL_BOT_TOKEN "$tok"
  [ -n "$ap" ] && { set_kv "$GK" BG_APPROVER_IDS "$ap"; set_kv "$GK" BG_APPROVAL_CHAT_ID "${ap%%,*}"; set_kv "$ENV_CF" CG_APPROVER_IDS "$ap"; }
  [ -n "$(get_kv "$GK" BG_HMAC_KEY)" ] || set_kv "$GK" BG_HMAC_KEY "$(openssl rand -hex 32)"
  chmod 600 "$GK"
  # bot SOC cf-guard (tanya-jawab /ringkas, /ip, /blok) memakai bot notifikasi; /blok diajukan ke gerbang di atas
  [ -n "$(get_kv "$ENV_CF" CG_TG_TOKEN)" ] || set_kv "$ENV_CF" CG_TG_TOKEN "$(get_kv "$ENV_WI" TELEGRAM_BOT_TOKEN)"
  [ -n "$(get_kv "$ENV_CF" CG_CHAT_ID)" ] || set_kv "$ENV_CF" CG_CHAT_ID "$(get_kv "$ENV_WI" TELEGRAM_CHAT_ID)"
  set_kv "$ENV_CF" CG_VIEW_CHATS "$(get_kv "$ENV_WI" TELEGRAM_CHAT_ID)"
  [ -n "$(get_kv "$ENV_CF" CG_HMAC_KEY)" ] || set_kv "$ENV_CF" CG_HMAC_KEY "$(openssl rand -hex 32)"
  sukses "gerbang persetujuan tersimpan di $GK (root 600); bot SOC cf-guard di $ENV_CF"
  status_set PERSETUJUAN "$([ -n "$ap" ] && echo ok || echo sebagian)"
}

cek() {
  judul "Uji token tersimpan (token tidak dicetak)"
  t=$(get_kv "$ENV_WI" TELEGRAM_BOT_TOKEN); c=$(get_kv "$ENV_WI" TELEGRAM_CHAT_ID)
  if [ -n "$t" ]; then
    n=$(api_json "https://api.telegram.org/bot$t/getMe" | py 'import json,sys; d=json.load(sys.stdin); print(d["result"]["username"] if d.get("ok") else "")')
    [ -n "$n" ] && sukses "Telegram: bot @$n, chat id ${c:-BELUM DIISI}" || galat "Telegram: token ditolak"
  else peringatan "Telegram: token belum diisi"; fi
  t=$(get_kv "$ENV_CF" CF_AUTH_TOKEN)
  if [ -n "$t" ]; then
    s=$(api_json https://api.cloudflare.com/client/v4/user/tokens/verify "Authorization: Bearer $t" | py 'import json,sys; print(json.load(sys.stdin).get("result",{}).get("status",""))')
    [ "$s" = active ] && sukses "Cloudflare: token aktif" || galat "Cloudflare: token ${s:-tidak bisa dicek}"
  else peringatan "Cloudflare: token belum diisi (cf-guard.py belum bisa dipakai; lapisan lain tetap jalan)"; fi
}

case "${1:-menu}" in
  telegram) telegram;; cloudflare) cloudflare;; persetujuan) persetujuan;; cek) cek;;
  semua) telegram; if ya_tidak "Atur Cloudflare sekarang (bisa nanti)?" n; then cloudflare; else status_set CLOUDFLARE "$(status_get CLOUDFLARE | grep . || echo belum)"; info "Cloudflare dilewati"; fi
         if ya_tidak "Atur bot persetujuan sekarang (bisa nanti)?" n; then persetujuan; fi;;
  menu) echo "1) Telegram  2) Cloudflare  3) Bot persetujuan  4) Cek token"; read -r -t "$BATAS_TANYA" -p "Pilih: " p || p=""
        case "$p" in 1) telegram;; 2) cloudflare;; 3) persetujuan;; 4) cek;; *) echo "tidak ada pilihan";; esac;;
  *) sed -n '2,12p' "$0"; exit 2;;
esac
