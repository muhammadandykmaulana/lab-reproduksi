#!/bin/bash
[ -f /etc/web-integrity.env ] && . /etc/web-integrity.env

# Konfigurasi
IPTABLES_CONF="${IPTABLES_CONF:-/var/opt/iptables-save-after-attack.conf}"
NOTIFY_RUN="${NOTIFY_RUN:-$(dirname "$(readlink -f "$0")")/notify-run.sh}"

# Notifikasi Telegram lewat satu pengirim bersama (notify-run.sh --pesan)
send_telegram_alert() {
    [ -x "$NOTIFY_RUN" ] && printf '%s' "$1" | "$NOTIFY_RUN" --pesan > /dev/null 2>&1
    return 0
}

# Fungsi untuk memeriksa iptables kosong
check_iptables() {
    iptables_status=$(iptables -L -n | grep -v "Chain" | grep -v "target")
    if [ -z "$iptables_status" ]; then
        return 0  # kosong
    else
        return 1  # tidak kosong
    fi
}

# Izinkan container Docker (supabase_default) keluar ke SMTP 465/587.
# Dipasang ulang setelah restore karena iptables-restore menghapus aturan ini.
DOCKER_SUBNET="${DOCKER_SUBNET:-172.19.0.0/16}"   # kosongkan bila tidak memakai Docker
R_FWD="-I FORWARD 1 -s $DOCKER_SUBNET -p tcp -m multiport --dports 587,465 -j ACCEPT"
R_NAT="-I POSTROUTING 1 -s $DOCKER_SUBNET ! -d $DOCKER_SUBNET -j MASQUERADE"

# Sisipkan aturan ke file conf, hanya jika belum ada.
update_conf_docker_smtp() {
  [ -f "$IPTABLES_CONF" ] || return 0
  local need_fwd=1 need_nat=1
  grep -qF -- "-s $DOCKER_SUBNET -p tcp -m multiport --dports 587,465 -j ACCEPT" "$IPTABLES_CONF" && need_fwd=0
  grep -qF -- "-s $DOCKER_SUBNET ! -d $DOCKER_SUBNET -j MASQUERADE" "$IPTABLES_CONF" && need_nat=0
  [ "$need_fwd$need_nat" = "00" ] && return 0

  cp -a "$IPTABLES_CONF" "$IPTABLES_CONF.bak-$(date +%F-%H%M)"
  awk -v fwd="$R_FWD" -v nat="$R_NAT" -v nf="$need_fwd" -v nn="$need_nat" '
    /^\*filter/ {t="filter"}
    /^\*nat/    {t="nat"}
    /^COMMIT/ {
      if (t=="filter" && nf==1 && !f) { print fwd; f=1 }
      if (t=="nat"    && nn==1 && !n) { print nat; n=1 }
      t=""
    }
    { print }' "$IPTABLES_CONF" > "$IPTABLES_CONF.new"

  # Pakai file baru hanya kalau sintaksnya valid.
  if iptables-restore --test < "$IPTABLES_CONF.new" 2>/dev/null; then
    mv "$IPTABLES_CONF.new" "$IPTABLES_CONF"
  else
    rm -f "$IPTABLES_CONF.new"
    echo "WARN: conf tidak diubah (validasi gagal)" >&2
  fi
}

ensure_docker_smtp() {
  update_conf_docker_smtp
  iptables -C FORWARD -s "$DOCKER_SUBNET" -p tcp -m multiport --dports 587,465 -j ACCEPT 2>/dev/null \
    || iptables -I FORWARD 1 -s "$DOCKER_SUBNET" -p tcp -m multiport --dports 587,465 -j ACCEPT

  iptables -t nat -C POSTROUTING -s "$DOCKER_SUBNET" ! -d "$DOCKER_SUBNET" -j MASQUERADE 2>/dev/null \
    || iptables -t nat -I POSTROUTING 1 -s "$DOCKER_SUBNET" ! -d "$DOCKER_SUBNET" -j MASQUERADE
}

# Bodyguard HITL: set ipset ber-timeout + aturan DROP. Dipasang ulang SETELAH setiap restore karena
# iptables-restore menghapus aturan yang tidak ada di conf. Isi set (IP terblokir) tidak terhapus oleh
# iptables-restore dan kedaluwarsa sendiri (TTL 1-24 jam). Tidak melakukan apa pun bila ipset belum terpasang.
ensure_bodyguard_ipset() {
  command -v ipset >/dev/null 2>&1 || return 0
  ipset create bodyguard_v4 hash:ip family inet  timeout 3600 maxelem 65536 -exist
  ipset create bodyguard_v6 hash:ip family inet6 timeout 3600 maxelem 65536 -exist
  iptables  -C INPUT -m set --match-set bodyguard_v4 src -j DROP 2>/dev/null \
    || iptables  -I INPUT 1 -m set --match-set bodyguard_v4 src -j DROP
  ip6tables -C INPUT -m set --match-set bodyguard_v6 src -j DROP 2>/dev/null \
    || ip6tables -I INPUT 1 -m set --match-set bodyguard_v6 src -j DROP
}

# Fungsi untuk merestore iptables
restore_iptables() {
    if [ -f "$IPTABLES_CONF" ]; then
        echo "iptables kosong / tidak sesuai, mencoba merestore konfigurasi dari: $IPTABLES_CONF"
        iptables-restore < "$IPTABLES_CONF"
        if [ $? -eq 0 ]; then
            echo "Berhasil merestore iptables."
        else
            echo "Gagal merestore iptables. Periksa file konfigurasi."
            exit 1
        fi
    else
        echo "File konfigurasi tidak ditemukan: $IPTABLES_CONF"
        exit 1
    fi
}

# Fungsi untuk memeriksa status fail2ban
check_fail2ban() {
    systemctl is-active --quiet fail2ban
    if [ $? -ne 0 ]; then
        echo "fail2ban tidak aktif. Mencoba restart service..."
        systemctl restart fail2ban
        sleep 5
        systemctl is-active --quiet fail2ban
        if [ $? -ne 0 ]; then
            echo "Gagal merestart fail2ban. Mengirim notifikasi Telegram..."
            send_telegram_alert "🚨 ALERT: fail2ban mati dan gagal direstart di server $(hostname). Harap segera cek server VPS!"
        else
            echo "fail2ban berhasil direstart."
        fi
    else
        echo "fail2ban aktif dan berjalan normal."
    fi
}

# Main Program
echo "Memeriksa iptables..."
if check_iptables; then
    restore_iptables
else
    echo "iptables sudah diatur. Tidak perlu merestore konfigurasi."
fi

echo "Memeriksa status fail2ban..."
check_fail2ban
echo "sisipkan ke conf (kalau belum ada)"
ensure_docker_smtp   # sisipkan ke conf (kalau belum ada)
echo "Merestore iptables setiap kali script dijalankan... ORA URUS"
restore_iptables
ensure_docker_smtp
ensure_bodyguard_ipset
