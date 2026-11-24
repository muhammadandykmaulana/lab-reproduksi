# lib/umum.sh - fungsi bersama install.sh, atur-token.sh, lab.sh (di-source, bukan dijalankan)
# shellcheck shell=bash
# folder lab di server: skripsi-lab bila sudah ada (server STAI-ALI), selain itu lab-reproduksi
if [ -z "${LAB_TUJUAN:-}" ]; then
  if [ -d /var/opt/script/tools/skripsi-lab ]; then LAB_TUJUAN=/var/opt/script/tools/skripsi-lab; else LAB_TUJUAN=/var/opt/script/tools/lab-reproduksi; fi
fi
TOOLS=${TOOLS:-/var/opt/script/tools}
ETC_LAB=${ETC_LAB:-/etc/lab-reproduksi}
ENV_WI=${ENV_WI:-/etc/web-integrity.env}
ENV_CD=${ENV_CD:-/etc/cek-disk.env}
ENV_CF=${ENV_CF:-/etc/bodyguard/cloudflare.env}
STATUS_FILE="$ETC_LAB/status"
BATAS_TANYA=${BATAS_TANYA:-60}          # detik menunggu jawaban; lewat = dilewati, bisa diisi nanti
OTOMATIS=${OTOMATIS:-0}

if [ -t 1 ]; then H=$'\e[1;32m'; K=$'\e[1;33m'; M=$'\e[1;31m'; B=$'\e[1m'; N=$'\e[0m'; else H=; K=; M=; B=; N=; fi
judul() { printf '\n%s== %s ==%s\n' "$B" "$*" "$N"; }
sukses() { printf '%s[ OK ]%s %s\n' "$H" "$N" "$*"; }
peringatan() { printf '%s[WARN]%s %s\n' "$K" "$N" "$*"; }
galat() { printf '%s[FAIL]%s %s\n' "$M" "$N" "$*"; }
info() { printf '[INFO] %s\n' "$*"; }

perlu_root() { [ "$(id -u)" -eq 0 ] || { galat "Jalankan sebagai root: sudo bash $0"; exit 1; }; }

cek_os() {  # lab hanya didukung di Ubuntu Server LTS 22.04 dan 24.04
  local id ver
  id=$(. /etc/os-release 2>/dev/null; echo "${ID:-?}")
  ver=$(. /etc/os-release 2>/dev/null; echo "${VERSION_ID:-?}")
  if [ "$id" != ubuntu ] || { [ "$ver" != 22.04 ] && [ "$ver" != 24.04 ]; }; then
    galat "Sistem ini $id $ver. Lab hanya didukung di Ubuntu Server 22.04 LTS atau 24.04 LTS."
    echo "       Distro lain (Debian, CentOS, Windows/WSL, macOS) tidak diuji dan TIDAK dipasang supaya tidak merusak sistem."
    exit 1
  fi
  sukses "Sistem operasi: Ubuntu $ver LTS (didukung)"
}

# tanya VAR "pertanyaan" [bawaan] [rahasia=1]  -> isi variabel VAR; kosong bila dilewati/waktu habis
tanya() {
  local __v=$1 __t=$2 __d=${3:-} __s=${4:-0} __j=""
  if [ "$OTOMATIS" = 1 ] || [ ! -t 0 ]; then printf -v "$__v" '%s' "$__d"; return 0; fi
  if [ "$__s" = 1 ]; then
    read -r -s -t "$BATAS_TANYA" -p "$__t (Enter = lewati, ${BATAS_TANYA} detik): " __j || { echo; info "waktu habis, dilewati"; }
    echo
  else
    read -r -t "$BATAS_TANYA" -p "$__t${__d:+ [$__d]} (${BATAS_TANYA} detik): " __j || { echo; info "waktu habis, pakai bawaan"; }
  fi
  printf -v "$__v" '%s' "${__j:-$__d}"
}

# ya_tidak "pertanyaan" [bawaan y|n] -> kode 0 bila ya
ya_tidak() {
  local j bawaan=${2:-n}
  if [ "$OTOMATIS" = 1 ] || [ ! -t 0 ]; then [ "$bawaan" = y ]; return; fi
  read -r -t "$BATAS_TANYA" -p "$1 [$( [ "$bawaan" = y ] && echo Y/n || echo y/N )] (${BATAS_TANYA} detik): " j || { echo; info "waktu habis, pakai bawaan ($bawaan)"; }
  j=${j:-$bawaan}; case "$j" in y|Y|ya|Ya) return 0;; *) return 1;; esac
}

# set_kv BERKAS KUNCI NILAI : ubah/tambah KUNCI="NILAI" di berkas env (root:root 600). Nilai tidak dicetak.
set_kv() {
  local f=$1 k=$2 v=$3 tmp
  mkdir -p "$(dirname "$f")"; [ -f "$f" ] || { : > "$f"; }
  chown root:root "$f"; chmod 600 "$f"
  case "$v" in *'"'*|*$'\n'*) galat "nilai $k memuat tanda kutip atau baris baru, ditolak"; return 1;; esac
  tmp=$(mktemp "$f.XXXX")
  awk -v k="$k" -v v="$v" 'BEGIN{d=0} $0 ~ "^[[:space:]]*(export[[:space:]]+)?"k"=" {print k"=\""v"\""; d=1; next} {print} END{if(!d) print k"=\""v"\""}' "$f" > "$tmp"
  chmod 600 "$tmp"; mv "$tmp" "$f"
}
get_kv() { [ -f "$1" ] && sed -n -E "s/^[[:space:]]*(export[[:space:]]+)?$2=\"?([^\"]*)\"?[[:space:]]*$/\2/p" "$1" | tail -1; }

status_set() { mkdir -p "$ETC_LAB"; chmod 700 "$ETC_LAB"; touch "$STATUS_FILE"; chmod 600 "$STATUS_FILE"
  grep -v "^$1=" "$STATUS_FILE" > "$STATUS_FILE.tmp" 2>/dev/null; echo "$1=$2" >> "$STATUS_FILE.tmp"; mv "$STATUS_FILE.tmp" "$STATUS_FILE"; }
status_get() { [ -f "$STATUS_FILE" ] && sed -n "s/^$1=//p" "$STATUS_FILE" | tail -1; }
