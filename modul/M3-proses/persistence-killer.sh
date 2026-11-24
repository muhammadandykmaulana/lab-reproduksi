#!/usr/bin/env bash
# persistence-killer.sh v3 - deteksi dan penanganan persistence backdoor (gsocket, ZESTGOD, NineSec, proses yang menyamar jadi kernel thread)
# Dasar: penanganan insiden Oktober 2026 (proses [watchdogd]/[kcached] milik www-data, crontab "SEED PRNG",
#        dropper deploy-all.sh + defunct + gs-pkg di folder aset tema, shell ZESTGOD berizin 0444 dengan tanggal dipalsukan).
#
# USAGE
#   persistence-killer.sh [--dry-run]      default: hanya melaporkan, tidak mengubah apa pun
#   persistence-killer.sh --full           ditambah pemindaian isi PHP (penanda shell), tanggal dipalsukan, izin 0444, flag chattr +i
#   persistence-killer.sh --kill [--yes]   tindakan: crontab www-data dicadangkan lalu dikosongkan, unit systemd mencurigakan
#                                          dinonaktifkan, proses kandidat dihentikan (SIGSTOP, bukti, SIGKILL), berkas dropper dan
#                                          shell dengan ciri kuat dinetralkan di tempat (salin bukti + sha256, chown root, chmod 000)
#   persistence-killer.sh --harden         pembatasan www-data: cron.deny, laporan shell/home/izin; saran aturan iptables (tidak diterapkan)
#   persistence-killer.sh --auto           untuk timer systemd: --kill --yes tanpa tanya, KHUSUS proses milik www-data yang cocok kriteria
#                                          IOC; hanya proses dan crontab (cepat). Tambah --sweep untuk ikut berkas dropper bernama khas.
#                                          Pengaman: berhenti dan mengirim alert bila kandidat > 5 proses (anomali), tidak berjalan bila
#                                          FREEZE bersama aktif (freeze.sh), proses root tidak pernah disentuh. Senyap bila bersih.
#   --include-root   ikutkan proses milik root sebagai kandidat (default: hanya dilaporkan)
#   --no-cron        lewati pemeriksaan crontab (untuk uji)
#   --no-notify      jangan kirim ringkasan Telegram pada mode --kill
# END
# Aturan: mode default hanya membaca. --kill hanya dijalankan admin (bukan oleh SOC-IR T1 atau asisten AI) dan hanya pada proses
# yang cocok dengan kriteria IOC (bukan sekadar nama). Tidak ada penghapusan berkas: bukti disalin dulu, berkas dinetralkan.
# Keluaran memakai penanda [FAIL]/[WARN]/IOC: agar bisa dibungkus notify-run.sh.
# Utilitas bersama yang dipakai: simpan-bukti.py (penyimpanan bukti + SHA-256), freeze.sh (FREEZE), notify-run.sh (Telegram).

set -uo pipefail
VER=3
WEBROOT=${WEBROOT:-/var/www/html}
WWW=${WWW:-www-data}
WWWHOME=${WWWHOME:-/var/www}
TOOLS_DIR=$(dirname "$(readlink -f "$0")")
BUKTI_DIR=${BUKTI_DIR:-/var/opt/bukti}; export BUKTI_DIR
BUKTI=${BUKTI_PY:-$TOOLS_DIR/simpan-bukti.py}
NOTIFY_RUN=${NOTIFY_RUN:-$TOOLS_DIR/notify-run.sh}
# shellcheck disable=SC1091
. "${FREEZE_SH:-$TOOLS_DIR/freeze.sh}"
MODE=dry; FULL=0; YES=0; HARDEN=0; INCROOT=0; NOCRON=0; NOTIFY=1; AUTO=0; SWEEP=0
MAX_AUTO=5

usage() { sed -n '/^# USAGE/,/^# END/p' "$0" | sed 's/^# \{0,1\}//'; }
for a in "$@"; do
  case "$a" in
    --dry-run) MODE=dry;; --kill) MODE=kill;; --full) FULL=1;; --yes) YES=1;; --harden) HARDEN=1;;
    --include-root) INCROOT=1;; --no-cron) NOCRON=1;; --no-notify) NOTIFY=0;; --auto) AUTO=1;; --sweep) SWEEP=1;;
    -h|--help) usage; exit 0;;
    *) echo "argumen tidak dikenal: $a"; usage; exit 2;;
  esac
done
[ "$(id -u)" -eq 0 ] || { echo "Jalankan sebagai root."; exit 2; }
if [ "$AUTO" -eq 1 ]; then
  MODE=kill; YES=1; INCROOT=0; FULL=0; HARDEN=0
fi
if [ "$MODE" = kill ] && freeze_aktif; then
  echo "FREEZE aktif ($FREEZE_FILE): tidak ada tindakan. $(freeze_alasan)"; exit 0
fi
exec 9>/run/persistence-killer.lock 2>/dev/null && { flock -n 9 || { echo "[!] Proses sebelumnya masih jalan."; exit 0; }; }

# ----------------------------------------------------------------- daftar IOC (ubah di sini bila ada varian baru)
SYSPATH_RE='^/(usr|bin|sbin|lib|lib32|lib64|opt|snap)/'
BADEXE_RE='^(/var/www/|/tmp/|/var/tmp/|/dev/shm/|/run/user/|/run/lock/|/home/[^/]+/\.(config|cache|local)/|/root/\.(config|cache|local)/)'
ALLOW_EXE_RE=${ALLOW_EXE_RE:-'/telegram-bot-api/build/|/node_modules/'}   # pengecualian program sah (regex jalur)
FAKE_NAMES='defunct|gs-dbus|gs-netcat|gsocket|kcached|watchdogd|kdevtmpfsi|kinsing|xmrig'
# penanda persistence gsocket pada crontab, rc file, unit
GS_RE='SEED PRNG|DO NOT REMOVE THIS LINE|defunct-kernel|gs-dbus|gs-netcat|gsocket|\.gs-[0-9]'
CRON_RE="$GS_RE|base64[[:space:]]+(-d|--decode)[^|]*\\|[[:space:]]*(ba)?sh|/dev/shm/|/dev/random"
# penanda kuat shell: ZESTGOD, NineSec (berdasarkan nama), dan penanda lama insiden Juli
WS_STRONG='ZESTGOD|IDIOT CREW|zest_bypass|CONFIG ANTI DELETE|HELLO LITESPEED SERVER|BYPASS V2|<<S>>|GH_R0_EXEC|SSInjection|0xNix Encrypted Code'
WS_WEAK='[Nn]ine[Ss]ec|9sec|api\.telegram\.org[^;]{0,200}base64_decode|base64_decode[^;]{0,200}api\.telegram\.org'
DROP_NAMES=( -name defunct -o -name defunct.dat -o -name gs-pkg -o -name deploy-all.sh -o -name '.gs-*' -o -name 'gs-netcat*' -o -name 'gs-dbus*' -o -name 'gsocket*' )

NF=0; NW=0; NK=0; NA=0
ok()   { echo "  [ OK ] $*"; }
info() { echo "  [INFO] $*"; }
warn() { NW=$((NW+1)); echo "  [WARN] $*"; }
fail() { NF=$((NF+1)); echo "  [FAIL] $*"; }
ioc()  { NF=$((NF+1)); echo "  IOC: $*"; }
act()  { NA=$((NA+1)); echo "  [AKSI] $*"; }
sec()  { echo; echo "== $* =="; }
clean() { printf '%s' "$1" | tr -c '[:print:]' '?' | cut -c1-"${2:-160}"; }

TS=$(date +%Y%m%dT%H%M%S)
KASUS="pk-$TS"; RUNDIR="$BUKTI_DIR/$KASUS"
TMP=$(mktemp -d /run/pk.XXXXXX); trap 'rm -rf "$TMP"' EXIT
if [ "$AUTO" -eq 1 ]; then exec 3>&1; exec >"$TMP/auto.out" 2>&1; fi
flush_auto() { [ "$AUTO" -eq 1 ] && [ $((NF + NA + NK)) -gt 0 ] && cat "$TMP/auto.out" >&3; return 0; }
if [ "$MODE" = kill ] && [ "$AUTO" -eq 0 ]; then
  mkdir -p "$RUNDIR" && chmod 700 "$BUKTI_DIR" "$RUNDIR" 2>/dev/null
  exec > >(tee -a "$RUNDIR/laporan.txt") 2>&1
fi
echo "persistence-killer v$VER $(hostname) $(date '+%F %T') mode=$MODE full=$FULL"

# ----------------------------------------------------------------- 1. proses
declare -a CAND=(); declare -A WHY EXE ARGV USR PEER
tree_of() { local p=$1 c; echo "$p"; for c in $(pgrep -P "$p" 2>/dev/null); do tree_of "$c"; done; }
scan_procs() {
  CAND=(); WHY=(); EXE=(); ARGV=(); USR=(); PEER=()
  local conns d p exe args ppid user why weak base peer
  conns=$(ss -tnpH state established 2>/dev/null)
  for d in /proc/[0-9]*; do
    p=${d#/proc/}
    [ "$p" = "$$" ] && continue
    [ "$p" -le 2 ] 2>/dev/null && continue
    exe=$(readlink "$d/exe" 2>/dev/null) || continue
    [ -n "$exe" ] || continue                                   # kernel thread asli / zombie: tidak punya program
    ppid=$(awk '/^PPid:/{print $2}' "$d/status" 2>/dev/null)
    [ "$ppid" = "2" ] && continue                               # anak kthreadd = kernel thread
    grep -qE 'docker|containerd|kubepods|lxc' "$d/cgroup" 2>/dev/null && continue
    args=$(tr '\0' ' ' < "$d/cmdline" 2>/dev/null); args=${args% }
    user=$(stat -c %U "$d" 2>/dev/null)
    why=""; weak=""
    if [[ "$args" =~ ^\[[^]]+\]$ ]]; then
      why+="menyamar kernel thread '$args' tetapi punya program di disk; "
    fi
    case "$exe" in *" (deleted)"|/memfd:*) weak="program terhapus dari disk / memfd";; esac
    if [[ "$exe" =~ $BADEXE_RE ]] && ! [[ "$exe" =~ $ALLOW_EXE_RE ]]; then why+="program di folder yang dapat ditulis; "; fi
    base=$(basename "${exe% (deleted)}")
    if [[ "$base" =~ ^($FAKE_NAMES)$ ]] && ! [[ "$exe" =~ $SYSPATH_RE ]]; then why+="nama program khas backdoor di luar folder sistem; "; fi
    if [ -z "$why" ]; then
      # program terhapus saja BUKAN dasar kill: wajar setelah apt upgrade (nginx, php-fpm, mariadb masih memakai biner lama)
      [ -n "$weak" ] && ! [[ "$exe" =~ $SYSPATH_RE ]] && warn "pid=$p user=$user: $weak, periksa manual: exe=$(clean "$exe" 100)"
      continue
    fi
    [ -n "$weak" ] && why+="$weak; "
    peer=$(echo "$conns" | grep "pid=$p," | awk '{print $4}' | sort -u | tr '\n' ' ')
    if [ "$user" = root ] && [ "$INCROOT" -eq 0 ]; then
      warn "pid=$p milik root, dilewati (pakai --include-root bila yakin): exe=$(clean "$exe" 100) alasan: $why"
      continue
    fi
    CAND+=("$p"); WHY[$p]=$why; EXE[$p]=$exe; ARGV[$p]=$args; USR[$p]=$user; PEER[$p]=$peer
  done
}
sec "1. Proses (kriteria program, bukan hanya nama)"
scan_procs
if [ ${#CAND[@]} -eq 0 ]; then ok "Tidak ada proses yang menyamar / berjalan dari folder writable"; fi
for p in "${CAND[@]}"; do
  ioc "pid=$p user=${USR[$p]} exe=$(clean "${EXE[$p]}" 120) args=[$(clean "${ARGV[$p]}" 60)] alasan: ${WHY[$p]}${PEER[$p]:+koneksi: ${PEER[$p]}}"
done

# ----------------------------------------------------------------- 2. cron
CRON_BAD=0
sec "2. Cron"
if [ "$NOCRON" -eq 1 ]; then info "dilewati (--no-cron)"; else
  crontab -u "$WWW" -l > "$TMP/cron-www" 2>/dev/null
  if grep -qvE '^[[:space:]]*(#|$)' "$TMP/cron-www" 2>/dev/null || grep -qE "$GS_RE" "$TMP/cron-www" 2>/dev/null; then
    CRON_BAD=1
    if grep -qE "$CRON_RE" "$TMP/cron-www"; then ioc "crontab $WWW berisi pola persistence: $(grep -E "$CRON_RE" "$TMP/cron-www" | head -1 | cut -c1-110)..."
    else fail "crontab $WWW tidak kosong ($(grep -cvE '^[[:space:]]*(#|$)' "$TMP/cron-www") baris)"; fi
  else ok "crontab $WWW kosong"; fi
  for f in /etc/crontab /etc/cron.d/* /var/spool/cron/crontabs/*; do
    [ -f "$f" ] || continue
    [ "$f" = "/var/spool/cron/crontabs/$WWW" ] && continue
    grep -qE "$CRON_RE" "$f" 2>/dev/null && ioc "$f berisi pola persistence (hanya dilaporkan, tidak diubah)"
  done
fi

# ----------------------------------------------------------------- 3. tempat persistence lain
declare -a UNITS=() NEUT=(); declare -A SEEN
if [ "$AUTO" -eq 0 ] || [ "$SWEEP" -eq 1 ]; then
sec "3. rc file, systemd, ld.so.preload, kunci SSH"
RCF=("$WWWHOME/.profile" "$WWWHOME/.bashrc" "$WWWHOME/.bash_profile" "$WWWHOME/.bash_login" /root/.bashrc /root/.profile /root/.bash_profile
     /etc/profile /etc/bash.bashrc /etc/rc.local)
for f in /etc/profile.d/* /home/*/.bashrc /home/*/.profile; do [ -f "$f" ] && RCF+=("$f"); done
n=0; for f in "${RCF[@]}"; do [ -f "$f" ] && grep -qE "$GS_RE" "$f" 2>/dev/null && { ioc "penanda persistence di $f (hanya dilaporkan, bersihkan manual)"; n=1; }; done
[ $n -eq 0 ] && ok "rc file bersih dari penanda gsocket"
for u in /etc/systemd/system/*.service "$WWWHOME"/.config/systemd/user/*.service /root/.config/systemd/user/*.service; do
  [ -f "$u" ] || continue
  if grep -qE "$GS_RE|^ExecStart=[^#]*(/tmp/|/dev/shm/|/var/www/|/var/tmp/)" "$u" 2>/dev/null; then ioc "unit systemd mencurigakan: $u"; UNITS+=("$u"); fi
done
[ ${#UNITS[@]} -eq 0 ] && ok "tidak ada unit systemd mencurigakan"
[ -s /etc/ld.so.preload ] && ioc "/etc/ld.so.preload tidak kosong: $(head -c 120 /etc/ld.so.preload)" || ok "ld.so.preload kosong"
[ -e "$WWWHOME/.ssh/authorized_keys" ] && ioc "authorized_keys ada untuk $WWW" || ok "tidak ada authorized_keys untuk $WWW"
[ -d "$WWWHOME/.config/htop" ] && ioc "$WWWHOME/.config/htop ada (lokasi pasang gsocket)"

# ----------------------------------------------------------------- 4. berkas
sec "4. Berkas dropper dan shell"
DIRS=(); for d in "$WEBROOT" "$WWWHOME/.config" "$WWWHOME/.local" /tmp /var/tmp /dev/shm /root/.config /root /home/*/.config; do [ -d "$d" ] && DIRS+=("$d"); done
while IFS= read -r -d '' f; do
  case "$f" in "$BUKTI_DIR"/*|*.evd|*.bin) continue;; esac
  [ -n "${SEEN[$f]:-}" ] && continue; SEEN[$f]=1
  st=$(stat -c 'pemilik=%U izin=%a ukuran=%s' "$f" 2>/dev/null)
  if [ "$(stat -c '%U %a' "$f" 2>/dev/null)" = "root 0" ]; then info "sudah dinetralkan (root, izin 000): $f"; continue; fi
  case "$f" in
    /root/*) ioc "dropper/penanda di $f ($st): hanya dilaporkan, periksa apakah dijalankan sebagai root";;
    *)       ioc "dropper/penanda: $f ($st)"; NEUT+=("$f");;
  esac
done < <(find "${DIRS[@]}" -xdev -maxdepth 6 \( "${DROP_NAMES[@]}" \) -not -path '*/proc/*' -print0 2>/dev/null)
[ ${#NEUT[@]} -eq 0 ] && ok "tidak ada berkas dropper bernama khas"
fi
if [ "$FULL" -eq 1 ] && [ -d "$WEBROOT" ]; then
  info "pemindaian penuh isi PHP di $WEBROOT (nice/ionice)"
  while IFS= read -r f; do
    [ -f "$f" ] || continue
    case "$f" in */vendor/*|*/node_modules/*) continue;; esac
    if grep -qE "$WS_STRONG" "$f" 2>/dev/null; then ioc "penanda KUAT shell: $f (baris $(grep -nE "$WS_STRONG" "$f" | head -1 | cut -d: -f1))"; NEUT+=("$f")
    elif grep -qE "$WS_WEAK" "$f" 2>/dev/null; then warn "penanda lemah shell (periksa manual): $f"; fi
  done < <(nice -n 10 ionice -c2 -n7 find "$WEBROOT" -xdev -type f \( -iname '*.php' -o -iname '*.phtml' -o -iname '*.phar' -o -iname '*.php[0-9]' \) -size -2M 2>/dev/null)
  # tanggal dipalsukan: mtime jauh lebih tua daripada waktu lahir berkas, pada folder aset/data
  while IFS=' ' read -r b m f; do
    [ "$b" -gt 0 ] 2>/dev/null || continue
    [ $((b - m)) -gt 86400 ] && warn "TANGGAL DIPALSUKAN (mtime $(date -d @"$m" +%F), lahir $(date -d @"$b" +%F)): $f"
  done < <(find "$WEBROOT" -xdev -type f \( -iname '*.php' -o -iname '*.phtml' \) \( -path '*/assets/*' -o -path '*/uploads/*' -o -path '*/images/*' -o -path '*/fonts/*' -o -path '*/languages/*' -o -path '*/files/*' -o -path '*/public/*' \) -print0 2>/dev/null | xargs -0 -r stat -c '%W %Y %n' 2>/dev/null)
  # PHP berizin 0444 milik www-data di folder aset (pola "anti delete") dan flag immutable
  while IFS= read -r f; do
    warn "PHP read-only milik $WWW di folder aset/data (pola anti-delete): $f"
    lsattr -d -- "$f" 2>/dev/null | awk '{print $1}' | grep -q i && fail "flag immutable (chattr +i) pada $f"
  done < <(find "$WEBROOT" -xdev -type f \( -iname '*.php' -o -iname '*.phtml' \) -user "$WWW" -perm 0444 \( -path '*/assets/*' -o -path '*/uploads/*' -o -path '*/images/*' -o -path '*/fonts/*' -o -path '*/languages/*' -o -path '*/files/*' -o -path '*/public/*' \) 2>/dev/null | head -50)
fi

# ----------------------------------------------------------------- 5. pembatasan www-data
if [ "$HARDEN" -eq 1 ]; then
  sec "5. Pembatasan $WWW"
  if ! grep -qx "$WWW" /etc/cron.deny 2>/dev/null; then
    if [ "$MODE" = kill ]; then echo "$WWW" >> /etc/cron.deny && chmod 644 /etc/cron.deny && act "$WWW ditambahkan ke /etc/cron.deny"
    else info "akan menambahkan $WWW ke /etc/cron.deny (jalankan dengan --kill --harden)"; fi
  else ok "$WWW sudah ada di /etc/cron.deny"; fi
  sh=$(getent passwd "$WWW" | cut -d: -f7)
  case "$sh" in */nologin|*/false) ok "shell $WWW: $sh";; *) warn "shell $WWW: $sh (sebaiknya nologin; periksa dulu pemakaian 'sudo -u $WWW wp' di script audit)";; esac
  info "pemilik/izin $WWWHOME: $(stat -c '%U:%G %a' "$WWWHOME" 2>/dev/null)"
  [ -w "$WWWHOME" ] && sudo -u "$WWW" test -w "$WWWHOME" 2>/dev/null && warn "$WWW dapat menulis ke $WWWHOME (tempat .config/htop, .ssh, .bashrc)"
  info "saran (tidak diterapkan otomatis): catat koneksi keluar baru milik $WWW"
  info "  iptables -I OUTPUT -m owner --uid-owner $WWW -m conntrack --ctstate NEW -j LOG --log-prefix 'WWW-OUT '"
fi

# ----------------------------------------------------------------- 6. tindakan
# bukti lewat fungsi bersama simpan-bukti.py: salinan 0400 bernama SHA-256 + metadata + MANIFEST.tsv di $RUNDIR
bukti_teks() { /usr/bin/python3 -I "$BUKTI" simpan-stdin --kasus "$KASUS" --label "$1" > /dev/null 2>&1; }  # isi dari stdin
bukti_berkas() { /usr/bin/python3 -I "$BUKTI" simpan --kasus "$KASUS" -- "$@" > /dev/null 2>&1; }
ev_proc() { # pid: konteks proses + salinan program, sebelum SIGKILL
  local p=$1
  { echo "waktu: $(date -u +%FT%TZ)"; ls -l "/proc/$p/exe" "/proc/$p/cwd"; head -12 "/proc/$p/status"
    echo "-- cmdline"; tr '\0' ' ' < "/proc/$p/cmdline"; echo
    echo "-- environ"; tr '\0' '\n' < "/proc/$p/environ"
    echo "-- fd"; ls -l "/proc/$p/fd"
    echo "-- koneksi"; ss -tnp 2>/dev/null | grep "pid=$p,"
    echo "-- pstree"; pstree -aps "$p"; } 2>&1 | bukti_teks "proc-$p-konteks"
  head -c 52428800 "/proc/$p/exe" 2>/dev/null | bukti_teks "proc-$p-exe"
}
neut() { # path: simpan bukti, lalu chown root dan chmod 000 (tidak dihapus)
  local f=$1
  [ -e "$f" ] || return
  stat -c 'target=%n pemilik=%U izin=%a ukuran=%s lahir=%w mtime=%y ctime=%z' "$f" 2>&1 | bukti_teks "stat:$(basename "$f")"
  if [ -d "$f" ]; then find "$f" -type f -print0 | xargs -0 -r /usr/bin/python3 -I "$BUKTI" simpan --kasus "$KASUS" -- > /dev/null 2>&1
  else bukti_berkas "$f"; fi
  lsattr -d -- "$f" 2>/dev/null | awk '{print $1}' | grep -q i && chattr -i -- "$f" 2>/dev/null
  if [ -d "$f" ]; then chown -R root:root "$f"; chmod -R 000 "$f"
  else chown root:root "$f"; chmod 000 "$f"; fi
  act "dinetralkan (bukti di $RUNDIR): $f"
}
send_tg() { [ -x "$NOTIFY_RUN" ] && printf '%s' "$1" | "$NOTIFY_RUN" --pesan > /dev/null 2>&1; return 0; }

if [ "$MODE" = kill ]; then
  sec "6. Tindakan (--kill)"
  if [ "$AUTO" -eq 1 ]; then
    # lingkup otomatis: hanya proses dan berkas milik $WWW; unit systemd tidak disentuh
    keep=(); for p in "${CAND[@]}"; do [ "${USR[$p]}" = "$WWW" ] && keep+=("$p") || warn "pid=$p milik ${USR[$p]}, bukan $WWW: tidak ditindak otomatis"; done
    CAND=("${keep[@]}"); UNITS=()
    keepf=(); for f in "${NEUT[@]}"; do [ "$(stat -c %U "$f" 2>/dev/null)" = "$WWW" ] && keepf+=("$f"); done
    NEUT=("${keepf[@]}")
    if [ ${#CAND[@]} -gt "$MAX_AUTO" ]; then
      m="persistence-killer ANOMALI $(hostname): ${#CAND[@]} proses kandidat (> $MAX_AUTO). Tidak ada tindakan otomatis. Periksa manual: persistence-killer.sh --dry-run"
      echo "  [FAIL] $m"; NF=$((NF+1)); send_tg "$m"; flush_auto; exit 1
    fi
  fi
  if [ ${#CAND[@]} -eq 0 ] && [ $CRON_BAD -eq 0 ] && [ ${#UNITS[@]} -eq 0 ] && [ ${#NEUT[@]} -eq 0 ]; then
    info "tidak ada yang perlu ditindak"
  else
    mkdir -p "$RUNDIR" && chmod 700 "$BUKTI_DIR" "$RUNDIR" 2>/dev/null
    echo "  Rencana: crontab $WWW $([ $CRON_BAD -eq 1 ] && echo 'dicadangkan lalu dikosongkan' || echo 'tidak diubah'); unit: ${#UNITS[@]}; proses: ${#CAND[@]}; berkas dinetralkan: ${#NEUT[@]}"
    if [ "$YES" -ne 1 ]; then
      read -rp "  Lanjutkan? Bukti disalin ke $RUNDIR dulu. [y/N] " a
      [ "$a" = y ] || { echo "  Dibatalkan, tidak ada yang diubah."; exit 1; }
    fi
    # urutan: cron dulu (agar tidak hidup lagi), unit, proses, berkas
    if [ $CRON_BAD -eq 1 ] && [ "$NOCRON" -eq 0 ]; then
      bukti_teks "crontab-$WWW" < "$TMP/cron-www"
      crontab -u "$WWW" -r 2>/dev/null && act "crontab $WWW dicadangkan ke $RUNDIR lalu dikosongkan"
    fi
    for u in "${UNITS[@]}"; do
      n=$(basename "$u")
      case "$u" in /etc/systemd/system/*) systemctl disable --now "$n" >/dev/null 2>&1; act "unit $n dinonaktifkan";; esac
      neut "$u"
    done
    [ ${#UNITS[@]} -gt 0 ] && systemctl daemon-reload 2>/dev/null
    for p in "${CAND[@]}"; do
      [ -d "/proc/$p" ] || continue
      pids=$(tree_of "$p")
      for q in $pids; do kill -STOP "$q" 2>/dev/null; done      # bekukan dulu supaya tidak sempat memunculkan proses baru
      ev_proc "$p"
      for q in $pids; do kill -KILL "$q" 2>/dev/null && { NK=$((NK+1)); act "SIGKILL pid=$q (induk pid=$p, bukti proc-$p)"; }; done
    done
    for f in "${NEUT[@]}"; do neut "$f"; done
    chmod 600 "$RUNDIR/laporan.txt" 2>/dev/null
    sleep 2
    scan_procs
    if [ ${#CAND[@]} -gt 0 ]; then fail "masih ada proses kandidat setelah SIGKILL: ${CAND[*]}"; else ok "pemeriksaan ulang: tidak ada proses kandidat"; fi
    info "periksa lagi setelah menit 00 (cron per jam) dan sesudah 24 jam: ss -tnp, ps, crontab -u $WWW -l"
  fi
fi

echo; echo "=============================================="
echo "RINGKASAN persistence-killer v$VER: mode=$MODE temuan=$NF peringatan=$NW proses_dihentikan=$NK aksi=$NA"
[ "$MODE" = kill ] && echo "Bukti: $RUNDIR"
if [ "$MODE" = kill ] && [ "$NOTIFY" -eq 1 ] && [ $((NA + NK)) -gt 0 ]; then
  send_tg "persistence-killer $(hostname): $([ "$AUTO" -eq 1 ] && echo "AUTO-KILL" || echo "--kill") dijalankan. temuan=$NF proses_dihentikan=$NK aksi=$NA. Bukti: $RUNDIR"
fi
flush_auto
[ "$NF" -gt 0 ] && exit 1
exit 0
