#!/usr/bin/env bash
# L3-trigger-ojs.sh - lapisan L3: aturan trigger pada database OJS (Bab III subbab L3, Lampiran 4).
#   Aturan 1  akun baru tertahan disabled          -> trigger yang SUDAH ADA (misalnya p_setdisable_newuser), tidak diubah
#   Aturan 2  INSERT akun berpenanda ditolak       -> trigger baru l3_tolak_penanda (BEFORE INSERT pada users)
#   Aturan 3  penambahan peran admin dicatat       -> trigger baru l3_audit_peran (AFTER INSERT pada user_user_groups)
#                                                     ke tabel l3_audit_log
# Hanya MENAMBAH. Trigger yang sudah ada tidak disentuh. Tidak mencetak password.
#   bash L3-trigger-ojs.sh [rencana] [DB]   hanya membaca: trigger yang ada, isi aturan 1, akun berpenanda yang sudah ada
#   bash L3-trigger-ojs.sh uji DB           pasang + uji mandiri di database SALINAN (misalnya uji_jurnalst_ojs)
#   bash L3-trigger-ojs.sh terapkan         pasang + uji mandiri di database OJS produksi (OJS_DB, minta konfirmasi YA)
#   bash L3-trigger-ojs.sh tes [DB]         uji mandiri saja (semua uji di dalam transaksi, lalu dibatalkan)
#   bash L3-trigger-ojs.sh audit [DB]       20 catatan terakhir penambahan peran admin
#   bash L3-trigger-ojs.sh batal [DB]       hapus dua trigger baru (tabel audit dan isinya tetap ada)
# DB bawaan = OJS_DB di /etc/web-integrity.env. Berkas kerja: /root/trigger-l3/ (root 700).
set -uo pipefail
export LC_ALL=C
[ "$(id -u)" -eq 0 ] || { echo "Jalankan sebagai root (sudo)."; exit 1; }
DIR=/root/trigger-l3; mkdir -p "$DIR"; chmod 700 "$DIR"; umask 077
TS=$(date +%F-%H%M%S)
ENV=${ENV_WI:-/etc/web-integrity.env}
OJS_DB=$(sed -n -E 's/^[[:space:]]*(export[[:space:]]+)?OJS_DB="?([^"]*)"?[[:space:]]*$/\2/p' "$ENV" 2>/dev/null | tail -1)
PENANDA_SUREL='%.internal'            # penanda akun siluman pada insiden (Bab I)
PENANDA_NAMA='^(wpsvc|svc_)'
PESAN='L3: akun berpenanda ditolak'

q() { mysql -N -B -r -e "$1"; }
qd() { mysql -N -B -r "$1" -e "$2"; }

pilih_db() {  # $1 = DB dari argumen (boleh kosong)
  DB=${1:-$OJS_DB}
  [ -n "$DB" ] || { echo "OJS_DB belum diisi di $ENV dan DB tidak disebut. Contoh: bash $0 rencana jurnalst_ojs"; exit 1; }
  [[ $DB =~ ^[A-Za-z0-9_]+$ ]] || { echo "Nama DB tidak valid: $DB"; exit 1; }
  [ "$(q "SELECT COUNT(*) FROM information_schema.SCHEMATA WHERE SCHEMA_NAME='$DB'")" = 1 ] || { echo "Database '$DB' tidak ada."; exit 1; }
  local t
  for t in users user_user_groups user_groups; do
    [ "$(q "SELECT COUNT(*) FROM information_schema.TABLES WHERE TABLE_SCHEMA='$DB' AND TABLE_NAME='$t'")" = 1 ] \
      || { echo "Tabel $t tidak ada di '$DB'. Ini bukan database OJS 3.x?"; exit 1; }
  done
}

sql_pasang() {
  cat <<SQL
CREATE TABLE IF NOT EXISTS l3_audit_log (
  id BIGINT AUTO_INCREMENT PRIMARY KEY,
  waktu DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  user_id BIGINT NOT NULL,
  user_group_id BIGINT NOT NULL,
  role_id BIGINT NOT NULL,
  context_id BIGINT NULL,
  pelaku VARCHAR(190) NOT NULL,
  KEY (waktu)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
DROP TRIGGER IF EXISTS l3_tolak_penanda;
DROP TRIGGER IF EXISTS l3_audit_peran;
DELIMITER //
CREATE DEFINER=CURRENT_USER TRIGGER l3_tolak_penanda BEFORE INSERT ON users FOR EACH ROW
BEGIN
  IF NEW.email LIKE '$PENANDA_SUREL' OR NEW.username REGEXP '$PENANDA_NAMA' THEN
    SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = '$PESAN';
  END IF;
END//
CREATE DEFINER=CURRENT_USER TRIGGER l3_audit_peran AFTER INSERT ON user_user_groups FOR EACH ROW
BEGIN
  INSERT INTO l3_audit_log (user_id, user_group_id, role_id, context_id, pelaku)
  SELECT NEW.user_id, NEW.user_group_id, ug.role_id, ug.context_id, LEFT(USER(), 190)
  FROM user_groups ug WHERE ug.user_group_id = NEW.user_group_id AND ug.role_id IN (1, 16);
END//
DELIMITER ;
SQL
}

rencana() {
  echo "== L3 trigger, database: $DB =="
  echo; echo "Trigger yang sudah ada:"
  local ada; ada=$(qd "$DB" "SELECT TRIGGER_NAME, ACTION_TIMING, EVENT_MANIPULATION, EVENT_OBJECT_TABLE FROM information_schema.TRIGGERS WHERE TRIGGER_SCHEMA='$DB' ORDER BY EVENT_OBJECT_TABLE, ACTION_TIMING")
  if [ -z "$ada" ]; then echo "   (tidak ada)"
  else awk -F'\t' '{printf "   %-26s %s %s pada %s\n",$1,$2,$3,$4}' <<<"$ada"; fi
  echo; echo "Isi trigger lama (untuk mencocokkan aturan 1 dengan naskah):"
  local n
  while IFS=$'\t' read -r n _; do
    case "$n" in ""|l3_tolak_penanda|l3_audit_peran) continue;; esac
    echo "   --- $n"
    qd "$DB" "SELECT ACTION_STATEMENT FROM information_schema.TRIGGERS WHERE TRIGGER_SCHEMA='$DB' AND TRIGGER_NAME='$n'" | sed 's/^/   /'
  done <<<"$ada"
  echo; echo "Akun berpenanda yang SUDAH ada di users (trigger baru tidak mengubahnya; periksa manual bila ada):"
  local s; s=$(qd "$DB" "SELECT user_id, username, disabled FROM users WHERE email LIKE '$PENANDA_SUREL' OR username REGEXP '$PENANDA_NAMA'")
  if [ -z "$s" ]; then echo "   tidak ada"; else awk -F'\t' '{printf "   id=%s %s disabled=%s\n",$1,$2,$3}' <<<"$s"; fi
  echo; echo "Peran yang dicatat aturan 3 (role_id 1 Site Admin, 16 Journal Manager): $(qd "$DB" "SELECT COUNT(*) FROM user_groups WHERE role_id IN (1,16)") grup"
  local sal; sal=$(q "SELECT SCHEMA_NAME FROM information_schema.SCHEMATA WHERE SCHEMA_NAME LIKE 'uji\\_%'" | paste -sd' ' -)
  echo; echo "Yang akan DITAMBAHKAN: tabel l3_audit_log, trigger l3_tolak_penanda, trigger l3_audit_peran."
  echo "Urutan aman: bash $0 uji ${sal:-<db-salinan>}   lalu   bash $0 terapkan"
}

tes() {  # semua uji di satu sesi + transaksi; hasil diperiksa lewat keluaran, lalu ROLLBACK
  local out gagal=0 uid ug
  echo "== Uji mandiri L3 pada $DB =="
  # aturan 2: salin satu baris users yang ada, ganti nama dan surel jadi berpenanda, coba INSERT
  out=$(mysql -N -B --force "$DB" 2>&1 <<SQL
CREATE TEMPORARY TABLE l3_t AS SELECT * FROM users ORDER BY user_id LIMIT 1;
ALTER TABLE l3_t MODIFY user_id BIGINT NULL;
UPDATE l3_t SET user_id = NULL, username = 'svc_uji_l3_$$', email = 'uji$$@contoh.internal';
START TRANSACTION;
INSERT INTO users SELECT * FROM l3_t;
SELECT CONCAT('SISA=', COUNT(*)) FROM users WHERE username = 'svc_uji_l3_$$';
ROLLBACK;
SQL
)
  if grep -qF "$PESAN" <<<"$out" && grep -qx 'SISA=0' <<<"$out"; then echo "[ OK ] aturan 2: INSERT akun berpenanda ditolak trigger"
  else echo "[FAIL] aturan 2: INSERT berpenanda TIDAK ditolak"; sed 's/^/       /' <<<"$out" | grep -v '^ *$' | head -5; gagal=1; fi
  qd "$DB" "DELETE FROM users WHERE username='svc_uji_l3_$$'" 2>/dev/null
  # aturan 3: beri satu akun non-admin peran Journal Manager di dalam transaksi, cek catatan audit, lalu ROLLBACK
  ug=$(qd "$DB" "SELECT user_group_id FROM user_groups WHERE role_id IN (16,1) ORDER BY role_id DESC, user_group_id LIMIT 1")
  uid=$(qd "$DB" "SELECT MIN(u.user_id) FROM users u WHERE NOT EXISTS (SELECT 1 FROM user_user_groups x WHERE x.user_id=u.user_id AND x.user_group_id='${ug:-0}')")
  if [ -z "$ug" ] || [ -z "$uid" ] || [ "$uid" = NULL ]; then echo "[WARN] aturan 3: tidak ada grup admin atau akun untuk diuji"
  else
    out=$(mysql -N -B --force "$DB" 2>&1 <<SQL
START TRANSACTION;
INSERT INTO user_user_groups (user_group_id, user_id) VALUES ($ug, $uid);
SELECT CONCAT('AUDIT=', COUNT(*)) FROM l3_audit_log WHERE user_id = $uid AND user_group_id = $ug AND waktu >= NOW() - INTERVAL 1 MINUTE;
ROLLBACK;
SQL
)
    if grep -qE '^AUDIT=[1-9]' <<<"$out"; then echo "[ OK ] aturan 3: penambahan peran admin tercatat di l3_audit_log"
    else echo "[FAIL] aturan 3: tidak tercatat"; sed 's/^/       /' <<<"$out" | grep -v '^ *$' | head -5; gagal=1; fi
    # pengaman bila tabel bukan InnoDB (ROLLBACK tidak berlaku): hapus sisa uji
    # (akun $uid dipilih karena BELUM punya grup $ug, jadi baris ini pasti baris uji)
    qd "$DB" "DELETE FROM user_user_groups WHERE user_id=$uid AND user_group_id=$ug" 2>/dev/null
    qd "$DB" "DELETE FROM l3_audit_log WHERE user_id=$uid AND user_group_id=$ug AND waktu >= NOW() - INTERVAL 2 MINUTE" 2>/dev/null
  fi
  return $gagal
}

pasang() {
  local f=$DIR/pasang-$DB-$TS.sql
  sql_pasang > "$f"
  qd "$DB" "SELECT CONCAT('-- ', TRIGGER_NAME) FROM information_schema.TRIGGERS WHERE TRIGGER_SCHEMA='$DB'" > "$DIR/sebelum-$DB-$TS.txt"
  if mysql "$DB" < "$f"; then echo "[ OK ] terpasang di $DB (SQL: $f)"; else echo "[FAIL] gagal memasang (SQL: $f)"; return 1; fi
}

case "${1:-rencana}" in
  rencana) pilih_db "${2:-}"; rencana;;
  uji)
    [ $# -ge 2 ] || { echo "Pakai: bash $0 uji <db-salinan>, contoh: bash $0 uji uji_jurnalst_ojs"; exit 1; }
    pilih_db "$2"
    [ "$DB" != "$OJS_DB" ] || { echo "'$DB' adalah DB produksi. Untuk produksi pakai: bash $0 terapkan"; exit 1; }
    pasang && echo && tes;;
  terapkan)
    pilih_db ""; rencana; echo
    read -r -p "Ketik YA untuk memasang dua trigger baru di database produksi $DB: " j
    [ "$j" = YA ] || { echo "Dibatalkan."; exit 0; }
    pasang && echo && { tes || echo "Uji gagal. Lepas dengan: bash $0 batal"; }
    echo; echo "Catat tanggal ini untuk Tabel 4.5 (L3): $(date '+%d/%m/%Y')";;
  tes) pilih_db "${2:-}"; tes;;
  audit)
    pilih_db "${2:-}"
    [ "$(q "SELECT COUNT(*) FROM information_schema.TABLES WHERE TABLE_SCHEMA='$DB' AND TABLE_NAME='l3_audit_log'")" = 1 ] \
      || { echo "Tabel l3_audit_log belum ada di $DB."; exit 0; }
    echo "== 20 penambahan peran admin terakhir di $DB (role 1 = Site Admin, 16 = Journal Manager) =="
    qd "$DB" "SELECT a.waktu, a.user_id, IFNULL(u.username,'-'), a.role_id, IFNULL(a.context_id,'-'), a.pelaku FROM l3_audit_log a LEFT JOIN users u USING(user_id) ORDER BY a.id DESC LIMIT 20" \
      | awk -F'\t' 'BEGIN{printf "%-19s  %-7s %-20s %-4s %-7s %s\n","waktu","user_id","nama","role","konteks","pelaku"} {printf "%-19s  %-7s %-20s %-4s %-7s %s\n",$1,$2,$3,$4,$5,$6; n++} END{if(!n) print "(belum ada catatan)"}';;
  batal)
    pilih_db "${2:-}"
    qd "$DB" "DROP TRIGGER IF EXISTS l3_tolak_penanda; DROP TRIGGER IF EXISTS l3_audit_peran" \
      && echo "[ OK ] dua trigger L3 baru dilepas dari $DB. Tabel l3_audit_log tetap ada."
    ;;
  *) sed -n '2,15p' "$0";;
esac
