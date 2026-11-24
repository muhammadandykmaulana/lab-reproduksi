# Bodyguard HITL (SOC-IR) - bagian modul M5 Penjaga Keputusan

Sistem deterministik berjenjang **T0-T3** yang mengikat kontrol yang sudah ada (`web-integrity-cek.sh`,
`collect3_evidence.sh`, `fw.sh`, `notify-run.sh`) dengan prinsip **gagal aman ke alert/log, bukan blokir massal**.
LLM (bila dipakai nanti) hanya **penasihat read-only**: tidak ada jalur kode dari jawaban LLM ke eksekusi.

Hanya pustaka standar Python 3 (diuji di 3.8 dan 3.13; sintaks & API diperiksa untuk 3.6). Tidak perlu `pip` di server.

---

## 1. Tingkatan aksi

| Tier | Siapa yang memutuskan | Aksi | Sifat |
|---|---|---|---|
| **T0** Amati | otomatis, selalu jalan | pindai IOC file (0xNix, yoibre, polyglot EXIF, webshell umum), log akses nginx, audit akun WP/OJS (`wpsvc_*`, admin baru), plugin samaran (`security-headers-manager-*`), laporan `web-integrity-cek.sh` | read-only |
| **T1** Otomatis | policy deterministik + circuit breaker | kunci file PHP liar di folder data (bukti dulu, lalu `chown root:root` + `chmod 000`); blokir IP 1-24 jam lewat cf-guard (daftar IP Cloudflare) | reversibel, ber-TTL, maks 20 IP/jam & 5 file/jam |
| **T2** Persetujuan 1 orang | admin via **bot approval terpisah** (SATU gerbang untuk semua modul) | karantina permanen (rename tanpa `.php`), nonaktifkan akun WP/OJS, matikan plugin samaran, terima baseline integritas, usulan blokir cf-guard | reversibel, perintah rollback dicetak |
| **T3** Manual | admin | rotasi rahasia, migrasi, reset DB | sistem **hanya mencetak checklist Markdown** |

## 2. Arsitektur

```
 systemd timer (10 menit)                                      Telegram
 bodyguard run  [user guard]                                   +--------------------+
   T0 detektor -> policy -+-> T1 -> breaker -> sudo -n bg-root -> chmod/cf-guard   |  bot ALERT         |
                          |                       [root, validasi ulang]          |  (notifikasi saja) |
                          +-> T2 antre (SQLite) ---------------------+            +--------------------+
                          +-> T3 checklist .md                       |
                          +-> alert tersanitasi ---------------------)----------> bot ALERT
                                                                     v
 gatekeeper_bot.py [user guard] <== tombol ber-HMAC, TTL 30 menit ==> bot APPROVAL (allowlist user_id)
        +-> eksekutor T2 -> sudo -n bg-root quarantine/plugin-disable/integrity-accept
        +-> mysql (hak UPDATE per-kolom) untuk nonaktifkan akun
```

## 3. Jaminan keamanan dan di mana diuji

| Jaminan | Ditegakkan di | Diuji di |
|---|---|---|
| `guard` tidak punya izin `chmod`/`cf-guard` langsung; hanya pintu `bg-root` dengan sub-perintah tetap | `etc/sudoers.d/guard-bodyguard` | `test_repo_hygiene` (visudo + larangan) |
| Path ditelusuri dari `/` dengan `O_NOFOLLOW`; symlink, hardlink, `..`, FIFO, path di luar root = tolak | `sbin/bg-root` | `test_bg_root` (juga mode root sungguhan) |
| Bukti (salinan + SHA256 + metadata) disimpan **sebelum** izin diubah; chmod pada inode yang sama dengan yang di-hash | `bg-root contain` | `test_bg_root` |
| `chown root` sebelum `chmod 000` (pemilik file selalu bisa membatalkan chmod miliknya) | `bg-root` | `test_bg_root` (privileged) |
| Breaker: 21 blokir/6 chmod per 60 menit = trip, T1 pindah ke T0, latched sampai reset konsol; galat = tolak; atomik antar-proses | `breaker.py` | `test_breaker` (termasuk 8 proses paralel) |
| Rate cap kedua di sisi root (jaring bila `guard` disusupi) | `bg-root` | `test_bg_root` |
| IP Cloudflare/admin/loopback/privat tidak pernah diblokir; whitelist gagal dimuat = semua blokir mati | `whitelist.py` + `bg-root` | `test_whitelist`, `test_bg_root` |
| Tombol T2: HMAC mengikat keputusan, nonce, waktu, request, digest aksi, chat; TTL 30 menit = TOLAK; nonce sekali pakai | `signing.py`, `gatekeeper.py` | `test_signing`, `test_gatekeeper` |
| Isi aksi yang diubah di DB setelah pesan terbit tidak akan dieksekusi | `gatekeeper.py` | `test_gatekeeper` |
| `/freeze` membekukan T1 **dan** eksekusi T2; unfreeze hanya dari konsol | `breaker.py`, `gatekeeper.py` | `test_gatekeeper`, `test_breaker` |
| Data penyerang disanitasi (kontrol, ANSI, bidi/zero-width, panjang) dan tidak pernah masuk shell/SQL | `sanitizer.py`, `mysqlcli.py`, `t2.py` | `test_sanitizer`, `test_t2` |
| Regex IOC linear (anti ReDoS) | `detectors/rules.py` | `test_detectors` |
| Kode sumber ASCII murni (anti "Trojan Source"), API Python 3.6 | seluruh repo | `test_repo_hygiene` |

## 4. Peta file & izin di server

| Path | Pemilik | Mode | Isi |
|---|---|---|---|
| `/opt/bodyguard/` | root:root | 0755/0644 | kode (guard **tidak** bisa mengubah kodenya sendiri) |
| `/usr/local/sbin/bg-root` | root:root | 0755 | satu-satunya pintu root |
| `/etc/sudoers.d/guard-bodyguard` | root:root | 0440 | izin sudo `guard` |
| `/etc/bodyguard/` | root:guard | 0750 | konfigurasi |
| `/etc/bodyguard/bodyguard.conf` | root:guard | 0640 | config utama |
| `/etc/bodyguard/root.conf` | root:root | 0644 | config pintu root (root data, collect3, accept_cmd) |
| `/etc/bodyguard/alert.env`, `gatekeeper.env` | root:root | **0600** | token bot, kunci HMAC, allowlist (dibaca systemd) |
| `/etc/bodyguard/mysql-ro.cnf` | root:guard | 0640 | DB hanya SELECT (pemindai) |
| `/etc/bodyguard/mysql-t2.cnf` | root:guard-approve | 0640 | DB UPDATE per-kolom (hanya gatekeeper) |
| `/var/lib/bodyguard/` | guard:guard | 2770 | `state.db`, checklist T3, brief LLM (dibagi dengan gatekeeper lewat grup) |
| `/var/lib/bodyguard-evidence/<INC>/` | root:root | 0700/0400 | salinan bukti + metadata JSON |
| `/var/lib/bodyguard-root/` | root:root | 0700 | rate cap sisi root |
| `/var/log/bodyguard/bodyguard.jsonl` | guard:guard | 0660 | log JSON (satu event per baris) |

**Dua user**: `guard` menjalankan pemindai (memproses data penyerang) dan hanya boleh `sudo` aksi T1.
`guard-approve` menjalankan gatekeeper Telegram dan hanya boleh `sudo` aksi T2. Bug di pemindai tidak bisa
langsung menjalankan T2, tidak bisa membaca kunci HMAC (beda uid), dan tidak bisa membaca `mysql-t2.cnf`.

## 5. Pemasangan di lab reproduksi

Di lab, modul ini dipasang lewat `lab.sh` (menu SOC-IR) yang memanggil `tools/install.sh --plan` lalu `--apply`.
Isi `/etc/bodyguard/bodyguard.conf` sesuai situs Anda (contoh: `etc/bodyguard.conf.example`), tetap pada `mode = dry-run`
sampai temuan T0 sudah diperiksa, lalu aktifkan timer: `systemctl enable --now bodyguard-scan.timer`.

## 6. Runbook

| Situasi | Tindakan |
|---|---|
| Bodyguard salah sasaran / ragu | FREEZE bersama (juga menghentikan cf-guard dan M3 --auto): Telegram `/freeze alasan` atau `sudo -u guard /opt/bodyguard/bin/bodyguard freeze --reason "..."`. T0 & alert tetap jalan. |
| Cabut freeze | **Hanya konsol**: `sudo -u guard /opt/bodyguard/bin/bodyguard unfreeze --reason "..."` atau `penjaga.sh unfreeze "..."` |
| Breaker trip (alert darurat) | Periksa alert & `bodyguard status`, lalu `sudo -u guard /opt/bodyguard/bin/bodyguard reset-breaker --reason "..."` |
| Batalkan blokir IP | `cf-guard.py remove <IP>` (atau tunggu TTL habis; dicabut cf-guard run berikutnya) |
| Batalkan kunci file T1 | perintah persis ada di `bodyguard status` (kolom rollback), mis. `chown 33:33 -- '<path>' && chmod 0644 -- '<path>'` |
| Batalkan T2 | perintah rollback tercetak di pesan Telegram setelah eksekusi dan di `bodyguard status` |
| Lihat bukti | `/var/opt/bukti/<INC-ID>/` (root; MANIFEST.tsv, sama dengan modul lain) |
| Checklist T3 | `/var/lib/bodyguard/checklists/<INC-ID>.md` |
| Brief untuk LLM penasihat | `sudo -u guard /opt/bodyguard/bin/bodyguard brief <INC-ID>` -> `/var/lib/bodyguard/briefs/` |
| Log | `journalctl -u bodyguard-scan -u bodyguard-gatekeeper`, `/var/log/bodyguard/bodyguard.jsonl` |
| Perbarui daftar Cloudflare | `/opt/bodyguard/tools/update-cloudflare-ips.sh` (cek) lalu `--apply`; samakan `set_real_ip_from` nginx |

## 7. Keputusan desain yang perlu diketahui

1. **TTL kunci file (T1) = tenggat keputusan, bukan pemulihan otomatis.** Memulihkan izin webshell secara otomatis sama dengan
   mengaktifkannya kembali. File tetap terkunci; usulan karantina T2 diajukan ulang tiap 6 jam bila kedaluwarsa tanpa jawaban.
   Blokir IP memakai TTL di cf-guard (1-24 jam); entri kedaluwarsa dicabut cf-guard pada run berikutnya.
2. **`/freeze` membekukan T1 dan eksekusi T2** (lebih luas dari spesifikasi T1 saja). Kill-switch yang setengah jalan membingungkan saat darurat.
3. **Asimetri wewenang**: membuat sistem lebih aman boleh dari jauh (`/freeze`, `--dry-run`); membuatnya lebih agresif hanya dari konsol/config milik root (unfreeze, reset breaker, `mode=enforce`).
4. **Cloudflare**: bila situs di belakang Cloudflare, pengunjung tiba dari IP Cloudflare. Karena itu blokir IP dilakukan di Cloudflare lewat cf-guard (satu jalur blokir), bukan ipset di server.
   Pasang `etc/nginx-realip-cloudflare.conf.example` agar `$remote_addr` = IP asli. Jangan pernah mencatat `X-Forwarded-For` mentah sebagai IP (bisa dipalsukan untuk "memfitnah" IP lain).
5. **File kode (tema/plugin/core) tidak pernah dikenai T1.** IOC di kode hanya alert, usulan matikan plugin (T2), dan checklist T3.
6. **PHP apa pun di folder data dianggap mencurigakan** (kecuali `index.php` "Silence is golden", `data_php_allow`, atau hash jinak). Karena itu wajib dry-run dulu.
7. **Breaker bisa dipicu penyerang** (mis. mengunggah 6 file PHP) untuk mematikan T1. Ini sesuai spesifikasi (gagal ke T0, bukan blokir massal); selama trip, alert pengingat dikirim tiap jam agar tidak terlupa.
8. **Skor IP anti-fitnah**: hanya POST sukses ke URL webshell yang langsung critical. GET sukses (bisa dipicu `<img src>` dari pengunjung sah) bernilai kecil; tiap aturan+URI dihitung sekali per IP per siklus.
9. Audit akun: WordPress single-site (multisite belum), OJS 3.x role 1 (site admin) & 16 (manager). Sebelum baseline diterima, hanya pola IOC (`wpsvc_*`) yang dilaporkan.
10. Tidak ada `rm`, `DROP`, atau `kill` di mana pun. Karantina = rename di tempat; plugin = rename folder; akun = cabut role/disabled.

## 8. Pengujian

```bash
clear
echo "=== Unit test (sebagai root ikut menguji jalur bg-root sesungguhnya) + simulasi breaker/HMAC ==="
cd /root/bodyguard-hitl
python3 -m unittest discover -s tests -p 'test_*.py' 2>&1 | tail -3
python3 /opt/bodyguard/tools/simulate.py
```

Tes hanya memakai direktori sementara, skrip cf-guard/collect3 palsu, dan Telegram palsu: tidak ada sudo, jaringan,
`/var/www`, atau database yang disentuh. `tools/simulate.py` aman dijalankan kapan saja, termasuk sebagai user `guard`.
