# Lab Reproduksi: Pertahanan Berlapis dan Backup untuk Website Kampus

Kumpulan script dari skripsi **"Mengamankan Website Kampus dengan Sumber Daya Terbatas di STAI-ALI Surabaya:
Pendekatan Design Science Research untuk Pertahanan Berlapis dan Backup"** (Muhammad Andyk Maulana, ITTS, 2026).
Paket ini disusun supaya bisa dipasang ulang di kampus lain **tanpa biaya lisensi**.

- `README.md` (berkas ini): cara memasang dan memakai.
- `PANDUAN-LAB.pdf`: penjelasan konsep beserta diagram.

> [!IMPORTANT]
> **Folder ini tidak berisi token, kata sandi, atau data server.** Semua rahasia diisi lewat `atur-token.sh` dan
> disimpan di `/etc/*.env` (pemilik root, izin 600). Sebelum mengunggah ke GitHub, jalankan `bash cek-rahasia.sh`
> (lihat [bagian 11](#11-mengunggah-ke-github)).

## Daftar isi

1. [Isi paket](#1-isi-paket)
2. [Kebutuhan](#2-kebutuhan)
3. [Memasang](#3-memasang)
4. [Token Telegram dan Cloudflare](#4-token-telegram-dan-cloudflare)
5. [Urutan setelah pemasangan](#5-urutan-setelah-pemasangan)
6. [Pemakaian sehari-hari](#6-pemakaian-sehari-hari)
7. [Satu pekerjaan, satu pemilik](#7-satu-pekerjaan-satu-pemilik)
8. [Jadwal](#8-jadwal)
9. [Urutan backup](#9-urutan-backup)
10. [Hardening MariaDB, trigger OJS, dan port SSH](#10-hardening-mariadb-trigger-ojs-dan-port-ssh)
11. [Mengunggah ke GitHub](#11-mengunggah-ke-github)
12. [Masalah umum](#12-masalah-umum)
13. [Riwayat perubahan](#13-riwayat-perubahan)
14. [Lisensi](#14-lisensi)

---

## 1. Isi paket

> [!TIP]
> Peta lengkap berkas, lokasi konfigurasi/data di server, dan diagram keterkaitannya ada di [STRUKTUR.md](STRUKTUR.md).

Folder mengikuti rancangan skripsi (Tabel 3.5). Saat dipasang, semua script disalin **rata** ke
`/var/opt/script/tools/`, karena cron, timer, dan konfigurasi SOC-IR memanggilnya dengan jalur tetap.

```text
lab-reproduksi/
├── install.sh              pemasang semi-otomatis
├── lab.sh                  menu: status, IP admin, database OJS, demo, baseline, cek, jadwal, SOC-IR, uji, copot
├── STRUKTUR.md             peta berkas penting, lokasi data, dan diagram keterkaitan (mermaid)
├── atur-token.sh           pengisian token Telegram, Cloudflare, dan bot persetujuan
├── cek-rahasia.sh          pemeriksaan sebelum git push (hanya membaca)
├── modul/
│   ├── M1-berkas/          web-integrity-cek.sh, webscan-wp.sh
│   ├── M2-database-akun/   db-integrity-cek.sh
│   ├── M3-proses/          persistence-killer.sh, pk-systemd-setup.sh
│   ├── M4-backup-verify/   backup-verify.sh
│   ├── M5-penjaga-keputusan/  cf-guard.py, ip-report.sh, soc-ir/, soc_ir-data.sh, soc_ir-kirim.sh
│   └── umum/               notify-run.sh, bukti.py, penjaga.sh, collect3_evidence.sh
├── lapisan/                L3-trigger-ojs.sh, L4-hardening-db.sh
├── lingkungan/             backup, cek-disk, cek-all, firewall, arsip log, IP admin (tidak dievaluasi)
├── uji/                    uji-skripsi.py (K1-K11, 14 skenario, R1/R3, metrik)
├── config/                 contoh konfigurasi TANPA rahasia (*.example)
├── jadwal/                 cron dan unit systemd
├── demo/                   demo aman di /var/tmp/lab-demo
└── lib/                    fungsi bersama pemasang
```

| Folder | Isi | Pemicu |
|---|---|---|
| `modul/M1-berkas/` | `web-integrity-cek.sh` (`--rebuild`, `--accept`, `--accept --yes`), `webscan-wp.sh` | timer tiap jam; webscan mingguan |
| `modul/M2-database-akun/` | `db-integrity-cek.sh` (`--rebuild`, `--accept`, `--days=N`, `--full`) | cron tiap jam; `--full` setiap Sabtu |
| `modul/M3-proses/` | `persistence-killer.sh` (`--dry-run`, `--full`, `--kill`, `--auto`, `--harden`), `pk-systemd-setup.sh` | timer tiap menit |
| `modul/M4-backup-verify/` | `backup-verify.sh` (`--restore-test`, `--berkas`, `--lolos-hari-ini`) | sesudah job backup; uji pulih setiap Sabtu |
| `modul/M5-penjaga-keputusan/` | `cf-guard.py`, `ip-report.sh`, `soc-ir/bodyguard-hitl/` (pemindai, `bg-root`, gerbang T2), `soc_ir-data.sh`, `soc_ir-kirim.sh` | SOC-IR tiap 10 menit; cf-guard tiap 6 jam |
| `modul/umum/` | `notify-run.sh`, `bukti.py`, `penjaga.sh`, `collect3_evidence.sh` | dipakai semua modul |
| `lapisan/` | `L3-trigger-ojs.sh`: dua trigger tambahan pada database OJS (tolak akun berpenanda, catat peran admin); `L4-hardening-db.sh`: cabut hak global akun aplikasi. Keduanya bisa dibatalkan | manual |
| `lingkungan/` | `backup-all-web.sh`, `backup-all-db.sh`, `backup_vps.py`, `cek-disk.py`, `cek-all.sh`, `fw.sh`, `update-ip-cloudflare.sh`, `img-scan.sh`, `notif-ojs.py`, `arsip-log.sh`, `ip-kantor-sync.sh`, `salin-uji.py` (situs salinan untuk pengujian) | cron/systemd/manual |
| `uji/` | `uji-skripsi.py` | manual |

## 2. Kebutuhan

| Kebutuhan | Keterangan |
|---|---|
| Sistem operasi | **Ubuntu Server 22.04 LTS atau 24.04 LTS** (64-bit). Distro lain ditolak pemasang supaya sistem tidak rusak. |
| Akses | root (`sudo`) |
| Web server | Nginx + PHP-FPM, situs di `/var/www/html/<nama-situs>/` (WordPress, OJS, SLiMS, atau EPrints) |
| Database | MariaDB/MySQL lokal; root bisa masuk lewat unix socket |
| Internet | Untuk `apt`, Telegram, dan Cloudflare. Tanpa internet, pakai `--tanpa-paket` |
| Opsional | Cloudflare Free (WAF), bot Telegram, rclone + Google Drive (backup tingkat 3), GitLab privat (tingkat 2) |

Disk kosong yang disarankan: minimal dua kali ukuran total folder situs dan database (untuk backup tingkat 1).

## 3. Memasang

```bash
# 1) dari komputer Anda: salin paket ke server
scp lab-reproduksi.zip root@SERVER:/root/

# 2) di server
sudo apt-get install -y unzip
cd /root && unzip lab-reproduksi.zip
sudo bash lab-reproduksi/install.sh
```

Pemasang bekerja **semi-otomatis**:

1. Memeriksa sistem operasi (hanya Ubuntu 22.04/24.04).
2. Memasang paket wajib: `curl jq zip unzip git python3 python3-requests mariadb-client openssl acl`.
3. Menyalin lab ke `/var/opt/script/tools/lab-reproduksi` dan semua script ke `/var/opt/script/tools/`.
   Bila sudah ada script bernama sama dengan isi berbeda, Anda ditanya dulu; cadangan `*.bak-lab-TANGGAL` dibuat.
4. Menyiapkan folder data berizin 700: baseline `/var/opt/filehash-web-all` dan `/var/opt/db-integrity`,
   bukti `/var/opt/bukti`, backup `/var/opt/BACKUP/{web,DB,vps}`, log `/var/log/audit-run`.
5. Menanyakan IP kantor dan nama database OJS, lalu token ([bagian 4](#4-token-telegram-dan-cloudflare)).
6. Menawarkan pemasangan jadwal. Bawaannya **tidak**: jadwal dipasang setelah baseline dibuat.

Setiap pertanyaan ditunggu **60 detik**. Bila tidak dijawab, langkah itu dilewati dan bisa diisi kemudian
lewat `atur-token.sh` atau `lab.sh`. Pemasang aman dijalankan berulang.

```bash
sudo bash install.sh --otomatis      # tanpa pertanyaan; token dan jadwal diisi nanti
sudo bash install.sh --tanpa-paket   # server tanpa internet atau paket sudah lengkap
sudo LAB_TUJUAN=/var/opt/script/tools/skripsi-lab bash install.sh   # nama folder lab lain
```

> [!NOTE]
> Bila memakai `LAB_TUJUAN`, sertakan juga saat menjalankan `lab.sh`, misalnya
> `sudo LAB_TUJUAN=/var/opt/script/tools/skripsi-lab bash lab.sh status`. Kalau tidak, baris "Folder lab" pada
> status menampilkan nama bawaan. Fungsinya tidak terpengaruh.

## 4. Token Telegram dan Cloudflare

Contoh di bagian ini memakai `LAB=/var/opt/script/tools/lab-reproduksi`.

```bash
LAB=/var/opt/script/tools/lab-reproduksi
sudo bash $LAB/atur-token.sh               # menu
sudo bash $LAB/atur-token.sh telegram      # bot notifikasi
sudo bash $LAB/atur-token.sh cloudflare    # cf-guard
sudo bash $LAB/atur-token.sh persetujuan   # bot tombol Setujui/Tolak
sudo bash $LAB/atur-token.sh cek           # uji token tersimpan (token tidak dicetak)
```

### 4.1 Bot notifikasi Telegram

1. Buka **@BotFather**, kirim `/newbot`, beri nama, lalu salin tokennya (bentuk `123456789:AAH...`).
2. Buat grup (misalnya "SOC Kampus"), undang bot, lalu kirim satu pesan apa saja di grup.
3. Jalankan `atur-token.sh telegram` dan tempel tokennya. Script membaca `getUpdates`, menampilkan chat id yang
   ditemukan (chat id grup selalu diawali tanda minus, misalnya `-1001234567890`), lalu mengirim pesan uji.

> [!WARNING]
> URL `https://api.telegram.org/bot<TOKEN>/getUpdates` memuat token. Jangan bagikan URL itu atau tangkapan layarnya.

### 4.2 Cloudflare (untuk `cf-guard.py`, opsional)

Buat token di **My Profile → API Tokens → Create Token → Custom token**, dibatasi ke zona kampus, dengan izin minimal
`Account Filter Lists: Edit`, `Zone WAF: Edit`, dan `Analytics: Read`. Buat juga satu custom rule bernama
**"Auto-Block - Dinamis Hacker"** (aksi Block). `atur-token.sh cloudflare` memverifikasi token, menampilkan zona dan
custom rule, lalu menyimpan ID-nya ke `/etc/bodyguard/cloudflare.env`.

### 4.3 Bot persetujuan (gerbang T2)

Tombol Setujui/Tolak memakai **bot kedua**: `atur-token.sh persetujuan`. Ini satu-satunya gerbang persetujuan T2
untuk semua modul, termasuk usulan blokir dari cf-guard.

> [!TIP]
> Bot yang sudah ada boleh dipakai, asalkan **tokennya berbeda dari bot notifikasi**. Telegram hanya memberikan
> setiap pesan masuk kepada satu pembaca. Bila satu bot dibaca oleh bot SOC cf-guard dan gerbang T2 sekaligus,
> tekanan tombol bisa "dimakan" pembaca yang salah.

## 5. Urutan setelah pemasangan

Kerjakan berurutan. `lab.sh status` menunjukkan bagian yang belum selesai.

| # | Langkah | Perintah | Selesai bila |
|---|---|---|---|
| 1 | Coba demo | `lab.sh demo` | Demo menampilkan deteksi, penolakan `--accept`, dan dump kosong |
| 2 | Isi token | `atur-token.sh` | `atur-token.sh cek` semuanya OK |
| 3 | IP admin dan database OJS | `lab.sh ip-admin`, `lab.sh ojs-db` ([bagian 6](#6-pemakaian-sehari-hari)) | `lab.sh status` menampilkan IP admin dan OJS_DB |
| 4 | Baseline berkas M1 | `lab.sh baseline` **saat situs dipastikan bersih** | `lab.sh status`: baseline berkas ada |
| 5 | Hardening database | `L4-hardening-db.sh` ([bagian 10](#10-hardening-mariadb-trigger-ojs-dan-port-ssh)) | `verifikasi` tidak menyisakan hak global |
| 5b | Trigger OJS (L3) | `L3-trigger-ojs.sh` ([bagian 10](#10-hardening-mariadb-trigger-ojs-dan-port-ssh)) | Uji mandiri: dua aturan `[ OK ]` |
| 6 | Baseline database M2 | `db-integrity-cek.sh --rebuild` | `lab.sh status`: baseline database ada |
| 7 | Jadwal | `lab.sh jadwal-pasang` (server baru) atau tambahkan baris cron secara manual (server yang sudah punya jadwal) | `lab.sh status`: JADWAL ok |
| 8 | Masa dry-run 3-7 hari | M3 mode dry, cf-guard tanpa `--apply`, SOC-IR `mode = dry-run` | Tidak ada temuan keliru |
| 9 | Aktifkan tindakan | `pk-systemd-setup.sh auto`, cf-guard `--apply`, SOC-IR `mode = enforce` | Dicatat tanggalnya untuk kronologi |

> [!CAUTION]
> Di server yang **sudah punya** timer/cron untuk script yang sama, jangan memakai `lab.sh jadwal-pasang`.
> Perintah itu memasang timer `lab-web-integrity`, sehingga M1 berjalan dua kali dan alert terkirim ganda.
> Tambahkan saja baris yang belum ada dari `jadwal/lab-reproduksi.cron` ke `/etc/cron.d/`, lalu tandai statusnya:
> `sudo bash -c ". $LAB/lib/umum.sh; status_set JADWAL 'manual'"`.

## 6. Pemakaian sehari-hari

```bash
LAB=/var/opt/script/tools/lab-reproduksi
T=/var/opt/script/tools

sudo bash $LAB/lab.sh status                 # apa yang sudah/belum diatur
sudo bash $T/cek-all.sh -q                   # audit harian: hanya WARN/FAIL + ringkasan M1-M4
sudo bash $LAB/lab.sh cek                    # jalankan M1, M2, M3 (dry-run), M4 sekarang tanpa kirim Telegram
sudo bash $T/web-integrity-cek.sh --accept   # setelah update plugin/WordPress yang sah (ditolak bila ada IOC)
sudo bash $T/collect3_evidence.sh --auto     # insiden: salin bukti dulu, baru bersihkan
sudo bash $T/penjaga.sh freeze "alasan"      # darurat: semua tindakan otomatis berhenti
sudo bash $T/penjaga.sh unfreeze "alasan"    # mencairkan, HANYA dari konsol
```

**Memperbarui lab di server** (setelah menerima zip baru), tanpa memasang ulang:

```bash
cd ~/unggahan && unzip -oq lab-reproduksi.zip        # folder tempat zip diunggah
sudo bash lab-reproduksi/lab.sh sinkron                 # rencana: salin ke folder lab, daftar skrip sama/berbeda/baru
sudo bash lab-reproduksi/lab.sh sinkron --pasang        # pasang yang berbeda/baru ke /var/opt/script/tools
sudo bash lab-reproduksi/lab.sh sinkron --pasang --hanya salin-uji.py,arsip-log.sh   # hanya skrip tertentu
```

Versi lama setiap skrip yang ditimpa disimpan di `/var/opt/script/tools/.sebelum-sinkron/<waktu>/`. Skrip yang
sengaja disesuaikan untuk server ini (bawaan: `backup-all-db.sh`, `backup-all-web.sh`, `backup_vps.py`) tidak
ditimpa; daftarnya di `/etc/lab-reproduksi/sinkron-lewati.txt`. Jadwal cron tidak diubah oleh `sinkron`.

**IP admin** adalah IP yang dikecualikan dari daftar IP mencurigakan (M1, `ip-report.sh`, laporan SOC-IR) dan
tidak akan diblokir `cf-guard.py`. Ada dua jenis:

| Jenis | Contoh | Cara mengisi |
|---|---|---|
| IP tetap | internet kantor *dedicated* | ditulis langsung |
| IP berubah-ubah | internet rumahan, atau kantor tanpa IP *dedicated* | lewat **nama DDNS**: router atau PC di lokasi itu melaporkan IP-nya ke layanan DDNS, server membaca nama itu tiap 10 menit |

```bash
sudo bash $LAB/lab.sh ip-admin                              # tanya-jawab; menampilkan IP yang sedang login SSH
sudo bash $LAB/lab.sh ip-admin "203.0.113.10" -             # IP tetap saja
sudo bash $LAB/lab.sh ip-admin "203.0.113.10" "admin-rumah.duckdns.org"   # IP tetap + IP dinamis
sudo bash $LAB/lab.sh ip-admin - "kantor.duckdns.org admin-rumah.duckdns.org"  # semuanya dinamis
sudo bash $LAB/lab.sh ojs-db                                # nama database OJS dibaca dari config.inc.php
```

Nama DDNS bisa didapat gratis dari:

- **MikroTik**: menu *IP > Cloud*, centang *DDNS Enabled*. Namanya berbentuk `xxxx.sn.mynetname.net`.
- **duckdns.org**: buat subdomain, lalu isi token DuckDNS di menu DDNS router, atau jalankan klien DuckDNS di PC yang selalu menyala.

Bila nama DDNS diisi, `lab.sh ip-admin` memasang `/etc/cron.d/lab-ip-admin` (tiap 10 menit). IP lama yang sudah
tidak dipakai otomatis dikeluarkan, karena IP rumahan bisa diberikan provider ke pelanggan lain. Bila nama DDNS
gagal di-resolve, IP terakhir dipertahankan supaya admin tidak ikut terblokir.

> [!NOTE]
> `uji-skripsi.py` (menu `lab.sh uji`) menanam penanda dan akun uji. Jalankan **hanya pada situs salinan**,
> jangan pada situs produksi. Situs salinan dibuat dan ditarik ulang dari produksi dengan
> `python3 /var/opt/script/tools/salin-uji.py` (tanpa argumen = rencana saja; `salin` = buat/sinkron;
> `status`; `hapus <domain-uji>`).
> Log situs salinan ditulis terpisah di `/var/log/nginx/uji/` (logrotate sendiri, 60 hari), sehingga lalu lintas
> pengujian tidak tercampur ke log produksi yang dianalisis `ip-report.sh`, `cf-guard.py`, SOC-IR, dan metrik.

## 7. Satu pekerjaan, satu pemilik

| Pekerjaan | Dulu | Sekarang |
|---|---|---|
| Menerima baseline setelah perubahan sah | `integrity-accept.sh` terpisah | `web-integrity-cek.sh --accept` dan `db-integrity-cek.sh --accept` |
| Menyimpan bukti + SHA-256 | `collect3_evidence.sh`, `persistence-killer.sh --kill`, `bg-root` masing-masing | `bukti.py`: salinan 0400 bernama hash, `MANIFEST.tsv`, satu folder `/var/opt/bukti/<kasus>/` |
| Blokir IP | fail2ban, ipset SOC-IR, cf-guard | `cf-guard.py` saja. ipset tidak berguna karena pengunjung datang dari IP Cloudflare; fail2ban hanya untuk SSH |
| Persetujuan dan FREEZE | cf-guard, SOC-IR, persistence-killer (tiga FREEZE) | satu gerbang T2 (SOC-IR) + satu FREEZE `/var/lib/penjaga/FREEZE` (`penjaga.sh`) |
| Kirim ke Telegram | tujuh pengirim berbeda | `notify-run.sh --pesan`. Pengecualian: tombol gerbang T2 dan unggah berkas backup tingkat 2 |
| Audit menyeluruh | `cek-all.sh` mengulang pemeriksaan modul | `cek-all.sh` v2: hanya pemeriksaan yang tidak dimiliki modul + ringkasan M1-M4 |

`notify-run.sh` menyimpan log setiap run di `/var/log/audit-run/`, hanya mengirim **temuan baru**, dan menyusun pesan
per kelompok (GAGAL, PERINGATAN, lain-lain) dengan satu poin per baris dan paling banyak 12 poin per kelompok.

## 8. Jadwal

Sumber: `jadwal/lab-reproduksi.cron` dan unit di `jadwal/`.

| Waktu | Tugas |
|---|---|
| Tiap menit | M3 `persistence-killer.sh` mode dry (timer) |
| Tiap 5 menit | `notif-ojs.py`: pendaftar OJS baru (L2) |
| Tiap 10 menit (bila ada DDNS) | `ip-kantor-sync.sh` lewat `/etc/cron.d/lab-ip-admin` (dipasang `lab.sh ip-admin`) |
| Tiap jam | M1 `web-integrity-cek.sh` (timer); M2 `db-integrity-cek.sh` (menit ke-5) |
| 00:10 | `backup-all-db.sh` dan `backup-all-web.sh`, lalu **segera** M4 `backup-verify.sh` |
| 00:40 | `arsip-log.sh`: log Nginx yang sudah dirotasi disalin ke `/var/opt/arsip-log/nginx/` |
| 07:05 | `uji-skripsi.py --panen`: hitungan log per hari dan arsip segmen ber-SHA-256 untuk baseline dan evaluasi |
| 02:30 (opsional) | `backup_vps.py`: zip VPS diverifikasi M4, lalu Telegram + Git (tingkat 2) |
| 05:20 | `ip-report.sh`: perilaku IP 30 hari (masukan cf-guard) |
| 05:30, 07:00 (opsional) | `rclone` ke Google Drive (tingkat 3), hanya bila verifikasi hari ini lolos |
| 06:00 | `cek-all.sh -q` (ringkasan) |
| Sabtu 03:30 / 07:45, Minggu 04:00 | M2 `--full` / M4 `--restore-test` / `webscan-wp.sh` |

## 9. Urutan backup

```text
00:10 backup ──▶ backup-verify.sh (M4)
                     │
             ┌───────┴────────┐
           lolos            ada FAIL
             │                 │
   penanda lolos-TANGGAL   tanpa penanda
             │                 │
   kirim Drive/Telegram    kirim dan rotasi DITAHAN,
   + rotasi diizinkan      salinan lama yang utuh aman, notifikasi FAIL
```

M4 memeriksa umur berkas, keutuhan (`gzip -t`, `tar -tzf`, `unzip -t`, dan baris penutup dump MariaDB maupun
PostgreSQL), rasio ukuran terhadap rata-rata tujuh backup sebelumnya, dan ruang disk. Izin berkas backup yang masih
bisa dibaca pengguna lain dirapikan otomatis menjadi 600. Uji pulih mingguan (`--restore-test`) memakai dump MariaDB
utuh terbaru, memulihkannya ke database sementara, menghitung tabelnya, lalu menghapus database sementara itu.

> [!IMPORTANT]
> M4 hanya **memeriksa** berkas yang sudah ada. Setelah memperbaiki script backup, jalankan backup-nya dulu,
> baru verifikasi: `backup-all-db.sh` → `backup-verify.sh` → `backup-verify.sh --lolos-hari-ini`.

## 10. Hardening MariaDB, trigger OJS, dan port SSH

Lab tidak mengubah firewall secara otomatis, karena salah langkah bisa mengunci akses Anda sendiri.

**MariaDB hanya mendengar di dalam server.** Tulis `bind-address = 127.0.0.1` di
`/etc/mysql/mariadb.conf.d/50-server.cnf`, lalu `systemctl restart mariadb`. Administrasi dari kantor lewat
tunnel SSH: `ssh -p PORT -L 3306:127.0.0.1:3306 user@server`.

**Hak akun aplikasi** dicabut bertahap dengan `lapisan/L4-hardening-db.sh`. Script ini hanya mencabut hak
**global** (`*.*`, termasuk FILE dan SUPER). Hak setiap aplikasi atas database miliknya sendiri tetap ada.

```bash
H="sudo bash /var/opt/script/tools/L4-hardening-db.sh"
$H                              # rencana saja: tidak mengubah apa pun
$H kunci "akun_lama@localhost"  # kunci akun yang tidak dipakai (bisa dibuka: $H buka ...)
$H uji wpuser@localhost         # terapkan ke SATU akun, lalu semua situs dicek otomatis
$H terapkan                     # semua akun pada rencana (diminta mengetik YA)
$H batal                        # kembalikan perubahan uji/terapkan terakhir
$H situs                        # cek semua situs saja
```

Cadangan hak akses, perintah yang dijalankan, dan berkas pembatalnya disimpan di `/root/hardening-db/` (root 700).
Password dan hash password tidak pernah dicetak ke layar.

**Trigger OJS (L3).** Naskah Bab III memakai tiga aturan. Aturan 1 (akun baru tertahan *disabled*) memakai trigger
yang sudah ada di server, misalnya `p_setdisable_newuser`, dan tidak diubah. `lapisan/L3-trigger-ojs.sh` hanya
menambah dua:

| Aturan | Trigger | Isi |
|---|---|---|
| 2 | `l3_tolak_penanda` (BEFORE INSERT pada `users`) | INSERT ditolak bila surel berakhiran `.internal` atau nama pengguna berawalan `wpsvc`/`svc_` |
| 3 | `l3_audit_peran` (AFTER INSERT pada `user_user_groups`) | penambahan peran Site Admin (1) atau Journal Manager (16) dicatat ke tabel `l3_audit_log` |

```bash
L3="sudo bash /var/opt/script/tools/L3-trigger-ojs.sh"
$L3                       # rencana: trigger yang ada beserta isinya, akun berpenanda yang sudah ada
$L3 uji uji_jurnalst_ojs  # pasang + uji mandiri di database SALINAN dulu (dibuat salin-uji.py)
$L3 terapkan              # pasang + uji mandiri di database produksi (diminta mengetik YA)
$L3 audit                 # 20 catatan penambahan peran admin terakhir
$L3 batal                 # lepas dua trigger baru (tabel audit tetap ada)
```

Uji mandiri berjalan di dalam transaksi yang dibatalkan, jadi tidak meninggalkan akun atau peran uji.

**SSH** sebaiknya hanya menerima IP kantor lewat iptables/ip6tables. Siapkan konsol penyedia VPS dan pengaman
rollback otomatis sebelum mencoba, karena IP kantor bisa berubah. `install.sh` sudah memasukkan `www-data` ke
`/etc/cron.deny` dan `/etc/at.deny`, sehingga penyusup lewat aplikasi web tidak bisa memasang jadwal tersembunyi.

## 11. Mengunggah ke GitHub

Paket ini sudah memuat `.gitignore` yang menolak:

- rahasia: `*.env` (kecuali `*.env.example`), kunci, `*.cnf`, `rclone.conf`, berkas kredensial JSON;
- daftar khusus server: `known_admins.txt`, `trusted_ips.txt`, `root.conf`, dan sejenisnya;
- data server: dump, zip, log, bukti, arsip log, folder hardening;
- cadangan pemasang (`*.bak-*`) dan berkas sementara.

```bash
cd lab-reproduksi
bash cek-rahasia.sh                  # harus berakhir dengan [ OK ]
git init -b main
git add .
git status                           # periksa: tidak ada .env, dump, zip, atau log
git commit -m "Lab reproduksi"
git remote add origin git@github.com:<akun>/lab-reproduksi.git
git push -u origin main
```

`cek-rahasia.sh` mencari token Telegram, token atau kunci Cloudflare/Google/AbuseIPDB, kunci privat, kata sandi
yang tertulis langsung, chat id grup sungguhan, dan jalur folder pribadi. Script ini hanya mencetak nama berkas dan
nomor baris, tidak pernah isi rahasianya, sehingga keluarannya aman ditempel ke chat.

> [!CAUTION]
> Bila sebuah rahasia **terlanjur** di-push, menghapus berkasnya saja tidak cukup karena rahasia tetap ada di riwayat
> Git. Ganti (rotasi) rahasia itu lebih dulu, baru bersihkan riwayat repositori.

## 12. Masalah umum

| Gejala | Penyebab dan solusi |
|---|---|
| `Lab hanya didukung di Ubuntu...` | Pasang di Ubuntu Server 22.04/24.04 |
| Pesan uji Telegram gagal (HTTP 400/403) | Bot belum ada di grup, atau tanda minus chat id salah |
| `getUpdates` kosong | Kirim pesan di grup setelah bot masuk. Bila bot memakai webhook, isi chat id manual |
| `Baseline belum ada` | `lab.sh baseline` |
| Alert berulang setelah update plugin | `web-integrity-cek.sh --accept` |
| Backup tidak terkirim ke Drive/Telegram | Verifikasi hari ini ada FAIL; lihat `/var/log/audit-run/backup-verify-*.log` |
| Dump `.sql.gz` 20 byte, log berisi `1045 Access denied` | Kata sandi akun di script backup lama tidak cocok. `backup-all-db.sh` versi lab memakai root lewat socket, sehingga tidak bergantung kata sandi situs |
| Verifikasi masih FAIL padahal script backup sudah diperbaiki | M4 memeriksa berkas lama. Jalankan backup dulu, baru verifikasi ([bagian 9](#9-urutan-backup)) |
| Laporan: database `ojs` tidak ditemukan | `OJS_DB` belum diisi, jadi skrip memakai nama bawaan `ojs`. Jalankan `lab.sh ojs-db` |
| IP kantor selalu muncul sebagai IP mencurigakan | `IP_KANTOR` kosong atau IP kantor sudah berubah. Jalankan `lab.sh ip-admin` |
| Situs galat database setelah hardening | `L4-hardening-db.sh batal`, lalu periksa akun yang hanya punya hak global |
| Semua tindakan otomatis berhenti | FREEZE aktif: `penjaga.sh status` |
| `cf-guard.py: Kurang di /etc/bodyguard/cloudflare.env` | `atur-token.sh cloudflare` |
| Tombol Setujui kadang tidak berfungsi | Bot persetujuan sama dengan bot notifikasi; pakai token berbeda ([bagian 4.3](#43-bot-persetujuan-gerbang-t2)) |

## 13. Riwayat perubahan

**24 November 2026**

- Baru: `lapisan/L3-trigger-ojs.sh` (aturan 2 dan 3 trigger OJS, dengan uji mandiri dan pembatalan).
- `lab.sh ip-admin`: IP tetap dan nama DDNS diisi dalam satu perintah; jadwal sinkron tiap 10 menit dipasang otomatis bila ada DDNS.
- `lab.sh ojs-db`: nama database OJS dibaca dari `config.inc.php` dan diperiksa sebelum disimpan.
- `lab.sh status` menampilkan IP tetap, DDNS, dan `OJS_DB`.
- `salin-uji.py`: log salinan dipisah ke `/var/log/nginx/uji/`; SLiMS 9 (`config/database.php`) dikenali; nama akun salinan `uji_utama`, `uji_jurnal`, `uji_library`; aplikasi yang tidak dikenali dilewati dengan daftar kandidat berkas konfigurasi.
- Baru: `STRUKTUR.md` (peta berkas dan diagram keterkaitan).
- `backup_vps.py`: bila `pull --rebase` konflik, rebase dibatalkan otomatis (repo tidak macet di tengah rebase), tanpa force push.
- `web-integrity-cek.sh`: `classes/migration/upgrade/` milik OJS/PKP tidak lagi dianggap "PHP di folder data" (positif palsu).
- `lab.sh sinkron`: memperbarui folder lab dan skrip di tools dari zip baru; versi lama dicadangkan, skrip khusus server dipertahankan.
- Jadwal baru: `uji-skripsi.py --panen` setiap 07:05 (sesudah log dirotasi).
- `salin-uji.py` juga mengizinkan `IP_KANTOR_TETAP`; `ip-kantor-sync.sh` ikut memperbarui `uji-izin.conf` saat IP admin berubah.

**23 November 2026**

- `backup-verify.sh` v2: dump PostgreSQL dikenali; izin berkas backup dirapikan otomatis ke 600; uji pulih hanya
  memakai dump MariaDB yang utuh; pesan FAIL tidak lagi mengulang nama berkas.
- `notify-run.sh`: notifikasi dikelompokkan (GAGAL, PERINGATAN, lain-lain), satu poin per baris, paling banyak 12 per kelompok.
- `soc_ir-kirim.sh` v5: mengenali judul format laporan baru dan merapatkan baris kosong ganda.
- `web-integrity-cek.sh`: saran pada alert brute force diganti dari `ufw` menjadi `/blok IP` di bot SOC.
- `ip-report.sh`: database WordPress dikenali dari tabel `*_usermeta`, tidak lagi bergantung awalan nama database.
- Baru: `lingkungan/salin-uji.py` (situs salinan uji.*, uji-jurnal.*, uji-library.* dengan pembatas IP), `lapisan/L4-hardening-db.sh`, `lingkungan/arsip-log.sh`, `lingkungan/ip-kantor-sync.sh`, `cek-rahasia.sh`, `.gitignore`.

**20 November 2026**

- `atur-token.sh`: perbaikan bentrok variabel yang membuat token Cloudflare tercetak di layar.
- `web-integrity-cek.sh`: perbaikan service ditandai FAILED oleh systemd (`grep | head`).

## 14. Lisensi

Bebas dipakai ulang untuk keperluan pendidikan. Rujukan rancangan dan hasil pengujian: naskah skripsi Bab III dan Bab IV.
