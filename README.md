# Lab Reproduksi: Pertahanan Berlapis dan Backup untuk Website Kampus

Kumpulan skrip dari skripsi **"Mengamankan Website Kampus dengan Sumber Daya Terbatas di STAI-ALI Surabaya:
Pendekatan Design Science Research untuk Pertahanan Berlapis dan Backup"** (Muhammad Andyk Maulana, ITTS, 2026).
Skrip di sini bisa dipasang di server kampus lain tanpa biaya lisensi.

- `README.md` (berkas ini): cara memasang dan memakai.
- `STRUKTUR.md`: daftar berkas, lokasi data di server, dan gambar alurnya.
- `PANDUAN-LAB.pdf`: penjelasan untuk pembaca awam, lengkap dengan diagram.

> [!IMPORTANT]
> **Folder ini tidak berisi token, kata sandi, atau data server.** Semua rahasia diisi lewat `atur-token.sh` dan
> disimpan di `/etc/*.env` (milik root, izin 600). Sebelum mengunggah ke GitHub, jalankan `bash cek-sebelum-share.sh`
> (lihat [bagian 11](#11-mengunggah-ke-github)).

## Daftar isi

1. [Isi paket](#1-isi-paket)
2. [Kebutuhan](#2-kebutuhan)
3. [Memasang](#3-memasang)
4. [Token Telegram dan Cloudflare](#4-token-telegram-dan-cloudflare)
5. [Urutan setelah pemasangan](#5-urutan-setelah-pemasangan)
6. [Pemakaian sehari-hari](#6-pemakaian-sehari-hari)
7. [Satu tugas, satu skrip](#7-satu-tugas-satu-skrip)
8. [Jadwal](#8-jadwal)
9. [Urutan backup](#9-urutan-backup)
10. [Hardening MariaDB, trigger OJS, dan SSH](#10-hardening-mariadb-trigger-ojs-dan-ssh)
11. [Mengunggah ke GitHub](#11-mengunggah-ke-github)
12. [Masalah umum](#12-masalah-umum)
13. [Riwayat perubahan](#13-riwayat-perubahan)
14. [Lisensi](#14-lisensi)

---

## 1. Isi paket

Folder disusun mengikuti rancangan di skripsi (Tabel 3.5). Saat dipasang, semua skrip disalin ke satu folder,
`/var/opt/script/tools/`, karena cron, timer, dan SOC-IR memanggilnya dari alamat yang tetap.

```text
lab-reproduksi/
├── install.sh            pemasang
├── lab.sh                menu: status, sinkron, IP admin, database OJS, demo, baseline, cek, cron, SOC-IR, uji
├── atur-token.sh         isi token Telegram, Cloudflare, dan bot persetujuan
├── cek-sebelum-share.sh        cek sebelum git push (hanya membaca)
├── modul/
│   ├── M1-berkas/        web-integrity-cek.sh, webscan-wp.sh
│   ├── M2-database-akun/ db-integrity-cek.sh
│   ├── M3-proses/        persistence-killer.sh, pk-systemd-setup.sh
│   ├── M4-backup-verify/ backup-verify.sh
│   ├── M5-blokir-attacker/     cf-guard.py, ip-report.sh, soc-ir/, soc_ir-data.sh, soc_ir-kirim.sh
│   └── umum/             notify-run.sh, freeze.sh, simpan-bukti.py, kumpulkan-bukti.sh
├── pencegahan/           L3-trigger-ojs.sh, L4-hardening-db.sh
├── pendukung/            backup, cek-disk, cek-all, firewall, arsip log, IP admin, situs salinan
├── uji/                  uji-skripsi.py (K1-K11, 9 skenario, restore drill R1, metrik)
├── config/               contoh konfigurasi TANPA rahasia (*.example)
├── jadwal/               cron dan unit systemd
├── demo/                 demo aman di /var/tmp/lab-demo
└── lib/                  fungsi bersama untuk pemasang dan menu
```

| Folder | Isi | Jalan kapan |
|---|---|---|
| `modul/M1-berkas/` | `web-integrity-cek.sh` (`--rebuild`, `--accept`, `--snapdb`), `webscan-wp.sh` | timer tiap jam; webscan seminggu sekali |
| `modul/M2-database-akun/` | `db-integrity-cek.sh` (`--rebuild`, `--accept`, `--full`) | cron tiap jam; `--full` tiap Sabtu |
| `modul/M3-proses/` | `persistence-killer.sh` (`--dry-run`, `--kill`, `--auto`), `pk-systemd-setup.sh` | timer tiap menit |
| `modul/M4-backup-verify/` | `backup-verify.sh` (`--restore-test`, `--berkas`, `--lolos-hari-ini`) | sesudah backup; uji pulih tiap Sabtu |
| `modul/M5-blokir-attacker/` | `cf-guard.py`, `ip-report.sh`, SOC-IR (`soc-ir/bodyguard-hitl/`), `soc_ir-data.sh`, `soc_ir-kirim.sh` | SOC-IR tiap 10 menit; cf-guard tiap 6 jam |
| `modul/umum/` | `notify-run.sh` (kirim Telegram), `freeze.sh` (hentikan semua tindakan otomatis), `simpan-bukti.py`, `kumpulkan-bukti.sh` | dipakai semua modul |
| `pencegahan/` | `L3-trigger-ojs.sh` (dua trigger tambahan OJS), `L4-hardening-db.sh` (cabut hak global akun database). Keduanya bisa dibatalkan (`batal`) | manual |
| `pendukung/` | `backup-all-web.sh`, `backup-all-db.sh`, `backup_vps.py`, `cek-disk.py`, `cek-all.sh`, `fw.sh`, `update-ip-cloudflare.sh`, `img-scan.sh`, `notif-ojs.py`, `arsip-log.sh`, `ip-kantor-sync.sh`, `salin-uji.py` | cron, systemd, atau manual |
| `uji/` | `uji-skripsi.py` | manual; `--ambil-log` lewat cron |

## 2. Kebutuhan

| Kebutuhan | Keterangan |
|---|---|
| Sistem operasi | **Ubuntu Server 22.04 LTS atau 24.04 LTS** (64-bit). Distro lain ditolak pemasang supaya sistem tidak rusak. |
| Akses | root (`sudo`) |
| Web server | Nginx + PHP-FPM, situs di `/var/www/html/<nama-situs>/` (WordPress, OJS, SLiMS, atau EPrints) |
| Database | MariaDB/MySQL di server yang sama; root bisa masuk lewat unix socket |
| Internet | Untuk `apt`, Telegram, dan Cloudflare. Tanpa internet, pakai `--tanpa-paket` |
| Opsional | Cloudflare Free (WAF), bot Telegram, rclone + Google Drive (backup tingkat 3), GitLab privat (tingkat 2) |

Sisakan ruang disk minimal dua kali ukuran semua situs dan database (untuk backup tingkat 1).

## 3. Memasang

```bash
# 1) dari komputer Anda: kirim paket ke server
scp lab-reproduksi.zip root@SERVER:/root/

# 2) di server
sudo apt-get install -y unzip
cd /root && unzip lab-reproduksi.zip
sudo bash lab-reproduksi/install.sh
```

Yang dikerjakan pemasang:

1. Mengecek sistem operasi (hanya Ubuntu 22.04/24.04).
2. Memasang paket: `curl jq zip unzip git python3 python3-requests mariadb-client openssl acl`.
3. Menyalin folder lab ke `/var/opt/script/tools/lab-reproduksi` dan semua skrip ke `/var/opt/script/tools/`.
   Kalau sudah ada skrip bernama sama dengan isi berbeda, Anda ditanya dulu dan cadangannya disimpan.
4. Membuat folder data berizin 700: baseline `/var/opt/filehash-web-all` dan `/var/opt/db-integrity`,
   bukti `/var/opt/bukti`, backup `/var/opt/BACKUP/{web,DB,vps}`, log `/var/log/audit-run`.
5. Menanyakan IP kantor, nama database OJS, dan token ([bagian 4](#4-token-telegram-dan-cloudflare)).
6. Menawarkan pemasangan cron. Bawaannya **tidak**, karena cron sebaiknya dipasang setelah baseline dibuat.

Setiap pertanyaan ditunggu **60 detik**. Kalau tidak dijawab, langkah itu dilewati dan bisa diisi nanti lewat
`atur-token.sh` atau `lab.sh`. Pemasang aman dijalankan berulang kali.

```bash
sudo bash install.sh --otomatis      # tanpa pertanyaan; token dan cron diisi nanti
sudo bash install.sh --tanpa-paket   # server tanpa internet, atau paket sudah lengkap
```

Kalau di server sudah ada folder `/var/opt/script/tools/skripsi-lab`, folder itu dipakai sebagai folder lab.
Nama lain bisa dipilih dengan `LAB_TUJUAN=/jalur/folder sudo -E bash install.sh`.

## 4. Token Telegram dan Cloudflare

```bash
LAB=/var/opt/script/tools/lab-reproduksi
sudo bash $LAB/atur-token.sh               # menu
sudo bash $LAB/atur-token.sh telegram      # bot notifikasi
sudo bash $LAB/atur-token.sh cloudflare    # cf-guard
sudo bash $LAB/atur-token.sh persetujuan   # bot tombol Setujui/Tolak
sudo bash $LAB/atur-token.sh cek           # cek token yang tersimpan (token tidak dicetak)
```

### 4.1 Bot notifikasi Telegram

1. Buka **@BotFather**, kirim `/newbot`, beri nama, lalu salin tokennya (bentuk `123456789:AAH...`).
2. Buat grup (misalnya "SOC Kampus"), undang bot, lalu kirim satu pesan apa saja di grup itu.
3. Jalankan `atur-token.sh telegram` dan tempel tokennya. Skrip mencari chat id grup dari pesan tadi
   (chat id grup selalu diawali tanda minus, misalnya `-1001234567890`), lalu mengirim pesan uji.

> [!WARNING]
> Alamat `https://api.telegram.org/bot<TOKEN>/getUpdates` berisi token. Jangan bagikan alamat itu atau tangkapan layarnya.

### 4.2 Cloudflare (untuk `cf-guard.py`, opsional)

Buat token di **My Profile → API Tokens → Create Token → Custom token**, khusus untuk zona kampus, dengan izin
`Account Filter Lists: Edit`, `Zone WAF: Edit`, dan `Analytics: Read`. Buat juga satu custom rule bernama
**"Auto-Block - Dinamis Hacker"** (aksi Block). `atur-token.sh cloudflare` mengecek token, menampilkan zona dan
custom rule, lalu menyimpan ID-nya ke `/etc/bodyguard/cloudflare.env`.

### 4.3 Bot persetujuan (T2)

Tombol Setujui/Tolak memakai **bot kedua**: `atur-token.sh persetujuan`. Semua tindakan yang butuh persetujuan admin
(T2), termasuk usulan blokir dari cf-guard, lewat bot ini.

> [!TIP]
> Bot yang sudah ada boleh dipakai, asalkan **tokennya beda dari bot notifikasi**. Satu pesan Telegram hanya bisa
> dibaca oleh satu program. Kalau satu bot dibaca dua program sekaligus, tombol yang ditekan bisa tidak sampai.

## 5. Urutan setelah pemasangan

Kerjakan berurutan. `lab.sh status` menunjukkan mana yang belum.

| # | Langkah | Perintah | Selesai kalau |
|---|---|---|---|
| 1 | Coba demo | `lab.sh demo` | Demo menampilkan deteksi webshell, `--accept` ditolak, dan dump kosong ketahuan |
| 2 | Isi token | `atur-token.sh` | `atur-token.sh cek` semuanya OK |
| 3 | IP admin dan database OJS | `lab.sh ip-admin`, `lab.sh ojs-db` ([bagian 6](#6-pemakaian-sehari-hari)) | `lab.sh status` menampilkan IP admin dan OJS_DB |
| 4 | Baseline berkas (M1) | `lab.sh baseline`, **hanya saat situs dipastikan bersih** | `lab.sh status`: baseline berkas ada |
| 5 | Hardening database | `L4-hardening-db.sh` ([bagian 10](#10-hardening-mariadb-trigger-ojs-dan-ssh)) | tidak ada lagi akun aplikasi dengan hak global |
| 6 | Trigger OJS (L3) | `L3-trigger-ojs.sh` ([bagian 10](#10-hardening-mariadb-trigger-ojs-dan-ssh)) | tes dua aturan `[ OK ]` |
| 7 | Baseline database (M2) | `db-integrity-cek.sh --rebuild` | `lab.sh status`: baseline database ada |
| 8 | Cron dan timer | `lab.sh pasang-cron` (server baru) atau tambah baris cron sendiri (server yang sudah punya jadwal) | `lab.sh status`: JADWAL ok |
| 9 | Masa coba 3-7 hari | M3 mode dry, cf-guard tanpa `--apply`, SOC-IR `mode = dry-run` | tidak ada temuan keliru |
| 10 | Nyalakan tindakan | `pk-systemd-setup.sh auto`, cf-guard `--apply`, SOC-IR `mode = enforce` | catat tanggalnya |

> [!CAUTION]
> Di server yang **sudah punya** cron/timer untuk skrip yang sama, jangan pakai `lab.sh pasang-cron`. Perintah itu
> memasang timer `lab-web-integrity`, sehingga M1 jalan dua kali dan notifikasi dobel. Tambahkan saja baris yang
> belum ada dari `jadwal/lab-reproduksi.cron` ke `/etc/cron.d/`, lalu tandai:
> `sudo bash -c ". $LAB/lib/umum.sh; status_set JADWAL 'manual'"`.

## 6. Pemakaian sehari-hari

```bash
LAB=/var/opt/script/tools/lab-reproduksi
T=/var/opt/script/tools

sudo bash $LAB/lab.sh status                 # apa yang sudah/belum diatur
sudo bash $T/cek-all.sh -q                   # cek harian: hanya WARN/FAIL + ringkasan M1-M4
sudo bash $LAB/lab.sh cek                    # jalankan M1, M2, M3 (dry-run), M4 sekarang tanpa kirim Telegram
sudo bash $T/web-integrity-cek.sh --accept   # setelah update plugin/WordPress yang sah (ditolak kalau ada IOC)
sudo bash $T/kumpulkan-bukti.sh --auto          # ada insiden: salin bukti dulu, baru bersihkan
sudo bash $T/freeze.sh on "alasan"           # darurat: semua tindakan otomatis berhenti
sudo bash $T/freeze.sh off "alasan"          # jalan lagi, HANYA dari konsol server
```

**Mengumpulkan bukti.** `kumpulkan-bukti.sh` hanya menyalin, tidak menghapus apa pun. Dengan `--auto`, skrip mengambil
semua berkas yang dilaporkan M1 dua hari terakhir (IOC, PHP di dalam gambar, PHP di folder data, ekstensi ganda,
plugin baru), lalu mencari sendiri folder plugin bernama acak, PHP di folder data, dan berkas berekstensi ganda.
Berkas PHP bawaan aplikasi (cache template OJS, vendor, plugin dan tema resmi) tidak ikut, supaya hasilnya tidak
penuh berkas aman. Bukti disimpan di `/var/opt/bukti/<kasus>/` beserta SHA-256-nya.

```bash
sudo bash $T/kumpulkan-bukti.sh --auto --kasus jurnal-20261124
sudo bash $T/kumpulkan-bukti.sh --kasus jurnal-20261124 /var/www/html/jurnal/public/site/images/x.php.gif
```

**Memperbarui lab di server** setelah menerima zip baru, tanpa memasang ulang:

```bash
cd /home/NAMA_ANDA/unggahan     # folder tempat zip diunggah (sebagai root, ~ adalah /root)
rm -rf lab-reproduksi && unzip -oq lab-reproduksi.zip   # hapus hasil ekstrak lama dulu
sudo bash lab-reproduksi/lab.sh sinkron                # lihat dulu: skrip mana yang sama, beda, atau baru
sudo bash lab-reproduksi/lab.sh sinkron --pasang       # pasang yang beda/baru ke /var/opt/script/tools
sudo bash lab-reproduksi/lab.sh sinkron --pasang --hanya salin-uji.py,arsip-log.sh   # skrip tertentu saja
```

Folder lab di server (`skripsi-lab`) dibuat sama persis dengan paket baru; berkas yang tidak ada lagi di paket dipindah ke `.sebelum-sinkron/lab-<waktu>/`, dan folder `.git` tidak disentuh. Versi lama setiap skrip yang diganti disimpan di `/var/opt/script/tools/.sebelum-sinkron/<waktu>/`. Skrip yang
disesuaikan khusus untuk server Anda (bawaan: `backup-all-db.sh`, `backup-all-web.sh`, `backup_vps.py`) tidak
ditimpa; daftarnya ada di `/etc/lab-reproduksi/sinkron-lewati.txt`. Cron tidak diubah oleh `sinkron`.

Beberapa skrip sudah ganti nama (lihat [riwayat perubahan](#13-riwayat-perubahan)) dan nama lama **tidak** diterima
lagi. `sinkron --pasang` memindahkan skrip bernama lama ke folder cadangan, memindah FREEZE ke `/var/lib/freeze`, lalu
menyebut berkas cron, systemd, atau `/etc/bodyguard` yang masih memakai nama lama. Cara menggantinya ada di
[Pindah dari versi lama](#pindah-dari-versi-lama).

#### Pindah dari versi lama

Untuk server yang sudah memasang lab sebelum 24 November 2026. Jalankan berurutan:

```bash
# 1) pasang skrip baru (skrip bernama lama otomatis dipindah ke .sebelum-sinkron/)
cd /home/NAMA_ANDA/unggahan && rm -rf lab-reproduksi && unzip -oq lab-reproduksi.zip
sudo bash lab-reproduksi/lab.sh sinkron --pasang

# 2) cari berkas yang masih memakai nama lama, lalu simpan salinannya dulu
LAMA='penjaga\.sh|(^|[^-])bukti\.py|collect3|kumpul-bukti\.sh|--panen|uji-skripsi-panen|/var/lib/penjaga|PENJAGA_FREEZE'
F=$(sudo grep -rlE "$LAMA" /etc/crontab /etc/cron.d /etc/systemd/system /etc/bodyguard 2>/dev/null); echo "$F"
[ -n "$F" ] && sudo tar czf /root/sebelum-ganti-nama-$(date +%F).tgz $F

# 3) ganti nama lama di berkas tersebut
GANTI='s/collect3_evidence\.sh|kumpul-bukti\.sh/kumpulkan-bukti.sh/g; s/penjaga\.sh/freeze.sh/g;
  s#(^|[^-])bukti\.py#\1simpan-bukti.py#g; s/--panen/--ambil-log/g; s/uji-skripsi-panen/uji-skripsi-ambil-log/g;
  s#/var/lib/penjaga#/var/lib/freeze#g; s/PENJAGA_FREEZE/FREEZE_FILE/g;
  s/^collect3_args/kumpulkan_bukti_args/; s/^collect3_timeout/kumpulkan_bukti_timeout/; s/^collect3/kumpulkan_bukti/'
[ -n "$F" ] && sudo sed -i -E "$GANTI" $F

# 4) crontab milik user (crontab -e) diganti lewat crontab, bukan sed langsung ke /var/spool
sudo crontab -l | grep -E "$LAMA"            # kalau ada isinya:
sudo crontab -l > /root/crontab-root-$(date +%F).txt && sudo crontab -l | sed -E "$GANTI" | sudo crontab -

# 5) SOC-IR: pasang bg-root dan pustaka yang baru (konfigurasi di /etc/bodyguard tidak ditimpa)
sudo bash lab-reproduksi/modul/M5-blokir-attacker/soc-ir/bodyguard-hitl/tools/install.sh --apply

# 6) muat ulang dan periksa
sudo systemctl daemon-reload
sudo grep -rnE "$LAMA" /etc/crontab /etc/cron.d /etc/systemd/system /etc/bodyguard; sudo crontab -l | grep -E "$LAMA"
sudo /usr/local/sbin/bg-root selftest          # baris kumpulkan_bukti harus "ok"
sudo bash /var/opt/script/tools/freeze.sh status
id guard; id guard-approve                     # keduanya anggota grup freeze
sudo getent group penjaga && sudo groupdel penjaga   # grup lama tidak dipakai lagi
```

Langkah 6 benar bila kedua `grep` tidak mencetak apa-apa. `uji-skripsi.py` memindah `hasil.csv` lama sendiri saat
pertama dijalankan (lihat riwayat 24 November).

**IP admin** adalah IP yang tidak dimasukkan ke daftar IP mencurigakan (M1, `ip-report.sh`, laporan SOC-IR) dan
tidak akan diblokir `cf-guard.py`. Ada dua jenis:

| Jenis | Contoh | Cara mengisi |
|---|---|---|
| IP tetap | internet kantor *dedicated* | ditulis langsung |
| IP berubah-ubah | internet rumahan, atau kantor tanpa IP *dedicated* | lewat **nama DDNS**: router atau PC di lokasi itu melaporkan IP-nya ke layanan DDNS, server membaca nama itu tiap 10 menit |

```bash
sudo bash $LAB/lab.sh ip-admin                                       # tanya-jawab; menampilkan IP yang sedang login SSH
sudo bash $LAB/lab.sh ip-admin "203.0.113.10" -                      # IP tetap saja
sudo bash $LAB/lab.sh ip-admin "203.0.113.10" "admin-rumah.duckdns.org"   # IP tetap + IP dinamis
sudo bash $LAB/lab.sh ip-admin - "kantor.duckdns.org admin-rumah.duckdns.org"  # semuanya dinamis
sudo bash $LAB/lab.sh ojs-db                                         # nama database OJS dibaca dari config.inc.php
```

Nama DDNS bisa didapat gratis dari:

- **MikroTik**: menu *IP > Cloud*, centang *DDNS Enabled*. Namanya berbentuk `xxxx.sn.mynetname.net`.
- **duckdns.org**: buat subdomain, lalu isi token DuckDNS di menu DDNS router, atau jalankan klien DuckDNS di PC yang selalu menyala.

Kalau nama DDNS diisi, `lab.sh ip-admin` memasang `/etc/cron.d/lab-ip-admin` (tiap 10 menit). IP lama yang sudah
tidak dipakai otomatis dibuang, karena IP rumahan bisa diberikan provider ke pelanggan lain. Kalau nama DDNS gagal
dibaca, IP terakhir tetap dipakai supaya admin tidak ikut terblokir.

> [!WARNING]
> IP admin tidak dianalisis. Masukkan hanya IP yang **pasti** milik tim Anda. IP yang belum jelas pemiliknya jangan
> dimasukkan, karena aktivitasnya jadi tidak terlihat di laporan.

**Situs salinan untuk pengujian.** `uji-skripsi.py` (menu `lab.sh uji`) menanam berkas uji dan akun uji, jadi
jalankan **hanya di situs salinan**, jangan di situs asli. Situs salinan dibuat dari situs asli dengan
`salin-uji.py`:

```bash
sudo python3 $T/salin-uji.py                   # lihat rencana saja: situs, ukuran, database, vhost
sudo python3 $T/salin-uji.py buat              # buat salinan, atau tarik ulang dari situs asli kalau sudah ada
sudo python3 $T/salin-uji.py status            # cek salinan yang sudah ada
sudo python3 $T/salin-uji.py hapus uji-jurnal.kampus.ac.id
```

Log situs salinan ditulis terpisah di `/var/log/nginx/uji/`, jadi lalu lintas pengujian tidak tercampur dengan log
situs asli yang dipakai `ip-report.sh`, `cf-guard.py`, SOC-IR, dan perhitungan data skripsi.

## 7. Satu tugas, satu skrip

Dulu beberapa skrip mengerjakan hal yang sama dengan caranya masing-masing. Sekarang setiap tugas cuma dikerjakan
satu skrip:

| Tugas | Dulu | Sekarang |
|---|---|---|
| Menerima perubahan sah ke baseline | `integrity-accept.sh` terpisah | `web-integrity-cek.sh --accept` dan `db-integrity-cek.sh --accept` |
| Menyimpan bukti + SHA-256 | tiap skrip punya cara sendiri | `simpan-bukti.py`: salinan 0400 bernama hash, `MANIFEST.tsv`, satu folder `/var/opt/bukti/<kasus>/` |
| Blokir IP | fail2ban, ipset SOC-IR, cf-guard | `cf-guard.py` saja. ipset tidak berguna karena pengunjung datang lewat IP Cloudflare; fail2ban hanya untuk SSH |
| Persetujuan admin dan FREEZE | tiga tempat berbeda | satu bot persetujuan (SOC-IR) + satu FREEZE `/var/lib/freeze/FREEZE` (`freeze.sh`) |
| Kirim ke Telegram | tujuh pengirim berbeda | `notify-run.sh --pesan`. Kecuali tombol persetujuan dan unggah berkas backup tingkat 2 |
| Cek menyeluruh | `cek-all.sh` mengulang cek milik modul | `cek-all.sh` v2: hanya cek yang tidak dimiliki modul + ringkasan M1-M4 |

`notify-run.sh` menyimpan log setiap run di `/var/log/audit-run/`, hanya mengirim **temuan baru**, dan menyusun pesan
per kelompok (GAGAL, PERINGATAN, lain-lain), satu poin per baris, paling banyak 12 poin per kelompok.

## 8. Jadwal

Sumber: `jadwal/lab-reproduksi.cron` dan unit di `jadwal/`.

| Waktu | Tugas |
|---|---|
| Tiap menit | M3 `persistence-killer.sh` mode dry (timer) |
| Tiap 5 menit | `notif-ojs.py`: pendaftar OJS baru (L2) |
| Tiap 10 menit (kalau ada DDNS) | `ip-kantor-sync.sh` lewat `/etc/cron.d/lab-ip-admin` (dipasang `lab.sh ip-admin`) |
| Tiap jam | M1 `web-integrity-cek.sh` (timer); M2 `db-integrity-cek.sh` (menit ke-5) |
| 00:10 | `backup-all-db.sh` dan `backup-all-web.sh`, lalu **langsung** M4 `backup-verify.sh` |
| 00:40 | `arsip-log.sh`: log Nginx yang sudah dirotasi disalin ke `/var/opt/arsip-log/nginx/` |
| 02:30 (opsional) | `backup_vps.py`: zip VPS dicek M4, lalu dikirim ke Telegram + Git (tingkat 2) |
| 05:20 | `ip-report.sh`: perilaku tiap IP selama 30 hari (bahan cf-guard) |
| 05:30, 07:00 (opsional) | `rclone` ke Google Drive (tingkat 3), hanya kalau verifikasi hari ini lolos |
| 06:00 | `cek-all.sh -q` (ringkasan) |
| 07:05 | `uji-skripsi.py --ambil-log`: ambil dan rekap log harian (data skripsi), salinan log disimpan dengan SHA-256 |
| Sabtu 03:30 / 07:45, Minggu 04:00 | M2 `--full` / M4 `--restore-test` / `webscan-wp.sh` |

## 9. Urutan backup

```text
00:10 backup ──▶ backup-verify.sh (M4)
                     │
             ┌───────┴────────┐
           lolos            ada FAIL
             │                 │
   tanda lolos-TANGGAL     tanpa tanda lolos
             │                 │
   kirim Drive/Telegram    kirim dan hapus backup lama DITAHAN,
   + backup lama boleh     backup lama yang utuh tetap aman, notifikasi FAIL
     dihapus
```

M4 mengecek umur berkas, keutuhan (`gzip -t`, `tar -tzf`, `unzip -t`, dan baris penutup dump MariaDB maupun
PostgreSQL), ukuran dibanding rata-rata tujuh backup sebelumnya, dan sisa disk. Berkas backup yang masih bisa dibaca
user lain izinnya diubah otomatis menjadi 600. Uji pulih mingguan (`--restore-test`) memakai dump MariaDB utuh
terbaru, memulihkannya ke database sementara, menghitung tabelnya, lalu menghapus database sementara itu.

> [!IMPORTANT]
> M4 hanya **mengecek** berkas yang sudah ada. Setelah memperbaiki skrip backup, jalankan backup-nya dulu, baru cek:
> `backup-all-db.sh` → `backup-verify.sh` → `backup-verify.sh --lolos-hari-ini`.

## 10. Hardening MariaDB, trigger OJS, dan SSH

Lab tidak mengubah firewall secara otomatis, karena salah langkah bisa mengunci akses Anda sendiri.

**MariaDB hanya menerima koneksi dari dalam server.** Tulis `bind-address = 127.0.0.1` di
`/etc/mysql/mariadb.conf.d/50-server.cnf`, lalu `systemctl restart mariadb`. Kalau perlu mengakses dari kantor,
pakai tunnel SSH: `ssh -p PORT -L 3306:127.0.0.1:3306 user@server`.

**Hak akun aplikasi** dicabut bertahap dengan `L4-hardening-db.sh`. Skrip ini hanya mencabut hak **global**
(`*.*`, termasuk FILE dan SUPER). Hak setiap aplikasi atas database miliknya sendiri tetap ada.

```bash
H="sudo bash /var/opt/script/tools/L4-hardening-db.sh"
$H                              # cek: lihat rencananya saja, tidak mengubah apa pun
$H kunci "akun_lama@localhost"  # kunci akun yang tidak dipakai (buka lagi: $H buka ...)
$H uji wpuser@localhost         # ubah SATU akun dulu, lalu semua situs dicek otomatis
$H pasang                       # ubah semua akun pada rencana (harus ketik YA)
$H batal                        # kembalikan perubahan uji/pasang terakhir
$H cek-situs                    # cek semua situs saja
```

Cadangan hak akses, perintah yang dijalankan, dan berkas undo disimpan di `/root/hardening-db/` (root 700).
Password dan hash password tidak pernah dicetak.

**Trigger OJS (L3).** Rancangan di skripsi memakai tiga aturan. Aturan 1 (akun baru otomatis *disabled*) memakai
trigger yang sudah ada di server, misalnya `p_setdisable_newuser`, dan tidak diubah. `L3-trigger-ojs.sh` hanya
menambah dua:

| Aturan | Trigger | Isi |
|---|---|---|
| 2 | `l3_tolak_akun_palsu` (BEFORE INSERT pada `users`) | akun baru ditolak kalau surelnya berakhiran `.internal` atau nama penggunanya berawalan `wpsvc`/`svc_` (ciri akun palsu pada insiden) |
| 3 | `l3_audit_peran` (AFTER INSERT pada `user_user_groups`) | setiap penambahan peran Site Admin (1) atau Journal Manager (16) dicatat ke tabel `l3_audit_log` |

```bash
L3="sudo bash /var/opt/script/tools/L3-trigger-ojs.sh"
$L3                        # cek: trigger yang ada beserta isinya, dan akun palsu yang sudah ada
$L3 uji uji_jurnalst_ojs   # pasang + tes di database SALINAN dulu (dibuat salin-uji.py)
$L3 pasang                 # pasang + tes di database asli (harus ketik YA)
$L3 cek-trigger            # tes ulang trigger yang sudah terpasang
$L3 log                    # 20 catatan penambahan peran admin terakhir
$L3 batal                  # lepas dua trigger baru (tabel log tetap ada)
```

Tes berjalan di dalam transaksi yang dibatalkan, jadi tidak meninggalkan akun atau peran uji.

**SSH** sebaiknya hanya menerima IP kantor lewat iptables/ip6tables. Siapkan konsol penyedia VPS dan cara
mengembalikan aturan otomatis sebelum mencoba, karena IP kantor bisa berubah. `install.sh` sudah memasukkan
`www-data` ke `/etc/cron.deny` dan `/etc/at.deny`, jadi penyusup lewat aplikasi web tidak bisa memasang jadwal tersembunyi.

## 11. Mengunggah ke GitHub

Paket ini sudah punya `.gitignore` yang menolak:

- rahasia: `*.env` (kecuali `*.env.example`), kunci, `*.cnf`, `rclone.conf`, berkas kredensial JSON;
- daftar khusus server: `known_admins.txt`, `trusted_ips.txt`, `root.conf`, dan sejenisnya;
- data server: dump, zip, log, bukti, arsip log, folder hardening;
- cadangan pemasang (`*.bak-*`) dan berkas sementara.

```bash
cd lab-reproduksi
bash cek-sebelum-share.sh                  # harus berakhir dengan [ OK ]
git init -b main
git add .
git status                           # pastikan tidak ada .env, dump, zip, atau log
git commit -m "Lab reproduksi"
git remote add origin git@github.com:<akun>/lab-reproduksi.git
git push -u origin main
```

`cek-sebelum-share.sh` mencari token Telegram, token atau kunci Cloudflare/Google/AbuseIPDB, kunci privat, kata sandi
yang tertulis langsung, chat id grup sungguhan, dan alamat folder pribadi. Yang dicetak hanya nama berkas dan nomor
baris, tidak pernah isi rahasianya, jadi hasilnya aman ditempel ke chat.

> [!CAUTION]
> Kalau sebuah rahasia **terlanjur** di-push, menghapus berkasnya saja tidak cukup karena rahasia tetap ada di
> riwayat Git. Ganti rahasia itu dulu, baru bersihkan riwayat repositorinya.

## 12. Masalah umum

| Gejala | Penyebab dan solusi |
|---|---|
| `Lab hanya didukung di Ubuntu...` | Pasang di Ubuntu Server 22.04/24.04 |
| Pesan uji Telegram gagal (HTTP 400/403) | Bot belum masuk grup, atau tanda minus chat id salah |
| `getUpdates` kosong | Kirim pesan di grup setelah bot masuk. Kalau bot memakai webhook, isi chat id manual |
| `Baseline belum ada` | `lab.sh baseline` |
| Notifikasi berulang setelah update plugin | `web-integrity-cek.sh --accept` |
| `--accept` ditolak karena `DB OJS BERUBAH` | Periksa dulu apa yang berubah, lalu terima dengan `web-integrity-cek.sh --snapdb` sebelum `--accept` |
| Backup tidak terkirim ke Drive/Telegram | Verifikasi hari ini ada FAIL; lihat `/var/log/audit-run/backup-verify-*.log` |
| Dump `.sql.gz` 20 byte, log berisi `1045 Access denied` | Kata sandi database di skrip backup tidak cocok |
| Verifikasi masih FAIL padahal skrip backup sudah diperbaiki | M4 mengecek berkas lama. Jalankan backup dulu, baru verifikasi ([bagian 9](#9-urutan-backup)) |
| Laporan: database `ojs` tidak ditemukan | `OJS_DB` belum diisi, jadi skrip memakai nama bawaan `ojs`. Jalankan `lab.sh ojs-db` |
| IP kantor selalu muncul sebagai IP mencurigakan | `IP_KANTOR` kosong atau IP kantor sudah berubah. Jalankan `lab.sh ip-admin` |
| IP Cloudflare (104.x, 172.64-71.x) muncul sebagai pelaku | Nginx belum memakai `real_ip_header CF-Connecting-IP` untuk semua situs |
| Situs error database setelah hardening | `L4-hardening-db.sh batal`, lalu periksa akun yang hanya punya hak global |
| Semua tindakan otomatis berhenti | FREEZE aktif: `freeze.sh status` |
| `cf-guard.py: Kurang di /etc/bodyguard/cloudflare.env` | `atur-token.sh cloudflare` |
| Tombol Setujui kadang tidak jalan | Bot persetujuan sama dengan bot notifikasi; pakai token berbeda ([bagian 4.3](#43-bot-persetujuan-t2)) |

## 13. Riwayat perubahan

**24 November 2026**

- **Ganti nama** supaya lebih mudah dipahami. Nama lama tidak diterima lagi; cara pindah ada di
  [Pindah dari versi lama](#pindah-dari-versi-lama).

  | Lama | Baru |
  |---|---|
  | folder `lapisan/`, `lingkungan/`, `modul/M5-penjaga-keputusan/` | `pencegahan/`, `pendukung/`, `modul/M5-blokir-attacker/` |
  | `cek-rahasia.sh` | `cek-sebelum-share.sh` |
  | FREEZE `/var/lib/penjaga/FREEZE`, grup `penjaga`, variabel `PENJAGA_FREEZE` | `/var/lib/freeze/FREEZE`, grup `freeze`, variabel `FREEZE_FILE` |
  | kunci `collect3`, `collect3_args`, `collect3_timeout` di `/etc/bodyguard/root.conf` | `kumpulkan_bukti`, `kumpulkan_bukti_args`, `kumpulkan_bukti_timeout` |
  | `penjaga.sh freeze` / `unfreeze` | `freeze.sh on` / `off` |
  | `bukti.py`, `collect3_evidence.sh` | `simpan-bukti.py`, `kumpulkan-bukti.sh` |
  | `lab.sh jadwal-pasang` / `jadwal-lepas` / `copot` | `lab.sh pasang-cron` / `lepas-cron` / `uninstall` |
  | mode `rencana` / `coba` / `terapkan` / `undo` (L3, L4); `tes` (L3) | `cek` / `uji` / `pasang` / `batal`; `cek-trigger` |
  | `salin-uji.py rencana` / `salin` | `salin-uji.py cek` / `buat` |
  | `uji-skripsi.py --panen` | `uji-skripsi.py --ambil-log` |
  | trigger `l3_tolak_penanda` | `l3_tolak_akun_palsu` |

- `kumpulkan-bukti.sh --auto` ikut mengambil berkas yang dilaporkan M1, dan tidak lagi menyalin berkas PHP bawaan
  aplikasi (cache template OJS, vendor, plugin/tema resmi).
- `uji-skripsi.py`: skenario dipadatkan menjadi 9 (S1-S7, N1-N2) ditambah restore drill R1; R1 diakhiri dengan cek
  bahwa hasil pulih bersih. Saat pertama dijalankan, `hasil.csv` yang berisi kode lama otomatis dipindah ke
  `hasil-sebelum-lama-<waktu>.csv`, jadi rekap tidak tercampur; uji K dan skenario dijalankan ulang.
- Baru: `L3-trigger-ojs.sh`, `lab.sh sinkron`, `lab.sh ip-admin`, `lab.sh ojs-db`, `STRUKTUR.md`.
- `salin-uji.py`: log salinan dipisah ke `/var/log/nginx/uji/`; SLiMS 9 dikenali; IP tetap kantor ikut diizinkan.
- `ip-kantor-sync.sh` ikut memperbarui daftar IP yang boleh membuka situs salinan.
- `web-integrity-cek.sh`: folder migrasi OJS tidak lagi dianggap "PHP di folder data"; ringkasan `--accept` menghitung
  semua berkas per situs (berubah, baru, hilang).
- `backup_vps.py`: kalau `pull --rebase` bentrok, rebase dibatalkan otomatis; tidak ada force push.
- Cron baru: `uji-skripsi.py --ambil-log` tiap 07:05.

**23 November 2026**

- `backup-verify.sh` v2: dump PostgreSQL dikenali; izin berkas backup diubah otomatis ke 600; uji pulih hanya
  memakai dump MariaDB yang utuh.
- `notify-run.sh`: notifikasi dikelompokkan (GAGAL, PERINGATAN, lain-lain), satu poin per baris.
- Baru: `salin-uji.py`, `L4-hardening-db.sh`, `arsip-log.sh`, `ip-kantor-sync.sh`, `cek-sebelum-share.sh`, `.gitignore`.

**20 November 2026**

- `atur-token.sh`: token Cloudflare tidak lagi tercetak di layar.
- `web-integrity-cek.sh`: service tidak lagi ditandai FAILED oleh systemd.

## 14. Lisensi

Bebas dipakai ulang untuk keperluan pendidikan. Rancangan dan hasil pengujian lengkap ada di naskah skripsi Bab III dan Bab IV.
