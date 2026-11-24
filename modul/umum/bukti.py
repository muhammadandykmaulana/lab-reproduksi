#!/usr/bin/python3 -I
# -*- coding: utf-8 -*-
"""bukti.py - SATU fungsi penyimpan bukti untuk semua modul (utilitas bersama).

Dipakai oleh collect3_evidence.sh, persistence-killer.sh --kill/--auto, dan bg-root (SOC-IR, lewat stdin).
Setiap bukti disimpan dengan cara yang sama:
  BUKTI_DIR/<kasus>/<sha256>.bin        salinan isi, izin 0400 (tanpa hak eksekusi), nama = hash (tidak ada duplikat)
  BUKTI_DIR/<kasus>/<sha256>.<ms>.json  metadata (sumber, ukuran, izin, pemilik, waktu ubah, waktu ambil)
  BUKTI_DIR/<kasus>/MANIFEST.tsv        satu baris per pengambilan: waktu, sha256, ukuran, label, sumber
Salinan diverifikasi ulang (hash dibaca kembali dari disk). Tidak ada yang dihapus atau ditimpa.

Pemakaian (root):
  bukti.py simpan --kasus KASUS [--label TEKS] [--maks BYTE] -- BERKAS...
        menyalin berkas; symlink pada komponen terakhir ditolak (O_NOFOLLOW), bukan berkas biasa dilewati
  bukti.py simpan-stdin --kasus KASUS --label TEKS [--sha256 HEX] [--meta-json JSON] [--min-free BYTE]
        menyimpan isi dari STDIN; bila --sha256 diberikan, isi harus cocok (dipakai bg-root)
  bukti.py periksa --kasus KASUS
        mencocokkan ulang semua *.bin dengan namanya (deteksi bukti yang berubah)
Opsi umum: --dir FOLDER (bawaan $BUKTI_DIR atau /var/opt/bukti).
Keluaran: satu baris JSON per berkas. Kode keluar: 0 ok, 2 argumen salah, 3 ditolak, 5 gagal.
"""

import argparse
import hashlib
import json
import os
import re
import stat
import sys
import time

KASUS_RE = re.compile(r"\A[A-Za-z0-9][A-Za-z0-9._-]{0,99}\Z")
SHA_RE = re.compile(r"\A[0-9a-f]{64}\Z")
O_CLOEXEC = getattr(os, "O_CLOEXEC", 0)
MAKS_BAWAAN = 200 * 1024 * 1024


class Ditolak(Exception):
    kode = 3


class Gagal(Exception):
    kode = 5


def _bersih(s, n=300):
    s = "".join(ch if 32 <= ord(ch) < 127 else "?" for ch in str(s))
    return s[:n]


def _tulis_semua(fd, data):
    view = memoryview(data)
    while view:
        n = os.write(fd, view)
        view = view[n:]


def _buka_folder(path, wajib_root):
    os.makedirs(path, mode=0o700, exist_ok=True)
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | O_CLOEXEC)
    st = os.fstat(fd)
    if wajib_root and (st.st_uid != 0 or stat.S_IMODE(st.st_mode) & 0o077):
        os.close(fd)
        raise Ditolak("folder bukti %s harus milik root dengan izin 0700" % path)
    return fd


def simpan_bytes(folder, kasus, data, label, meta=None, sha_harap=None, min_free=0, wajib_root=None):
    """Fungsi inti. Kembalikan dict hasil. Dipanggil juga oleh simpan berkas."""
    if not KASUS_RE.match(kasus or ""):
        raise Ditolak("nama kasus tidak valid")
    if wajib_root is None:
        wajib_root = os.geteuid() == 0
    sha = hashlib.sha256(data).hexdigest()
    if sha_harap and sha != sha_harap:
        raise Ditolak("isi tidak cocok dengan sha256 yang diharapkan")
    vfd = _buka_folder(folder, wajib_root)
    try:
        vfs = os.fstatvfs(vfd)
        if min_free and vfs.f_bavail * vfs.f_frsize - len(data) < min_free:
            raise Ditolak("ruang disk folder bukti di bawah batas minimum; bukti tidak disimpan")
        try:
            os.mkdir(kasus, 0o700, dir_fd=vfd)
        except FileExistsError:
            pass
        kfd = os.open(kasus, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | O_CLOEXEC, dir_fd=vfd)
        try:
            nama = sha + ".bin"
            try:
                efd = os.open(nama, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | O_CLOEXEC, 0o400, dir_fd=kfd)
                try:
                    _tulis_semua(efd, data)
                    os.fsync(efd)
                finally:
                    os.close(efd)
            except FileExistsError:
                pass  # isi identik sudah tersimpan
            rfd = os.open(nama, os.O_RDONLY | os.O_NOFOLLOW | O_CLOEXEC, dir_fd=kfd)
            try:
                h = hashlib.sha256()
                while True:
                    b = os.read(rfd, 1 << 20)
                    if not b:
                        break
                    h.update(b)
            finally:
                os.close(rfd)
            if h.hexdigest() != sha:
                raise Gagal("verifikasi salinan bukti gagal (hash berbeda)")
            waktu = time.time()
            m = dict(meta or {})
            m.update({"kasus": kasus, "label": _bersih(label), "sha256": sha, "ukuran": len(data), "diambil": waktu})
            mnama = "%s.%d.%s.json" % (sha, int(waktu * 1000), os.urandom(3).hex())
            mfd = os.open(mnama, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | O_CLOEXEC, 0o400, dir_fd=kfd)
            try:
                _tulis_semua(mfd, json.dumps(m, ensure_ascii=True, sort_keys=True, indent=1).encode("ascii"))
                os.fsync(mfd)
            finally:
                os.close(mfd)
            baris = "%s\t%s\t%d\t%s\t%s\n" % (time.strftime("%Y-%m-%dT%H:%M:%S%z", time.localtime(waktu)), sha, len(data),
                                             _bersih(label, 80).replace("\t", " "), _bersih(m.get("sumber", "-")).replace("\t", " "))
            afd = os.open("MANIFEST.tsv", os.O_WRONLY | os.O_CREAT | os.O_APPEND | os.O_NOFOLLOW | O_CLOEXEC, 0o600, dir_fd=kfd)
            try:
                _tulis_semua(afd, baris.encode("ascii", "replace"))
            finally:
                os.close(afd)
            os.fsync(kfd)
        finally:
            os.close(kfd)
    finally:
        os.close(vfd)
    return {"ok": True, "sha256": sha, "ukuran": len(data), "path": os.path.join(folder, kasus, sha + ".bin")}


def simpan_berkas(folder, kasus, path, label, maks):
    """Baca berkas tanpa mengikuti symlink, lalu simpan lewat simpan_bytes."""
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | O_CLOEXEC | getattr(os, "O_NONBLOCK", 0))
    except OSError as e:
        raise Ditolak("%s: tidak bisa dibuka tanpa mengikuti symlink (%s)" % (_bersih(path), e.__class__.__name__))
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode):
            raise Ditolak("%s: bukan berkas biasa" % _bersih(path))
        if st.st_size > maks:
            raise Ditolak("%s: %d byte melebihi batas %d" % (_bersih(path), st.st_size, maks))
        bagian = []
        while True:
            b = os.read(fd, 1 << 20)
            if not b:
                break
            bagian.append(b)
            if sum(len(x) for x in bagian) > maks:
                raise Ditolak("%s: bertambah melebihi batas saat dibaca" % _bersih(path))
        data = b"".join(bagian)
    finally:
        os.close(fd)
    meta = {"sumber": path, "mode": "%04o" % stat.S_IMODE(st.st_mode), "uid": st.st_uid, "gid": st.st_gid,
            "mtime": st.st_mtime, "ctime": st.st_ctime, "inode": st.st_ino}
    return simpan_bytes(folder, kasus, data, label or os.path.basename(path), meta)


def periksa(folder, kasus):
    d = os.path.join(folder, kasus)
    hasil, rusak = 0, 0
    for n in sorted(os.listdir(d)):
        if not n.endswith(".bin"):
            continue
        h = hashlib.sha256()
        with open(os.path.join(d, n), "rb") as f:
            for b in iter(lambda: f.read(1 << 20), b""):
                h.update(b)
        cocok = h.hexdigest() + ".bin" == n
        hasil += 1
        rusak += 0 if cocok else 1
        print(json.dumps({"berkas": n, "utuh": cocok}))
    print(json.dumps({"kasus": kasus, "jumlah": hasil, "rusak": rusak}))
    return 0 if rusak == 0 else 5


def main(argv=None):
    ap = argparse.ArgumentParser(prog="bukti.py")
    ap.add_argument("--dir", default=os.environ.get("BUKTI_DIR", "/var/opt/bukti"))
    sub = ap.add_subparsers(dest="cmd")
    p = sub.add_parser("simpan")
    p.add_argument("--kasus", required=True)
    p.add_argument("--label", default="")
    p.add_argument("--maks", type=int, default=MAKS_BAWAAN)
    p.add_argument("berkas", nargs="+")
    p = sub.add_parser("simpan-stdin")
    p.add_argument("--kasus", required=True)
    p.add_argument("--label", required=True)
    p.add_argument("--sha256", default="")
    p.add_argument("--meta-json", default="{}")
    p.add_argument("--min-free", type=int, default=0)
    p.add_argument("--maks", type=int, default=MAKS_BAWAAN)
    p = sub.add_parser("periksa")
    p.add_argument("--kasus", required=True)
    a = ap.parse_args(argv)
    if not a.cmd:
        ap.print_help()
        return 2
    if not os.path.isabs(a.dir):
        print(json.dumps({"ok": False, "galat": "--dir harus path absolut"}))
        return 2
    os.umask(0o077)
    kode = 0
    try:
        if a.cmd == "periksa":
            if not KASUS_RE.match(a.kasus):
                raise Ditolak("nama kasus tidak valid")
            return periksa(a.dir, a.kasus)
        if a.cmd == "simpan-stdin":
            if a.sha256 and not SHA_RE.match(a.sha256):
                raise Ditolak("sha256 tidak valid")
            meta = json.loads(a.meta_json)
            if not isinstance(meta, dict):
                raise Ditolak("--meta-json harus objek JSON")
            data = sys.stdin.buffer.read(a.maks + 1)
            if len(data) > a.maks:
                raise Ditolak("isi melebihi batas %d byte" % a.maks)
            print(json.dumps(simpan_bytes(a.dir, a.kasus, data, a.label, meta, a.sha256 or None, a.min_free)))
            return 0
        for b in a.berkas:
            try:
                print(json.dumps(dict(simpan_berkas(a.dir, a.kasus, b, a.label, a.maks), sumber=_bersih(b))))
            except Ditolak as e:
                print(json.dumps({"ok": False, "sumber": _bersih(b), "galat": str(e)}))
                kode = 3
    except (Ditolak, Gagal) as e:
        print(json.dumps({"ok": False, "galat": str(e)}))
        return e.kode
    except (OSError, ValueError) as e:
        print(json.dumps({"ok": False, "galat": "%s: %s" % (e.__class__.__name__, _bersih(e))}))
        return 5
    return kode


if __name__ == "__main__":
    sys.exit(main())
