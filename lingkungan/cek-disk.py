#!/usr/bin/env python3
import subprocess
import time
from datetime import datetime
import os
import glob

# Telegram lewat satu pengirim bersama (notify-run.sh --pesan). Token dibaca notify-run dari
# /etc/web-integrity.env; bila service memakai EnvironmentFile=/etc/cek-disk.env, nilai di environment didahulukan.
NOTIFY_RUN = os.environ.get("NOTIFY_RUN", os.path.join(os.path.dirname(os.path.abspath(__file__)), "notify-run.sh"))
# Rotasi hanya bila verifikasi M4 hari ini PASS (penanda dibuat backup-verify.sh). Gambar 3.3 skripsi.
BV_STATE_DIR = os.environ.get("BV_STATE_DIR", "/var/lib/backup-verify")

# Konfigurasi auto-delete
auto_delete = True  # set True / False

# Folder backup yang dibersihkan: (folder, pola file).
# Aturan: hanya file yang cocok pola DAN tidak mengandung tanggal hari ini yang dihapus.
# Folder/file lain (docker, etc_named, backup_vps.zip, dll) tidak disentuh.
BACKUP_TARGETS = [
    ("/var/opt/BACKUP/web", "*"),
    ("/var/opt/BACKUP/DB", "*"),
]

# Variabel penanda waktu
last_alert_40 = None
last_alert_50 = None
last_delete = None


def get_disk_usage():
    try:
        result = subprocess.run(['df', '-h', '/'], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        if result.returncode != 0:
            print("Error:", result.stderr)
            return None
        lines = result.stdout.split('\n')
        if len(lines) < 2:
            return None
        parts = lines[1].split()
        if len(parts) < 5:
            return None
        return int(parts[4].replace('%', ''))
    except Exception as e:
        print(f"Error getting disk usage: {e}")
        return None


def send_telegram_alert(message):
    try:
        r = subprocess.run([NOTIFY_RUN, "--pesan"], input=message.replace("*", "").replace("`", "").encode(),
                           stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, timeout=60)
        if r.returncode != 0:
            print("Failed to send Telegram alert:", r.stderr.decode(errors="replace")[:200])
    except Exception as e:
        print(f"Error sending Telegram alert: {e}")


def verifikasi_lolos_hari_ini():
    return os.path.exists(os.path.join(BV_STATE_DIR, "lolos-" + datetime.now().strftime("%Y-%m-%d")))


def auto_delete_backup():
    """Hapus backup lama jika backup hari ini sudah ada di SEMUA folder target.
    Return True jika proses benar-benar dijalankan, False jika ditunda."""
    today_str = datetime.now().strftime("%Y_%m_%d")  # format pakai underscore
    if not verifikasi_lolos_hari_ini():
        print("Auto-delete ditunda: verifikasi backup (M4) hari ini belum PASS.")
        return False

    # Kumpulkan file per folder (hanya file biasa, bukan direktori)
    plan = []
    missing = []
    for folder, pattern in BACKUP_TARGETS:
        files = [f for f in glob.glob(os.path.join(folder, pattern)) if os.path.isfile(f)]
        keep = [f for f in files if today_str in os.path.basename(f)]
        if not keep:
            missing.append(folder)
        plan.append((folder, files))

    # backup_vps.zip tidak bertanggal di nama file: cek lewat waktu modifikasi (hari ini)
    vz = os.environ.get("BACKUP_VPS_DIR", "/var/opt/BACKUP/vps") + "/backup_vps.zip"
    if not (os.path.isfile(vz) and datetime.fromtimestamp(os.path.getmtime(vz)).date() == datetime.now().date()):
        missing.append(vz)

    # Kalau backup hari ini belum ada di salah satu folder, jangan hapus apa pun
    if missing:
        send_telegram_alert(
            f"⚠️ *Auto-delete ditunda.* Backup bertanggal `{today_str}` belum ditemukan di: "
            + ", ".join(f"`{m}`" for m in missing)
        )
        print("Auto-delete postponed, today backup missing in:", missing)
        return False

    deleted_count = 0
    freed_bytes = 0
    for folder, files in plan:
        for f in files:
            if today_str in os.path.basename(f):
                continue
            try:
                size = os.path.getsize(f)
                os.remove(f)
                deleted_count += 1
                freed_bytes += size
            except Exception as e:
                print(f"Failed to delete {f}: {e}")

    # [WAZUH] Dinonaktifkan karena Wazuh sudah di-uninstall.
    # print("Menjalankan pembersihan darurat log Wazuh (> 7 hari)...")
    # try:
    #     container_name = "single-node-wazuh.manager-1"
    #     subprocess.run([
    #         "docker", "exec", container_name,
    #         "find", "/var/ossec/logs/alerts", "-type", "f", "-name", "*.gz", "-mtime", "+7", "-delete"
    #     ], check=False)
    #     subprocess.run([
    #         "docker", "exec", container_name,
    #         "find", "/var/ossec/logs/alerts", "-type", "d", "-empty", "-delete"
    #     ], check=False)
    # except Exception as e:
    #     print(f"Failed to clean Wazuh logs: {e}")

    if deleted_count > 0:
        freed_gb = freed_bytes / (1024 ** 3)
        send_telegram_alert(
            f"✅ *Auto-delete dijalankan.* {deleted_count} file backup lama dihapus, "
            f"sekitar {freed_gb:.2f} GB dibebaskan."
        )
    else:
        send_telegram_alert("ℹ️ *Auto-delete dijalankan*, namun tidak ada file lama yang perlu dihapus.")
    return True


def check_disk_and_alert():
    global last_alert_40, last_alert_50, last_delete

    usage = get_disk_usage()
    if usage is None:
        return

    current_time = datetime.now()

    if usage > 50:
        # Alert >50% setiap 12 jam
        if last_alert_50 is None or (current_time - last_alert_50).total_seconds() >= 12 * 3600:
            message = f"🚨 *Super Warning!* 🚨\nDisk saat ini {usage}%, harap segera lakukan penghapusan file!"
            send_telegram_alert(message)
            last_alert_50 = current_time
            last_alert_40 = current_time  # reset juga

        # auto-delete maksimal 1x per 24 jam.
        # last_delete hanya diisi jika penghapusan benar-benar jalan,
        # jadi kalau ditunda (backup hari ini belum ada) akan dicoba lagi pada pengecekan berikutnya.
        if auto_delete:
            if last_delete is None or (current_time - last_delete).total_seconds() >= 24 * 3600:
                if auto_delete_backup():
                    last_delete = current_time

    elif usage > 40:
        # Alert 40% setiap 24 jam
        if last_alert_40 is None or (current_time - last_alert_40).total_seconds() >= 24 * 3600:
            message = f"⚠️ *Warning!* ⚠️\nDisk saat ini {usage}%, harap lakukan penghapusan file!"
            send_telegram_alert(message)
            last_alert_40 = current_time


if __name__ == "__main__":
    print("Disk monitoring script started...", flush=True)
    while True:
        check_disk_and_alert()
        time.sleep(3600)  # Cek setiap jam
