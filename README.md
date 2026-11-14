# Homelab Security Project

Project latihan cybersecurity pribadi menggunakan virtualisasi (VMware Workstation Pro), dibuat untuk menghubungkan materi semester 1-3 Teknik Informatika (Polibatam) ke dalam satu lab praktik nyata: Linux fundamental, administrasi sistem, jaringan komputer, kriptografi terapan, network defender, DevOps, dan SOC essential.

## Arsitektur Lab

| Komponen | Detail |
|---|---|
| Hypervisor | VMware Workstation Pro |
| Target server | Ubuntu Server 26.04.1 LTS (`192.168.236.129`) |
| Attacker machine | Kali Linux 2026.3 (`192.168.236.130`) |
| Jaringan | NAT, subnet `192.168.236.0/24` |

## Daftar Isi

1. [Setup Ubuntu Server](#1-setup-ubuntu-server)
2. [Web Server (Nginx)](#2-web-server-nginx)
3. [Reconnaissance dari Kali (Nmap)](#3-reconnaissance-dari-kali-nmap)
4. [Hardening Firewall (UFW)](#4-hardening-firewall-ufw)
5. [HTTPS / Kriptografi Terapan](#5-https--kriptografi-terapan)
6. [Simulasi Brute Force & Fail2Ban](#6-simulasi-brute-force--fail2ban)
7. [SOC Essential — Log Analysis Scripts](#7-soc-essential--log-analysis-scripts)
8. [Pembelajaran & Keterbatasan](#8-pembelajaran--keterbatasan)
9. [Rencana Lanjutan](#9-rencana-lanjutan)

---

## 1. Setup Ubuntu Server

- Instalasi Ubuntu Server 26.04.1 LTS di VMware (2 vCPU, 2GB RAM, 25GB disk).
- Partisi LVM diperbesar manual dari default 11,5GB menjadi ~23GB saat instalasi.
- OpenSSH server dipasang manual setelah instalasi (terlewat saat setup awal).
- Akses diverifikasi via SSH dari Windows host.

**Masalah yang ditemui:**

| Masalah | Penyebab | Solusi |
|---|---|---|
| SSH `Connection refused` | OpenSSH server belum terpasang | `sudo apt install openssh-server -y` |
| Partisi `/` hanya 11,5GB | Default LVM memakai separuh disk | Edit ukuran partisi manual saat instalasi |

## 2. Web Server (Nginx)

```bash
sudo apt install nginx -y
systemctl status nginx
```

Diverifikasi dengan mengakses `http://192.168.236.129` dari browser Windows host, menampilkan halaman default "Welcome to nginx!".

## 3. Reconnaissance dari Kali (Nmap)

Simulasi tahap *reconnaissance* yang biasa dilakukan penyerang sebelum menyerang.

```bash
ping -c 3 192.168.236.129
nmap 192.168.236.129
nmap -sV 192.168.236.129
```

**Hasil:**

| Port | Layanan | Versi |
|---|---|---|
| 22/tcp | ssh | OpenSSH 10.2p1 Ubuntu 3ubuntu3.8 |
| 80/tcp | http | nginx 1.28.3 |

Informasi versi ini (*banner/service fingerprinting*) adalah data yang biasa dimanfaatkan penyerang untuk mencari kerentanan spesifik versi software.

## 4. Hardening Firewall (UFW)

Firewall diaktifkan dengan kebijakan default deny, lalu hanya port yang diperlukan dibuka.

```bash
sudo ufw allow 22/tcp
sudo ufw allow 80/tcp
sudo ufw enable
```

Setelah diuji ulang dengan nmap dari Kali, port lain yang tadinya `closed` berubah menjadi **`filtered`** — bukti firewall aktif membuang paket tanpa balasan.

**Hardening lanjutan:** akses SSH dibatasi hanya untuk IP host Windows.

```bash
sudo ufw allow from 192.168.236.1 to any port 22 proto tcp
sudo ufw delete allow 22/tcp
```

**Hasil pengujian dari Kali setelah pembatasan:**

```
$ ssh -o ConnectTimeout=5 irene@192.168.236.129
ssh: connect to host 192.168.236.129 port 22: Connection timed out
```

```
$ nmap 192.168.236.129
999 filtered tcp ports (no-response)
80/tcp open http
```

| Tahap | Port 22 dari Kali | Port 80 dari Kali |
|---|---|---|
| Sebelum firewall | open | open |
| UFW aktif (22 & 80 diizinkan semua) | open | open |
| SSH dibatasi ke IP host | **filtered / timeout** | open |

## 5. HTTPS / Kriptografi Terapan

Sertifikat self-signed dibuat untuk mengaktifkan enkripsi TLS pada Nginx (karena lab tidak memiliki domain publik untuk Let's Encrypt).

```bash
sudo openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
  -keyout /etc/nginx/ssl/nginx-selfsigned.key \
  -out /etc/nginx/ssl/nginx-selfsigned.crt
```

Konfigurasi Nginx diubah menjadi dua server block: port 80 melakukan redirect otomatis (301) ke port 443 (HTTPS), yang melayani konten dengan sertifikat RSA 2048-bit tersebut.

**Diverifikasi:**
- `https://192.168.236.129` → halaman tampil dengan koneksi terenkripsi (peringatan browser "Not secure" muncul karena sertifikat self-signed, bukan karena koneksi tidak terenkripsi).
- `http://192.168.236.129` → otomatis redirect ke `https://`.

**Catatan konfigurasi:** file index default Ubuntu bernama `index.nginx-debian.html`, bukan `index.html`, sempat menyebabkan `403 Forbidden` sebelum di-rename.

## 6. Simulasi Brute Force & Fail2Ban

Simulasi serangan brute force SSH menggunakan Hydra dari Kali, untuk menguji efektivitas pertahanan berlapis.

```bash
hydra -l irene -P userpass.txt ssh://192.168.236.129
```

**Lapis 1 — Tanpa proteksi tambahan:** password ditemukan dalam hitungan detik (`irene26`).

**Lapis 2 — Penalty bawaan OpenSSH:** setelah beberapa kali gagal, muncul log:
```
sshd[1166]: srclimit_penalise: 192.168.236.130/32: activating ipv4 penalty of 18 seconds
```
Jeda singkat, tapi serangan tetap bisa dilanjutkan setelah menunggu.

**Lapis 3 — Fail2Ban:**

```bash
sudo apt install fail2ban -y
sudo systemctl enable --now fail2ban
```

Setelah percobaan gagal berulang, IP Kali diblokir total selama 600 detik (10 menit):

```
$ sudo fail2ban-client status sshd
Currently banned: 1
Banned IP list:   192.168.236.130
```

Percobaan Hydra berikutnya langsung gagal koneksi:
```
[ERROR] could not connect to ssh://192.168.236.129:22 - Connection refused
```

**Perbandingan tiga lapis pertahanan:**

| Lapis | Reaksi terhadap brute force |
|---|---|
| Tanpa proteksi | Semua password dicoba bebas, password lemah ditemukan dalam detik |
| Penalty bawaan OpenSSH | Jeda 18 detik usai gagal beruntun, tapi masih bisa dicoba lagi |
| Fail2Ban | IP diblokir total di firewall selama 10 menit, percobaan baru langsung ditolak |

## 7. SOC Essential — Log Analysis Scripts

Dua script Python dibuat untuk melatih logika deteksi serangan secara manual (bukan sekadar menggunakan tool SIEM jadi), ada di folder [`scripts/`](./scripts).

### `detect_ssh_bruteforce.py`

Membaca `/var/log/auth.log`, menghitung jumlah percobaan login gagal per IP, dan menandai IP sebagai **MENCURIGAKAN** jika melebihi threshold (5 kali).

**Hasil pengujian (data serangan Hydra sebelumnya):**
```
IP: 192.168.236.130
  Jumlah percobaan gagal: 11
  Username yang dicoba : irene
  Status               : MENCURIGAKAN
```
### Automasi dengan Cron

Script `monitor.py` dijadwalkan berjalan otomatis setiap 5 menit:

\`\`\`bash
*/5 * * * * /usr/bin/python3 /home/irene/soc-tools/monitor.py >> /home/irene/soc-tools/cron.log 2>&1
\`\`\`

Diverifikasi berjalan tanpa intervensi manual — `cron.log` terus bertambah isi setiap 5 menit sesuai jadwal.

**Keterbatasan ditemukan:** karena script membaca ulang seluruh log dari awal setiap kali dijalankan (tidak ada state/memori alert yang sudah dilaporkan), insiden lama yang sama terus dilaporkan berulang di setiap siklus cron. Ini mendemonstrasikan masalah **alert fatigue** yang nyata terjadi di SOC sungguhan — analis bisa kebanjiran alert duplikat dan mengabaikan alert baru yang justru penting.

### `detect_web_scan.py`

Membaca `/var/log/nginx/access.log`, menghitung jumlah response `404 Not Found` per IP (indikasi *scanning*/*directory brute force*), dengan threshold 10.

**Hasil pengujian:**
```
IP: 192.168.236.1 (trafik normal dari host Windows)
  Jumlah request 404: 3
  Status            : normal

IP: 192.168.236.130 (Kali, setelah nmap scan + simulasi scanning tambahan)
  Jumlah request 404: 19
  Status            : MENCURIGAKAN (kemungkinan scanning)
```
### `detect_web_attacks.py`

Membaca `/var/log/nginx/access.log` dan mencocokkan setiap request dengan pola regex serangan umum: **SQL Injection**, **Path Traversal**, dan **XSS**. Berbeda dari dua script sebelumnya yang berbasis *threshold* (jumlah percobaan), script ini berbasis *pattern matching* — satu request yang cocok pola saja langsung ditandai, karena satu percobaan SQLi/path traversal sudah cukup jadi indikator serangan, tidak perlu menunggu terjadi berkali-kali.

**Hasil pengujian** (request simulasi dari Kali menggunakan payload umum lewat `curl`):

## 8. Pembelajaran & Keterbatasan

- **Threshold sederhana efektif tapi punya trade-off.** Serangan jelas (banyak percobaan dalam waktu singkat) mudah tertangkap, tapi serangan pelan/stealthy (di bawah threshold) bisa lolos (*false negative*). Sebaliknya, pengguna asli yang salah ketik URL berkali-kali berisiko salah terdeteksi (*false positive*).
- **Alert fatigue teratasi dengan state tracking.** Versi awal `monitor.py` melaporkan ulang insiden lama yang sama di setiap siklus cron (5 menit sekali) karena membaca ulang seluruh log dari awal. Solusinya: menyimpan "memori" alert terakhir di `state.json` (IP, jumlah percobaan terakhir, jenis serangan yang sudah dilaporkan), lalu hanya mengirim alert baru jika ada *peningkatan* dari yang tercatat sebelumnya. Ini meniru prinsip deduplikasi alert yang dipakai SIEM sungguhan.
- **Redirect HTTP→HTTPS dapat "menyembunyikan" serangan dari detector 404 sederhana.** Request `curl` tanpa opsi follow-redirect ke port 80 hanya menghasilkan kode 301, bukan 404, sehingga tidak tercatat sebagai anomali oleh script `detect_web_scan.py`.
- **User-Agent bisa dipalsukan.** Di lab ini, Nmap Scripting Engine tidak menyamarkan identitasnya, tapi di dunia nyata analis SOC tidak bisa hanya mengandalkan User-Agent sebagai penanda.
- **Defense in depth bekerja lebih baik daripada satu lapis saja.** Kombinasi firewall (membatasi akses), fail2ban (merespons otomatis), dan monitoring log (mendeteksi & mendokumentasikan) saling melengkapi kelemahan masing-masing.

## 9. Rencana Lanjutan

- [ ] Integrasi dengan Wazuh (SIEM) untuk monitoring terpusat.
- [x] Menambah deteksi pola serangan lain (SQL injection attempt, path traversal, XSS).
- [ ] Automasi script menjadi cron job dengan notifikasi (email/webhook).
- [ ] Segmentasi jaringan lebih lanjut dengan VLAN simulasi.
- [x] Automasi script menjadi cron job.
- [x] Tambahkan state tracking (`state.json`) agar tidak lapor insiden yang sama berulang kali.

---

**Disclaimer:** seluruh aktivitas serangan (nmap, hydra) dilakukan hanya terhadap VM milik sendiri dalam jaringan lab tertutup, untuk tujuan pembelajaran.
