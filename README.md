# TUGAS-DDRPL
# BY GUS WIRA | XSCURE

# PENJELASAN PADA CODE DAN README.md DIBUAT OLEH CHATGPT

# WiFi Network Security and Management System

Sistem ini dirancang untuk mengelola dan melindungi jaringan WiFi dari ancaman eksternal seperti **serangan DDoS**, **brute force login**, **spam password WiFi**, serta serangan hacker lainnya. Aplikasi ini berbasis **Flask** dan menggunakan **Scapy** untuk pemindaian dan deteksi lalu lintas jaringan.

## Fitur Utama

1. **Pemindaian Jaringan**:
   - Memindai perangkat yang terhubung ke jaringan.
   - Menampilkan informasi perangkat seperti alamat IP, MAC, dan vendor.
   
2. **Pemutusan Koneksi Perangkat**:
   - Memutus perangkat yang tidak dikenali atau dicurigai melalui MAC Address.

3. **Proteksi DDoS**:
   - Mendeteksi serangan DDoS berdasarkan lalu lintas jaringan.
   - Memblokir perangkat yang terindikasi melakukan serangan DDoS.

4. **Proteksi Spam Login**:
   - Mendeteksi percobaan login yang berulang-ulang (spam) dalam jangka waktu singkat.
   - Memblokir IP perangkat yang mencoba melakukan brute force password WiFi.

5. **Deteksi dan Pencegahan Hacker**:
   - Memantau lalu lintas jaringan untuk mendeteksi serangan hacker melalui port berbahaya seperti SSH (port 22) dan Telnet (port 23).
   - Memblokir IP perangkat yang terdeteksi melakukan aktivitas mencurigakan.

6. **Proteksi Otomatis**:
   - Proteksi otomatis diaktifkan berdasarkan aktivitas yang terdeteksi di jaringan, seperti serangan DDoS, spam login, atau brute force.

## Instalasi

### Persyaratan

- Python 3.x
- Flask
- Scapy
- WinPcap (untuk pengguna Windows)

### Langkah Instalasi

1. Clone repositori ini:
   ```bash
   git clone https://github.com/zynxx24/TUGAS-DDRPL.git
   cd TUGAS-DDRPL
   ```

2. Install dependencies Python:
   ```bash
   pip install -r requirements.txt
   ```

3. Pada sistem Windows, pastikan Anda menginstall **WinPcap** agar Scapy dapat bekerja:
   - Download WinPcap dari [sini](https://www.winpcap.org/install/default.htm) dan install di sistem Anda.

4. Jalankan aplikasi:
   ```bash
   python app.py
   ```

5. Akses aplikasi di browser melalui:
   ```
   http://localhost:3090
   ```

## Penggunaan

- **Melihat perangkat terhubung**: Akses halaman utama untuk melihat daftar perangkat yang terhubung ke jaringan.
- **Memutus perangkat**: Klik tombol "Disconnect" di sebelah perangkat yang ingin diputus dari jaringan.
- **Aktifkan proteksi DDoS dan spam login**: Klik tombol "Protect DDoS" untuk memulai proteksi otomatis.
- **Aktifkan proteksi hacker**: Jalankan deteksi lalu lintas hacker dengan mengunjungi endpoint `/start_hacker_protection`.

## Struktur Proyek

- `app.py`: File utama aplikasi Flask yang berisi logika untuk pemindaian jaringan, proteksi, dan manajemen perangkat.
- `templates/index.html`: Tampilan web untuk menampilkan perangkat terhubung dan kontrol jaringan.
- `network_security.log`: File log yang menyimpan aktivitas jaringan mencurigakan.
