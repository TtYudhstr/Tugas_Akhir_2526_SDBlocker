# Smart USB Data Blocker (SD-Blocker)

**Prototipe pengaman USB berbasis algoritma *Authenticated Encryption with Associated Data* (AEAD) untuk mencegah serangan *juice jacking*.**

Repositori ini memuat seluruh aset Tugas Akhir, meliputi *source code* firmware, aplikasi Authenticator, skematik, hingga desain prototipe. Sistem diimplementasikan dalam **dua varian algoritma AEAD** yang diuji dan dibandingkan secara menyeluruh:

1. **ASCON-AEAD128** (NIST SP 800-232) sebagai implementasi utama, dan
2. **ChaCha20-Poly1305** (RFC 8439) sebagai implementasi pembanding.

> **Video simulasi perangkat:** https://www.youtube.com/watch?v=aObp-zUMLXI
>
> [![Simulasi SD-Blocker](https://img.youtube.com/vi/aObp-zUMLXI/maxresdefault.jpg)](https://www.youtube.com/watch?v=aObp-zUMLXI)

---

## Latar Belakang

*Charging station* publik di bandara, stasiun, dan kafe menyimpan risiko **juice jacking**, yaitu pencurian data atau penyisipan *malware* melalui jalur data USB yang aktif tanpa disadari pengguna saat mengisi daya. USB data blocker pasif yang beredar di pasaran memutus jalur data secara **permanen**. Pendekatan tersebut aman, tetapi tidak fleksibel karena pengguna tidak dapat melakukan transfer data sama sekali.

**SD-Blocker** menjembatani keduanya dengan prinsip **fail-closed adaptif**:

- Kondisi *default*: hanya jalur daya (VBUS/GND) yang tersambung, sedangkan jalur data D+/D- **diputus secara fisik** oleh IC USB switch.
- Jalur data **hanya terbuka** setelah pengguna terautentikasi melalui protokol *challenge-response* berbasis AEAD.
- Saat sesi berakhir, atau ketika autentikasi gagal, sistem selalu kembali ke kondisi tertutup.

## Arsitektur Perangkat

| Komponen | Fungsi |
|---|---|
| **ESP32-S3** | Mikrokontroler utama: pembangkit nonce (TRNG perangkat keras), verifikasi tag AEAD, kendali switch |
| **FSUSB42MUX** | IC USB switch yang memutus/menyambungkan jalur D+/D- secara fisik |
| **LED indikator** | Penanda status perangkat (tertutup / sesi aktif) |
| **PCB custom** | Desain papan rangkaian prototipe (lihat folder `Printed Circuit Board (PCB)/`) |

### Protokol Challenge-Response

```
SD-Blocker (ESP32-S3)                    Laptop (Aplikasi Authenticator)
        |                                           |
        |--- CHALLENGE: nonce 96-bit (TRNG) ------->|
        |                                           | K = PBKDF2-SHA256(password, salt, 600.000 iterasi)
        |                                           | C || T = AEAD(K, nonce, AD, payload)
        |<-- RESPONSE: payload terenkripsi + tag ---|
        | verifikasi tag T                          |
        | tag valid  -> FSUSB42 sambungkan D+/D-    |
        | tag salah  -> jalur data tetap tertutup   |
```

- Fungsi AEAD pada diagram di atas berlaku untuk kedua varian: ASCON-AEAD128 maupun ChaCha20-Poly1305.
- Nonce dibangkitkan oleh TRNG ESP32-S3 dan tidak pernah dipakai ulang (diverifikasi pada 1.000.000 sampel dengan 0% perulangan).
- Payload memuat kode instruksi, identitas perangkat (serial number), dan timestamp. Format divalidasi sebelum diproses.
- Kegagalan apa pun (tag salah, format salah, timeout 5 detik) membuat sistem tetap atau kembali **fail-closed**.

## Struktur Repositori

```
├── Aplikasi/                      # Aplikasi Authenticator: .exe siap pakai + source code Python
├── Firmware/                      # Firmware ESP32-S3 (varian ASCON-AEAD128 & ChaCha20-Poly1305)
├── Printed Circuit Board (PCB)/   # Desain PCB prototipe
│   ├── Altium/                    # Proyek Altium Designer
│   └── EasyEDA/                   # Proyek EasyEDA
└── README.md
```

## Menjalankan Aplikasi Authenticator

Aplikasi sudah tersedia dalam bentuk **executable portabel (.exe)** di folder [`Aplikasi/`](Aplikasi). Tidak diperlukan instalasi Python maupun library apa pun.

1. Unduh file .exe dari folder `Aplikasi/` sesuai varian yang diinginkan (ASCON-AEAD128 atau ChaCha20-Poly1305).
2. Hubungkan SD-Blocker ke laptop melalui kabel USB.
3. Jalankan file .exe.

> Catatan: Windows SmartScreen mungkin menampilkan peringatan saat pertama kali dijalankan. Pilih **More info > Run anyway**.

Fitur kedua varian aplikasi identik: deteksi serial number otomatis (read-only), buka jalur data, tutup sesi, ganti password, dan penyimpanan log aktivitas (.txt) dengan timestamp.

### Menjalankan dari source code

**Kebutuhan:** Python 3.10+, Windows/Linux.

```bash
pip install pyserial pycryptodome
cd Aplikasi

# Varian ASCON-AEAD128
python main.py

# Varian ChaCha20-Poly1305
python main_chacha.py
```

Membangun ulang *executable* portabel (Windows):

```bash
pip install pyinstaller
cd Aplikasi

# Varian ASCON
pyinstaller --onefile --windowed --icon=shield.ico main.py

# Varian ChaCha20-Poly1305
pyinstaller --onefile --windowed --icon=shield.ico main_chacha.py
```

## Kompilasi Firmware

1. Pasang **Arduino IDE** beserta board package **ESP32 by Espressif** (pilih board *ESP32S3 Dev Module*).
2. Pasang library yang dibutuhkan (lihat tabel sumber library di bawah).
3. Pilih varian yang diinginkan pada folder `Firmware/`:
   - `firmware.ino` untuk varian ASCON-AEAD128, atau
   - `firmware_chacha.ino` untuk varian ChaCha20-Poly1305.
4. *Upload* ke ESP32-S3.

Kedua firmware memakai alur autentikasi, penyimpanan kredensial (Preferences/LittleFS), dan kendali FSUSB42 yang sama. Perbedaannya hanya pada primitif AEAD yang digunakan.

## Ringkasan Hasil Pengujian

### Pengujian fungsional

| Pengujian | Hasil |
|---|---|
| Known Answer Test (KAT) | 100% sesuai vektor uji |
| Keunikan nonce (1.000.000 sampel TRNG) | 0% perulangan |
| Penolakan autentikasi tidak sah | 100% |

### Perbandingan ASCON-AEAD128 vs ChaCha20-Poly1305

| Parameter | ASCON-AEAD128 | ChaCha20-Poly1305 |
|---|---|---|
| Latensi dekripsi rata-rata (n = 1000) | 64,73 µs | 116,84 µs |
| Waktu proses autentikasi end-to-end | 146,00 ms | 145,89 ms |
| Alokasi heap saat operasi | 84 B | 340 B |
| Ukuran state internal | 40 B | 240 B |

ASCON unggul sekitar 1,8 kali pada latensi dekripsi dan jauh lebih hemat memori, karena berbasis satu permutasi sponge monolitik dengan state 320 bit. ChaCha20-Poly1305 memakai dua primitif terpisah (cipher ChaCha20 dan autentikator Poly1305) sehingga kebutuhan memorinya lebih besar. Pada waktu proses end-to-end keduanya praktis setara karena durasi didominasi komunikasi serial, bukan komputasi kriptografi. Analisis lengkap tersedia pada dokumen Tugas Akhir.

## Sumber Library

### Firmware (Arduino / ESP32-S3)

| Library | Kegunaan | Sumber |
|---|---|---|
| ASCON C reference (`api.h`, `crypto_aead.h`) | Implementasi ASCON-AEAD128 pada firmware varian ASCON | https://github.com/ascon/ascon-c |
| Arduino Cryptography Library (`Crypto.h`, `ChaChaPoly.h`) | Implementasi ChaCha20-Poly1305 pada firmware varian ChaCha | https://github.com/rweather/arduinolibs |
| Arduino-ESP32 core (`WiFi.h`, `LittleFS.h`, `Preferences.h`) | Board support, penyimpanan konfigurasi dan kredensial | https://github.com/espressif/arduino-esp32 |
| Adafruit NeoPixel (`Adafruit_NeoPixel.h`) | Kendali LED indikator status | https://github.com/adafruit/Adafruit_NeoPixel |

### Aplikasi (Python)

| Library | Kegunaan | Sumber |
|---|---|---|
| pyascon, diadaptasi sebagai `ascon_nist.py` | Implementasi ASCON-AEAD128 (NIST SP 800-232) pada aplikasi varian ASCON | https://github.com/meichlseder/pyascon |
| PyCryptodome: `Crypto.Cipher.ChaCha20_Poly1305` | Implementasi ChaCha20-Poly1305 pada aplikasi varian ChaCha | https://github.com/Legrandin/pycryptodome |
| PyCryptodome: `Crypto.Protocol.KDF`, `Crypto.Hash` | Derivasi kunci PBKDF2-HMAC-SHA256 (600.000 iterasi) pada kedua varian | https://github.com/Legrandin/pycryptodome |
| pySerial | Komunikasi serial antara aplikasi dan ESP32-S3 | https://github.com/pyserial/pyserial |
| Tkinter | Antarmuka grafis aplikasi | Pustaka standar Python |
| PyInstaller | Pengemasan aplikasi menjadi .exe portabel | https://pyinstaller.org |

### Referensi utama

- NIST SP 800-232: *Ascon-Based Lightweight Cryptography Standards for Constrained Devices*
- Spesifikasi ASCON: https://ascon.iaik.tugraz.at/
- RFC 8439: *ChaCha20 and Poly1305 for IETF Protocols*
- Datasheet FSUSB42MUX (onsemi): *Low-Power, Two-Port, High-Speed USB 2.0 Switch*

## Tentang Proyek

Proyek ini merupakan Tugas Akhir:

> **"Rancang Bangun Prototipe Smart USB Data Blocker Berbasis Algoritma Authenticated Encryption with Associated Data (AEAD) untuk Mencegah Serangan Juice Jacking"**
>
> Seto Yudhistiro Hatmojo, IV Rekayasa Perangkat Keras Kriptografi, Politeknik Siber dan Sandi Negara, 2026.

Video simulasi pra-sidang: https://www.youtube.com/watch?v=aObp-zUMLXI
