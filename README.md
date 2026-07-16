# Smart USB Data Blocker (SD-Blocker)

**Prototipe pengaman USB berbasis algoritma *Authenticated Encryption with Associated Data* (AEAD) untuk mencegah serangan *juice jacking*.**

Repositori ini memuat seluruh aset Tugas Akhir — *source code* firmware, aplikasi Authenticator, skematik, hingga desain prototipe.

> 🎬 **Video simulasi perangkat:** https://www.youtube.com/watch?v=aObp-zUMLXI
>
> [![Simulasi SD-Blocker](https://img.youtube.com/vi/aObp-zUMLXI/maxresdefault.jpg)](https://www.youtube.com/watch?v=aObp-zUMLXI)

---

## 📌 Latar Belakang

*Charging station* publik (bandara, stasiun, kafe) menyimpan risiko **juice jacking**: pencurian data atau penyisipan *malware* melalui jalur data USB yang aktif tanpa disadari pengguna saat mengisi daya. USB data blocker pasif yang beredar di pasaran memutus jalur data secara **permanen**, sehingga aman tetapi tidak fleksibel — pengguna tidak dapat melakukan transfer data sama sekali.

**SD-Blocker** menjembatani keduanya dengan prinsip **fail-closed adaptif**:

- Kondisi *default*: hanya jalur daya (VBUS/GND) yang tersambung — jalur data D+/D− **diputus secara fisik** oleh IC USB switch.
- Jalur data **hanya terbuka** setelah pengguna terautentikasi melalui protokol *challenge–response* berbasis AEAD **ASCON-AEAD128 (NIST SP 800-232)**.
- Saat sesi berakhir (atau autentikasi gagal), sistem selalu kembali ke kondisi tertutup.

## ⚙️ Arsitektur Perangkat

| Komponen | Fungsi |
|---|---|
| **ESP32-S3** | Mikrokontroler utama: pembangkit nonce (TRNG perangkat keras), verifikasi tag AEAD, kendali switch |
| **FSUSB42MUX** | IC USB switch: memutus/menyambungkan jalur D+/D− secara fisik |
| **LED indikator** | Status perangkat (tertutup / sesi aktif) |
| **PCB custom** | Desain papan rangkaian prototipe (lihat folder `hardware/`) |

### Protokol Challenge–Response

```
SD-Blocker (ESP32-S3)                    Laptop (Aplikasi Authenticator)
        |                                           |
        |--- CHALLENGE: nonce 96-bit (TRNG) ------->|
        |                                           | K = PBKDF2-SHA256(password, salt, 600.000 iterasi)
        |                                           | C ‖ T = ASCON-AEAD128(K, nonce, AD, payload)
        |<-- RESPONSE: payload terenkripsi + tag ---|
        | verifikasi tag T                          |
        | tag valid  -> FSUSB42 sambungkan D+/D-    |
        | tag salah  -> jalur data tetap tertutup   |
```

- Nonce dibangkitkan oleh TRNG ESP32-S3 dan tidak pernah dipakai ulang (diverifikasi 1.000.000 sampel, 0% perulangan).
- Payload memuat kode instruksi, identitas perangkat (serial number), dan timestamp; format divalidasi sebelum diproses.
- Kegagalan apa pun (tag salah, format salah, timeout 5 detik) membuat sistem tetap/kembali **fail-closed**.

## 📂 Struktur Repositori

```
├── firmware/            # Firmware ESP32-S3 (Arduino) — ASCON-AEAD128
│   └── firmware.ino
├── firmware-chacha/     # Varian pembanding — ChaCha20-Poly1305
│   └── firmware_chacha.ino
├── app/                 # Aplikasi Authenticator (Python)
│   ├── main.py          # GUI Tkinter (splash, autentikasi, sesi, log)
│   ├── ascon_nist.py    # Implementasi ASCON-AEAD128 (NIST SP 800-232)
│   └── UX2_ASCON.py     # Versi CLI
├── hardware/            # Skematik & desain PCB prototipe
└── docs/                # Dokumentasi & flowchart
```

## 🖥️ Menjalankan Aplikasi Authenticator

**Kebutuhan:** Python 3.10+, Windows/Linux.

```bash
pip install pyserial pycryptodome
python app/main.py
```

Membangun *executable* portabel (Windows):

```bash
pip install pyinstaller
pyinstaller --onefile --windowed --icon=shield.ico app/main.py
```

Fitur aplikasi: deteksi serial number otomatis (read-only), buka jalur data, tutup sesi, ganti password, dan penyimpanan log aktivitas (.txt) dengan timestamp.

## 🔌 Kompilasi Firmware

1. Pasang **Arduino IDE** + board package **ESP32 by Espressif** (pilih board *ESP32S3 Dev Module*).
2. Pasang library yang dibutuhkan (lihat tabel sumber library di bawah).
3. Buka `firmware/firmware.ino`, lalu *upload* ke ESP32-S3.

## 📊 Ringkasan Hasil Pengujian

| Pengujian | Hasil |
|---|---|
| Known Answer Test (KAT) ASCON-AEAD128 | 100% sesuai vektor uji NIST |
| Keunikan nonce (1.000.000 sampel TRNG) | 0% perulangan |
| Penolakan autentikasi tidak sah | 100% |
| Latensi dekripsi ASCON (rata-rata, n=1000) | 64,73 µs |
| Alokasi memori state ASCON | 40 B (vs ChaCha20-Poly1305 240 B) |

Perbandingan lengkap ASCON vs ChaCha20-Poly1305 serta analisis terhadap penelitian terdahulu tersedia pada dokumen Tugas Akhir.

## 📚 Sumber Library

### Firmware (Arduino / ESP32-S3)

| Library | Kegunaan | Sumber |
|---|---|---|
| ASCON C reference (`api.h`, `crypto_aead.h`) | Implementasi ASCON-AEAD128 pada firmware | https://github.com/ascon/ascon-c |
| Arduino-ESP32 core (`WiFi.h`, `LittleFS.h`, `Preferences.h`) | Board support, penyimpanan konfigurasi & kredensial | https://github.com/espressif/arduino-esp32 |
| Adafruit NeoPixel (`Adafruit_NeoPixel.h`) | Kendali LED indikator status | https://github.com/adafruit/Adafruit_NeoPixel |
| Arduino Cryptography Library (`Crypto.h`, `ChaChaPoly.h`) | Varian pembanding ChaCha20-Poly1305 | https://github.com/rweather/arduinolibs |

### Aplikasi (Python)

| Library | Kegunaan | Sumber |
|---|---|---|
| pyascon — diadaptasi sebagai `ascon_nist.py` | Implementasi ASCON-AEAD128 (NIST SP 800-232) sisi aplikasi | https://github.com/meichlseder/pyascon |
| PyCryptodome (`Crypto.Protocol.KDF`, `Crypto.Hash`) | Derivasi kunci PBKDF2-HMAC-SHA256 (600.000 iterasi) | https://github.com/Legrandin/pycryptodome |
| pySerial | Komunikasi serial aplikasi ↔ ESP32-S3 | https://github.com/pyserial/pyserial |
| Tkinter | Antarmuka grafis aplikasi | Pustaka standar Python |
| PyInstaller | Pengemasan aplikasi menjadi .exe portabel | https://pyinstaller.org |

### Referensi utama

- NIST SP 800-232 — *Ascon-Based Lightweight Cryptography Standards for Constrained Devices*
- Spesifikasi ASCON: https://ascon.iaik.tugraz.at/
- Datasheet FSUSB42MUX (onsemi) — *Low-Power, Two-Port, High-Speed USB 2.0 Switch*

## 🎓 Tentang Proyek

Proyek ini merupakan Tugas Akhir:

> **"Rancang Bangun Prototipe Smart USB Data Blocker Berbasis Algoritma Authenticated Encryption with Associated Data (AEAD) untuk Mencegah Serangan Juice Jacking"**
>
> Seto Yudhistiro Hatmojo — IV Rekayasa Perangkat Keras Kriptografi, Politeknik Siber dan Sandi Negara, 2026.

Video simulasi pra-sidang: https://www.youtube.com/watch?v=aObp-zUMLXI
