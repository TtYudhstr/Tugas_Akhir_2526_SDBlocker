extern "C" {
#include "api.h"
}
#include "crypto_aead.h"

#include <Adafruit_NeoPixel.h>
#include <LittleFS.h>
#include <string.h>
#include <Preferences.h>
#include <WiFi.h>

// --- KONFIGURASI HARDWARE ---
#define RGB_PIN 48
#define SWITCH_PIN 4 // SEL PIN FSUSB42
#define NUMPIXELS 1
#define MAX_CIPHER_LEN 128
const size_t MAX_LOG_SIZE = 100000;

// --- DATA KEAMANAN DINAMIS ---
byte key[16];

Adafruit_NeoPixel pixels(NUMPIXELS, RGB_PIN, NEO_GRB + NEO_KHZ800);
Preferences preferences;

void setup() {
  Serial.begin(115200);

  // Idupkan Wi-Fi untuk suplai entropi
  WiFi.mode(WIFI_STA);
  WiFi.begin();

  // Inisialisasi Switch FSUSB42
  pinMode(SWITCH_PIN, OUTPUT);
  digitalWrite(SWITCH_PIN, LOW); // default: Jalur terputus

  // Inisialisasi LED RGB
  pixels.begin();
  pixels.setBrightness(20);
  setLedColor(255, 0, 0); // Merah

  // Inisialisasi LittleFS untuk LOG & WHITELIST
  if (!LittleFS.begin(true)) {
    Serial.println("LittleFS Gagal");
    while (1);
  } else {
    Serial.println("LittleFS Siap");
    if (!LittleFS.exists("/whitelist.txt")) {
      File f = LittleFS.open("/whitelist.txt", FILE_WRITE);
      f.close();
    }
  }

  // Inisialisasi NVS & panggil Master Key
  preferences.begin("kripto_data", false);
  size_t keyLen = preferences.getBytes("master_key", key, 16);

  if (keyLen != 16) {
    Serial.println("Kunci tidak ada/Gagal");
    setLedColor(255, 0, 0);
    while (1); // Lockdown jika tidak ada kunci
  } else {
    Serial.println("Kunci Berhasil");
  }

  Serial.println("SD-Blocker Siap...");
}

void loop() {
  if (Serial.available() > 0) {
    setLedColor(0, 0, 255); // Biru = sedang memproses
    delay(100);

    String input = Serial.readStringUntil('\n');
    input.trim();

    if (input.startsWith("REQUEST_NONCE:")) {
      String timestamp = input.substring(14);
      MulaiHandshake(timestamp);
    } else {
      setLedColor(255, 0, 0); // Tolak kalau requestnya ga pas
    }
  }
}

void MulaiHandshake(String timestamp) {
  // Pembangkitan nonce
  byte nonce[16];
  esp_fill_random(nonce, sizeof(nonce));

  Serial.print("NONCE:");
  for (int i = 0; i < 16; i++) {
    if (nonce[i] < 16) Serial.print("0");
    Serial.print(nonce[i], HEX);
  }
  Serial.println();

  // Tunggu respons dari komputer
  long startTime = millis();
  while (Serial.available() == 0) {
    if (millis() - startTime > 5000) {
      Serial.println("TIMEOUT!");
      setLedColor(255, 0, 0);
      return;
    }
  }

  //baca respons dari Python
  String response = Serial.readStringUntil('\n');
  response.trim();

  //proses dekrip
  static byte ct_with_tag[MAX_CIPHER_LEN + 16];
  static byte decrypted_text[MAX_CIPHER_LEN + 1];

  //hitung panjang ciphertext
  int totalLen  = response.length() / 2;
  int cipherLen = totalLen - 16;

  if (cipherLen > MAX_CIPHER_LEN || cipherLen <= 0) {
    Serial.println("Payload Overload!");
    flashRed();
    return;}

  hexStringToBytes(response, ct_with_tag, totalLen);

  // AAD = timestamp
  const byte* aad_ptr = (const byte*)timestamp.c_str();
  size_t aad_len      = timestamp.length();

  unsigned long long decrypted_len = 0;

  int ret = crypto_aead_decrypt(
    decrypted_text, &decrypted_len,
    NULL,
    ct_with_tag, (unsigned long long)(cipherLen + 16),
    aad_ptr, (unsigned long long)aad_len,
    nonce,
    key
  );

  // Validasi tag & buat keputusan
  if (ret != 0) {
    memset(decrypted_text, 0, sizeof(decrypted_text));
    logActivity("Unknown", timestamp, "INVALID TAG!");
    setLedColor(255, 0, 0);
    Serial.println("GAGAL, Invalid Tag");
    return;
  }

  decrypted_text[decrypted_len] = '\0';

  // Jika tag valid, pisahkan payload
  String payload = String((char*)decrypted_text);
  memset(decrypted_text, 0, sizeof(decrypted_text));

  int pemisah = payload.indexOf('|');
  if (pemisah == -1) {
    logActivity("UNKNOWN_PC", timestamp, "FORMAT PAYLOAD RUSAK");
    setLedColor(255, 0, 0);
    Serial.println("GAGAL, Format Payload Rusak");
    return;
  }

  String perintah = payload.substring(0, pemisah);
  String data_sn  = payload.substring(pemisah + 1);

//ini buat debug
  //Serial.println("Perintah Diekstrak: " + perintah);
  //Serial.println("Data Diekstrak  : " + data_sn);

  // Eksekusi perintah user
  //BukaJalurData
  if (perintah == "A") {
    prosesBukaJalur(data_sn, timestamp);
  } //AksesWhitelist
  else if (perintah == "B") {
    bacaWhitelist();
  } //TambahWhitelist
  else if (perintah == "C") {
    tambahWhitelist(data_sn, timestamp);
  } //HapusWhitelist 
  else if (perintah == "D") {
    hapusWhitelist(data_sn, timestamp);
  } //AksesLogSDBlocker 
  else if (perintah == "E") {
    printLog();
  } //UpdateKunci
  else if (perintah == "F") {
    perbaruiKunciNVS(data_sn, timestamp);
  } 
  else {
    Serial.println("GAGAL, Permintaan Tidak Dikenal");
    flashRed();
  }

  if (digitalRead(SWITCH_PIN) == LOW) setLedColor(255, 0, 0);
}

// MANAJEMEN LittleFS
void prosesBukaJalur(String sn, String ts) {
  bool match = false;
  File file = LittleFS.open("/whitelist.txt", FILE_READ);

  if (file) {
    while (file.available()) {
      String savedSN = file.readStringUntil('\n');
      savedSN.trim();
      if (savedSN == sn) {
        match = true;
        break;
      }
    }
    file.close();
  }

  if (match) {
    logActivity(sn, ts, "Akses Diberikan");
    Serial.println("SUKSES, Jalur Data Dibuka");
    Serial.flush();

    setLedColor(0, 255, 0);
    digitalWrite(SWITCH_PIN, HIGH); // Buka Jalur Data FSUSB42

    while (true) delay(1000); // Kunci state di posisi terbuka selama sesi berlangsung
  } else {
    logActivity(sn, ts, "Ditolak, Perangkat Tidak Terdaftar");
    setLedColor(255, 0, 0);
    Serial.println("GAGAL, Perangkat Tidak Terdaftar di Whitelist");
  }
}

void bacaWhitelist() {
  File file = LittleFS.open("/whitelist.txt", FILE_READ);
  if (!file) {
    Serial.println("Whitelist Kosong, belum ada perangkat terdaftar.");
    return;
  }

  Serial.println("=== START WHITELIST ===");
  while (file.available()) {
    Serial.write(file.read());
  }
  file.close();
  Serial.println("=== END WHITELIST ===");

  flashYellow();
}

void tambahWhitelist(String sn, String ts) {
  File readFile = LittleFS.open("/whitelist.txt", FILE_READ);
  if (readFile) {
    while (readFile.available()) {
      String savedSN = readFile.readStringUntil('\n');
      savedSN.trim();
      if (savedSN == sn) {
        Serial.println("GAGAL, Serial Number sudah Terdaftar");
        readFile.close();
        flashRed();
        return;
      }
    }
    readFile.close();
  }

// Tulis ke baris baru
  File writeFile = LittleFS.open("/whitelist.txt", FILE_APPEND);
  if (writeFile) {
    writeFile.println(sn);
    writeFile.close();
    Serial.println("SUKSES: Whitelist Baru Ditambahkan");
    logActivity(sn, ts, "Menambahkan Whitelist");
    flashYellow();

  } else {
    Serial.println("GAGAL, Terdapat kesalahan dalam penambahan whitelist");
    flashRed();
  }
}

void hapusWhitelist(String sn, String ts) {
  if (!LittleFS.exists("/whitelist.txt")) {
    Serial.println("GAGAL, Whitelist Kosong");
    flashRed();
    return;
  }

  File readFile = LittleFS.open("/whitelist.txt", FILE_READ);
  File tempFile = LittleFS.open("/temp.txt", FILE_WRITE);
  bool found = false;

  while (readFile.available()) {
    String savedSN = readFile.readStringUntil('\n');
    savedSN.trim();

// copy semua SN ke file temp, KECUALI SN target yang mau dihapus
    if (savedSN == sn) {
      found = true;
    } else if (savedSN.length() > 0) {
      tempFile.println(savedSN);
    }
  }

  readFile.close();
  tempFile.close();

  if (found) {
    LittleFS.remove("/whitelist.txt");
    LittleFS.rename("/temp.txt", "/whitelist.txt");

    Serial.println("SUKSES: Whitelist Berhasil Dihapus");
    logActivity(sn, ts, "Menghapus Whitelist");
    flashYellow();
  } else {
    LittleFS.remove("/temp.txt");
    Serial.println("GAGAL, Serial Number Tidak Ditemukan");
    flashRed();
  }
}

void logActivity(String sn, String ts, String status) {
  if (LittleFS.exists("/log.txt")) {
    File checkFile = LittleFS.open("/log.txt", FILE_READ);
    size_t currentSize = checkFile.size();
    checkFile.close();

    if (currentSize >= MAX_LOG_SIZE) {
      Serial.println("LOG_ROTATION: Menggeser file ke backup...");
      if (LittleFS.exists("/log_backup.txt")) LittleFS.remove("/log_backup.txt");
      LittleFS.rename("/log.txt", "/log_backup.txt");
    }
  }

  File file = LittleFS.open("/log.txt", FILE_APPEND);
  if (file) {
    file.printf("%s | %s | %s\n", sn.c_str(), ts.c_str(), status.c_str());
    file.close();
  }
}

void printLog() {
  Serial.println("=== START LOG ===");

  //Cek dan cetak log lama (jika sudah pernah rotasi)
  if (LittleFS.exists("/log_backup.txt")) {
    File backup = LittleFS.open("/log_backup.txt", FILE_READ);
    if (backup) {
      while (backup.available()) Serial.write(backup.read());
      backup.close();
    }
  }

//Cek dan cetak log terbaru
  File file = LittleFS.open("/log.txt", FILE_READ);
  if (file) {
    while (file.available()) Serial.write(file.read());
    file.close();
  } else if (!LittleFS.exists("/log_backup.txt")) {
    Serial.println("LOG Kosong, Belum ada aktivitas.");
  }

  Serial.println("=== END LOG ===");
  setLedColor(255, 255, 0); delay(3000); setLedColor(255, 0, 0);
}

void perbaruiKunciNVS(String newKeyHex, String ts) {
  // Ascon-AEAD128 = kunci 16 byte = 32 karakter hex
  if (newKeyHex.length() != 32) {
    Serial.println("GAGAL, Format Kunci Baru Salah (harus 32 karakter hex / 16 byte)");
    flashRed();
    return;
  }

  byte newKey[16];
  hexStringToBytes(newKeyHex, newKey, 16);

// Tulis kunci baru ke NVS
  size_t written = preferences.putBytes("master_key", newKey, 16);

  if (written == 16) {
    Serial.println("SUKSES, Master Key Berhasil Diperbarui di Hardware!");
    logActivity("SYSTEM", ts, "Perbarui Master Key");

    memcpy(key, newKey, 16); // Update kunci di RAM agar tidak perlu restart

    flashGreen();
  } else {
    Serial.println("GAGAL, Memori NVS Error");
    flashRed();
  }
}

// --- FUNGSI BANTUAN SISTEM ---
void setLedColor(int r, int g, int b) {
  pixels.setPixelColor(0, pixels.Color(r, g, b));
  pixels.show();
}

void flashRed() {
  for (int i = 0; i < 3; i++) {
    setLedColor(255, 0, 0); delay(100);
    setLedColor(0, 0, 0);   delay(100);
  }
}
void flashYellow() {
  for(int i=0; i<3; i++) {
    setLedColor(255, 255, 0); delay(200); // Kuning nyala
    setLedColor(0, 0, 0); delay(200);     // Mati
  }
}

void flashGreen() {
  for(int i=0; i<3; i++) {
    setLedColor(0, 255, 0); delay(200); // Hijau nyala
    setLedColor(0, 0, 0); delay(200);   // Mati
  }
}

void hexStringToBytes(String hex, byte* bytes, int len) {
  const char* str = hex.c_str(); 
  char buf[3] = {0, 0, 0};
  for (int i = 0; i < len; i++) {
    buf[0] = str[i*2];
    buf[1] = str[i*2+1];
    bytes[i] = (byte)strtol(buf, NULL, 16);
  }
}
