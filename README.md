# DUMMY NETWORKING TOOLS

Toolkit Python sederhana untuk diagnosis jaringan dan pemeriksaan keamanan dasar. Menu berjalan di terminal, tanpa framework dan tanpa library pihak ketiga.

## Fitur

- Cek koneksi internet (TCP dan DNS)
- Informasi hostname dan IP lokal
- Cek IP publik
- DNS lookup IPv4/IPv6
- Ping dan traceroute
- Pemeriksaan HTTP status dan header
- Informasi sertifikat TLS
- **Pentest Lab:** TCP port checker dengan batas jumlah port, audit port localhost, HTTP security headers, TLS check, dan HTTP `OPTIONS`
- Ekspor hasil ke file JSON

## Kebutuhan

- Python 3.10 atau lebih baru
- Koneksi internet hanya diperlukan untuk fitur yang menghubungi jaringan luar
- `ping` tersedia di sistem untuk fitur ping
- `traceroute` (Linux/macOS) atau `tracert` (Windows) untuk traceroute

Tidak perlu `pip install` apa pun.

## Menjalankan

Linux, macOS, atau Android dengan lingkungan Python:

```bash
python3 dummy.py
```

Windows:

```powershell
py dummy.py
```

## Pemakaian

1. Jalankan program.
2. Pilih nomor menu.
3. Ikuti petunjuk yang tampil di terminal.
4. Pilih **10. Ekspor laporan JSON** untuk menyimpan hasil pemeriksaan yang sudah dijalankan.

Laporan default bernama `dummy-report.json` dan tersimpan di direktori kerja saat ini.

## Catatan Pentest

Gunakan fitur audit hanya pada perangkat, server, atau domain milik sendiri atau yang secara jelas memberi izin pengujian. Port checker dibatasi maksimal 20 port untuk input manual per proses. Pemeriksaan ini bersifat ringan dan bukan pengganti audit keamanan profesional.

Hasil seperti port `closed/timeout`, header keamanan yang tidak ada, atau metode HTTP yang tidak diinformasikan bukan bukti tunggal bahwa sebuah sistem rentan. Hasil juga dapat dipengaruhi firewall, proxy, dan konfigurasi server.

## Batasan

- Tidak ada exploit, brute force, atau uji beban.
- IP publik diperoleh melalui layanan pihak ketiga `api.ipify.org`.
- Traceroute dan ping bergantung pada ketersediaan utilitas sistem dan kebijakan jaringan.
- Pemeriksaan HTTP memakai request sederhana; sebagian situs mungkin menolak `HEAD` atau `OPTIONS`.

## Lisensi

MIT — lihat file `LICENSE`.
