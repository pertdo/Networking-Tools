#!/usr/bin/env python3
"""DUMMY - a small, dependency-free network diagnostics toolkit."""

from __future__ import annotations

import json
import os
import platform
import re
import shutil
import socket
import ssl
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime
from typing import Any

APP_NAME = "DUMMY"
VERSION = "1.1.0"
REPORT_FILE = "dummy-report.json"
USER_AGENT = f"DUMMY/{VERSION} (network diagnostics)"

# Results are kept for the current run and can be exported as JSON.
RESULTS: list[dict[str, Any]] = []

COMMON_PORTS = [
    (21, "FTP"), (22, "SSH"), (25, "SMTP"), (53, "DNS"),
    (80, "HTTP"), (110, "POP3"), (143, "IMAP"), (443, "HTTPS"),
    (445, "SMB"), (3306, "MySQL"), (5432, "PostgreSQL"),
    (6379, "Redis"), (8080, "HTTP-alt"), (8443, "HTTPS-alt"),
]
SECURITY_HEADERS = [
    ("Strict-Transport-Security", "HSTS"),
    ("Content-Security-Policy", "CSP"),
    ("X-Content-Type-Options", "MIME protection"),
    ("X-Frame-Options", "Clickjacking protection"),
    ("Referrer-Policy", "Referrer policy"),
    ("Permissions-Policy", "Browser permissions"),
]


def now() -> str:
    return datetime.now().astimezone().isoformat(timespec="seconds")


def record(tool: str, target: str, status: str, details: dict[str, Any] | None = None) -> None:
    RESULTS.append({
        "time": now(),
        "tool": tool,
        "target": target,
        "status": status,
        "details": details or {},
    })


def line(char: str = "-", width: int = 54) -> None:
    print(char * width)


def header() -> None:
    print("\n" + "=" * 54)
    print(f"  {APP_NAME}  |  Network Toolkit  v{VERSION}")
    print("=" * 54)


def pause() -> None:
    try:
        input("\nEnter untuk kembali...")
    except (EOFError, KeyboardInterrupt):
        print()


def ask(prompt: str) -> str:
    try:
        return input(prompt).strip()
    except EOFError:
        return ""


def valid_host(value: str) -> bool:
    """Accept a plain IP address or hostname, not URLs/paths/options."""
    value = value.strip()
    if not value or len(value) > 253 or value.startswith("-"):
        return False
    if any(ch.isspace() for ch in value) or any(ch in value for ch in "/\\@?#"):
        return False
    try:
        socket.getaddrinfo(value, None)
        return True
    except (socket.gaierror, UnicodeError, OSError):
        # A DNS failure shouldn't make syntactically valid hostnames appear valid.
        if ":" in value:
            try:
                socket.inet_pton(socket.AF_INET6, value)
                return True
            except OSError:
                return False
        if re.fullmatch(r"\d{1,3}(?:\.\d{1,3}){3}", value):
            try:
                socket.inet_pton(socket.AF_INET, value)
                return True
            except OSError:
                return False
        labels = value.rstrip(".").split(".")
        if not labels or any(
            not label or len(label) > 63
            or not re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?", label)
            for label in labels
        ):
            return False
        return True


def ask_host(prompt: str = "Host/domain: ") -> str | None:
    host = ask(prompt)
    if not valid_host(host):
        print("Host tidak valid atau formatnya salah.")
        return None
    return host


def parse_url(raw: str, https_only: bool = False) -> str | None:
    raw = raw.strip()
    if not raw:
        print("URL tidak boleh kosong.")
        return None
    if "://" not in raw:
        raw = ("https://" if https_only else "https://") + raw
    parsed = urllib.parse.urlparse(raw)
    if (
        parsed.scheme not in (("https",) if https_only else ("http", "https"))
        or not parsed.hostname
        or not valid_host(parsed.hostname)
        or parsed.username is not None
        or parsed.password is not None
    ):
        print("URL tidak valid. Gunakan URL http:// atau https:// yang benar.")
        return None
    return raw


def run_system_command(args: list[str], timeout: int = 20) -> tuple[int | None, str]:
    try:
        completed = subprocess.run(
            args, capture_output=True, text=True, timeout=timeout, check=False
        )
        output = (completed.stdout or "") + (completed.stderr or "")
        return completed.returncode, output.strip()
    except FileNotFoundError:
        return None, f"Perintah '{args[0]}' tidak ditemukan di sistem."
    except subprocess.TimeoutExpired:
        return None, "Perintah melewati batas waktu dan dihentikan."
    except OSError as exc:
        return None, f"Gagal menjalankan perintah: {exc}"


def internet_check() -> None:
    print("\n[ CEK KONEKSI ]")
    results: dict[str, Any] = {}
    try:
        start = time.perf_counter()
        with socket.create_connection(("1.1.1.1", 443), timeout=4):
            ms = round((time.perf_counter() - start) * 1000, 1)
        print(f"TCP 1.1.1.1:443 : OK ({ms} ms)")
        results["tcp_1.1.1.1_443"] = {"ok": True, "latency_ms": ms}
    except OSError as exc:
        print(f"TCP 1.1.1.1:443 : GAGAL ({exc})")
        results["tcp_1.1.1.1_443"] = {"ok": False, "error": str(exc)}

    try:
        start = time.perf_counter()
        with socket.create_connection(("example.com", 443), timeout=4):
            ms = round((time.perf_counter() - start) * 1000, 1)
        print(f"DNS + TCP example.com:443 : OK ({ms} ms)")
        results["dns_tcp_example.com_443"] = {"ok": True, "latency_ms": ms}
    except OSError as exc:
        print(f"DNS + TCP example.com:443 : GAGAL ({exc})")
        results["dns_tcp_example.com_443"] = {"ok": False, "error": str(exc)}
    record("Connectivity check", "internet", "completed", results)


def local_info() -> None:
    print("\n[ INFO JARINGAN LOKAL ]")
    hostname = socket.gethostname()
    print(f"Hostname : {hostname}")
    print(f"OS       : {platform.system()} {platform.release()}")
    print(f"Arsitektur: {platform.machine()}")
    addresses: set[str] = set()
    try:
        for item in socket.getaddrinfo(hostname, None):
            ip = item[4][0]
            if not ip.startswith("127.") and ip != "::1":
                addresses.add(ip)
    except OSError:
        pass
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.connect(("1.1.1.1", 80))
            addresses.add(sock.getsockname()[0])
    except OSError:
        pass
    if addresses:
        for address in sorted(addresses):
            print(f"IP lokal : {address}")
    else:
        print("IP lokal : tidak berhasil dideteksi")
    record("Local network info", hostname, "completed", {"addresses": sorted(addresses)})


def public_ip() -> None:
    print("\n[ IP PUBLIK ]")
    endpoint = "https://api.ipify.org"
    try:
        req = urllib.request.Request(endpoint, headers={"User-Agent": USER_AGENT})
        with urllib.request.urlopen(req, timeout=6) as response:
            address = response.read(128).decode("utf-8", errors="replace").strip()
        # Validate the response so an unexpected page isn't printed as an IP.
        socket.inet_pton(socket.AF_INET if "." in address else socket.AF_INET6, address)
        print(f"IP publik: {address}")
        record("Public IP", endpoint, "success", {"ip": address})
    except Exception as exc:
        print(f"Gagal mengambil IP publik: {exc}")
        record("Public IP", endpoint, "failed", {"error": str(exc)})


def dns_lookup() -> None:
    print("\n[ DNS LOOKUP ]")
    host = ask_host()
    if not host:
        return
    try:
        rows = socket.getaddrinfo(host, None)
        items = sorted({(socket.AddressFamily(row[0]).name, row[4][0]) for row in rows})
        for family, address in items:
            print(f"{family.replace('AF_', ''):5}  {address}")
        record("DNS lookup", host, "success", {"results": [{"family": f, "address": a} for f, a in items]})
    except (socket.gaierror, OSError) as exc:
        print(f"Lookup gagal: {exc}")
        record("DNS lookup", host, "failed", {"error": str(exc)})


def ping_check() -> None:
    print("\n[ PING ]")
    host = ask_host()
    if not host:
        return
    raw = ask("Jumlah ping (1-10, default 4): ") or "4"
    try:
        count = int(raw)
        if not 1 <= count <= 10:
            raise ValueError
    except ValueError:
        print("Masukkan angka dari 1 sampai 10.")
        return
    if os.name == "nt":
        args = ["ping", "-n", str(count), "-w", "2000", host]
    elif platform.system() == "Darwin":
        args = ["ping", "-c", str(count), "-W", "2000", host]
    else:
        args = ["ping", "-c", str(count), "-W", "2", host]
    code, output = run_system_command(args, timeout=count * 3 + 5)
    print(output or "Tidak ada output.")
    record("Ping", host, "success" if code == 0 else "failed", {"count": count, "return_code": code, "output": output})


def traceroute_check() -> None:
    print("\n[ TRACEROUTE ]")
    host = ask_host()
    if not host:
        return
    if os.name == "nt":
        command = "tracert"
        args = [command, "-d", "-h", "12", "-w", "1000", host]
    else:
        command = "traceroute" if shutil.which("traceroute") else "tracepath"
        if not shutil.which(command):
            print("Traceroute tidak tersedia. Linux: install paket 'traceroute'.")
            return
        args = [command, "-n", "-m", "12", host] if command == "traceroute" else [command, host]
    code, output = run_system_command(args, timeout=25)
    print(output or "Tidak ada output.")
    record("Traceroute", host, "success" if code == 0 else "failed", {"return_code": code, "output": output})


def get_http_response(url: str, method: str = "HEAD"):
    req = urllib.request.Request(url, method=method, headers={"User-Agent": USER_AGENT})
    return urllib.request.urlopen(req, timeout=8)


def http_check(headers_only: bool = False) -> None:
    label = "SECURITY HEADERS" if headers_only else "HTTP CHECK"
    print(f"\n[ {label} ]")
    raw = ask("URL/domain: ")
    url = parse_url(raw, https_only=headers_only)
    if not url:
        return
    parsed = urllib.parse.urlparse(url)
    details: dict[str, Any] = {}
    try:
        try:
            response = get_http_response(url, "HEAD")
        except urllib.error.HTTPError as exc:
            # Some sites reject HEAD; the status and headers may still be useful.
            if exc.code in (400, 403, 405, 501):
                response = get_http_response(url, "GET")
            else:
                raise
        with response:
            headers = response.headers
            details = {
                "status_code": response.status,
                "final_url": response.geturl(),
                "server": headers.get("Server"),
                "content_type": headers.get("Content-Type"),
                "security_headers": {name: headers.get(name) for name, _ in SECURITY_HEADERS},
            }
            print(f"Status       : HTTP {response.status}")
            print(f"Final URL    : {response.geturl()}")
            print(f"Server       : {headers.get('Server', 'tidak diinformasikan')}")
            print(f"Content-Type : {headers.get('Content-Type', 'tidak diinformasikan')}")
            if headers_only:
                print("\nHeader keamanan:")
                for name, friendly in SECURITY_HEADERS:
                    value = headers.get(name)
                    mark = "ADA" if value else "TIDAK ADA"
                    print(f"[{mark:8}] {friendly}: {value or name}")
                print("Catatan: header yang hilang bukan bukti tunggal bahwa situs rentan.")
        record(label, parsed.hostname or url, "success", details)
    except urllib.error.HTTPError as exc:
        print(f"Server merespons HTTP {exc.code}: {exc.reason}")
        record(label, parsed.hostname or url, "http_error", {"status_code": exc.code, "error": str(exc)})
    except Exception as exc:
        print(f"Request gagal: {exc}")
        record(label, parsed.hostname or url, "failed", {"error": str(exc)})


def tls_check() -> None:
    print("\n[ TLS CERTIFICATE ]")
    host = ask_host()
    if not host:
        return
    try:
        context = ssl.create_default_context()
        start = time.perf_counter()
        with socket.create_connection((host, 443), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=host) as tls:
                cert = tls.getpeercert()
                cipher = tls.cipher()
                details = {
                    "tls_version": tls.version(),
                    "cipher": cipher[0] if cipher else None,
                    "expires": cert.get("notAfter"),
                    "issuer": cert.get("issuer"),
                    "latency_ms": round((time.perf_counter() - start) * 1000, 1),
                }
        print(f"TLS version : {details['tls_version']}")
        print(f"Cipher      : {details['cipher']}")
        print(f"Certificate : {details['expires'] or 'tanggal tidak tersedia'}")
        print(f"Handshake   : {details['latency_ms']} ms")
        print("Validasi sertifikat: berhasil")
        record("TLS certificate", host, "success", details)
    except Exception as exc:
        print(f"TLS check gagal: {exc}")
        record("TLS certificate", host, "failed", {"error": str(exc)})


def port_check(local_only: bool = False) -> None:
    title = "LOCAL PORT AUDIT" if local_only else "TCP PORT CHECKER"
    print(f"\n[ {title} ]")
    if local_only:
        host = "127.0.0.1"
        ports = [port for port, _ in COMMON_PORTS]
    else:
        print("Gunakan hanya host yang kamu miliki atau punya izin untuk diuji.")
        host = ask_host("Target host: ")
        if not host:
            return
        raw = ask("Port (misal 22,80,443) atau 'common': ").lower()
        if raw == "common":
            ports = [port for port, _ in COMMON_PORTS]
        else:
            try:
                parts = [part.strip() for part in raw.split(",") if part.strip()]
                ports = sorted(set(int(part) for part in parts))
                if not ports or len(ports) > 20 or any(p < 1 or p > 65535 for p in ports):
                    raise ValueError
            except ValueError:
                print("Port tidak valid. Masukkan 1-20 port, antara 1 dan 65535.")
                return
        confirm = ask(f"Konfirmasi pemeriksaan ringan pada {host} ({len(ports)} port)? ketik YA: ")
        if confirm != "YA":
            print("Dibatalkan.")
            return

    if local_only:
        print("Target dibatasi ke perangkat sendiri (127.0.0.1).")
    labels = dict(COMMON_PORTS)
    scanned: list[dict[str, Any]] = []
    for port in ports:
        try:
            start = time.perf_counter()
            with socket.create_connection((host, port), timeout=1.0):
                ms = round((time.perf_counter() - start) * 1000, 1)
            state = "open"
            print(f"[OPEN]   {port:5}/tcp  {labels.get(port, ''):10} {ms} ms")
        except socket.timeout:
            state = "filtered/timeout"
            print(f"[TIMEOUT] {port:5}/tcp  {labels.get(port, '')}")
        except ConnectionRefusedError:
            state = "closed"
            print(f"[CLOSED] {port:5}/tcp  {labels.get(port, '')}")
        except OSError as exc:
            state = "unavailable"
            print(f"[ERROR]  {port:5}/tcp  {exc}")
        scanned.append({"port": port, "state": state})
    record(title, host, "completed", {"ports": scanned})


def http_methods_check() -> None:
    print("\n[ HTTP OPTIONS CHECK ]")
    raw = ask("URL/domain (HTTPS): ")
    url = parse_url(raw, https_only=True)
    if not url:
        return
    parsed = urllib.parse.urlparse(url)
    try:
        response = get_http_response(url, "OPTIONS")
        with response:
            status = response.status
            allow = response.headers.get("Allow", "tidak diinformasikan")
    except urllib.error.HTTPError as exc:
        status = exc.code
        allow = exc.headers.get("Allow", "tidak diinformasikan")
    except Exception as exc:
        print(f"Pemeriksaan gagal: {exc}")
        record("HTTP OPTIONS", parsed.hostname or url, "failed", {"error": str(exc)})
        return
    print(f"Status HTTP : {status}")
    print(f"Allow       : {allow}")
    print("Catatan: respons OPTIONS bukan audit lengkap atas semua metode.")
    record("HTTP OPTIONS", parsed.hostname or url, "completed", {"status_code": status, "allow": allow})


def export_report() -> None:
    filename = ask(f"Nama file [{REPORT_FILE}]: ") or REPORT_FILE
    if not filename.lower().endswith(".json"):
        filename += ".json"
    if os.path.basename(filename) != filename or filename in (".", ".."):
        print("Gunakan nama file saja, tanpa folder/path.")
        return
    payload = {
        "tool": APP_NAME,
        "version": VERSION,
        "generated_at": now(),
        "record_count": len(RESULTS),
        "results": RESULTS,
    }
    try:
        with open(filename, "w", encoding="utf-8") as file:
            json.dump(payload, file, indent=2, ensure_ascii=False)
        print(f"Laporan tersimpan: {os.path.abspath(filename)}")
        print(f"Jumlah hasil: {len(RESULTS)}")
    except OSError as exc:
        print(f"Gagal menyimpan laporan: {exc}")


def pentest_menu() -> None:
    while True:
        print("\n[ PENTEST LAB ]")
        print("Pemeriksaan ringan untuk sistem sendiri / target berizin.")
        line()
        print(" 1. TCP port checker")
        print(" 2. Audit port localhost")
        print(" 3. HTTP security headers")
        print(" 4. TLS certificate check")
        print(" 5. HTTP OPTIONS check")
        print(" 0. Kembali")
        line()
        choice = ask("dummy/pentest> ")
        if choice == "0":
            return
        actions = {
            "1": port_check,
            "2": lambda: port_check(local_only=True),
            "3": lambda: http_check(headers_only=True),
            "4": tls_check,
            "5": http_methods_check,
        }
        action = actions.get(choice)
        if action:
            try:
                action()
            except KeyboardInterrupt:
                print("\nPemeriksaan dibatalkan.")
            pause()
        else:
            print("Pilihan tidak dikenal.")


def main() -> None:
    actions = {
        "1": ("Cek koneksi internet", internet_check),
        "2": ("Info jaringan lokal", local_info),
        "3": ("Cek IP publik", public_ip),
        "4": ("DNS lookup", dns_lookup),
        "5": ("Ping / latency", ping_check),
        "6": ("Traceroute", traceroute_check),
        "7": ("HTTP status", lambda: http_check(headers_only=False)),
        "8": ("TLS certificate", tls_check),
        "9": ("Pentest Lab", pentest_menu),
        "10": ("Ekspor laporan JSON", export_report),
    }
    while True:
        header()
        for key, (label, _) in actions.items():
            print(f" {key:>2}. {label}")
        print("  0. Keluar")
        line()
        choice = ask("dummy> ")
        if choice == "0":
            print("DUMMY ditutup.")
            return
        selected = actions.get(choice)
        if not selected:
            print("Pilihan tidak dikenal. Coba lagi.")
            continue
        try:
            selected[1]()
        except KeyboardInterrupt:
            print("\nOperasi dibatalkan.")
        except Exception as exc:
            print(f"Terjadi error: {exc}")
        pause()


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nDUMMY dihentikan.")
