#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
CLEAN_IP_FINDER [Version 2.0] – Simple, Fast, Reliable IP Scanner
==================================================================
Made with ❤️ by Mobin

Simple Features:
    - Real TCP ping (latency)
    - Optional HTTP, TLS, WebSocket tests
    - Full result classification (internal states 0-12)
    - Works on Termux (Android), Windows, Linux
    - Results grouped by port, sorted by latency
    - Crash‑resistant (saves every result immediately)
    - Shows your local ISP once in the header (robust with retries & fallback)
    - Memory‑optimised for large scans (no huge sets)
    - HTTP field always shown when HTTP test is enabled

Algorithm:
    1. Parse target as generator
    2. Producer pushes tasks to connect queue
    3. Connect workers: raw TCP connect, measure TCP latency
    4. Scan workers:
        - TLS handshake (if enabled & HTTPS)
        - HTTP request (GET /path) with custom Host header
        - WebSocket upgrade (if enabled) with separate WS Host
        - Collect latencies: TCP, TLS, HTTP TTFB
    5. Determine final state based on successes/timeouts (12 states)
    6. Logger writes raw results to two files:
        - raw_results.txt (append, flush) → survives crash
        - temp_results.txt (temporary)
    7. After scan, reorganize temp_results.txt into final grouped results.txt
    8. Keep raw_results.txt as a backup

How to use (Termux / Windows):
    Termux: pkg update && pkg install python; pip install requests
    Windows: Install Python 3.7+, then pip install requests
    Then run: python CLEAN_IP_FINDER.py

#Free_Iran
"""

import atexit
import base64
import contextlib
import ipaddress
import os
import re
import socket
import ssl
import sys
import threading
import time
import errno
from enum import IntEnum
from queue import Queue, Empty
from collections import defaultdict
from urllib.parse import urlparse
from typing import Iterator, List, Optional, Tuple, Dict, Any
import requests.exceptions

# ---------------------------- Welcome Banner ---------------------------
print("""
╔══════════════════════════════════════════════════════════════╗
║     CLEAN_IP_FINDER [Version 2.0] – Simple, Fast, Reliable   ║
║              Made with ❤️ by Mobin - #Free_Iran               ║
╚══════════════════════════════════════════════════════════════╝
""")
print("Press Enter to start scanning...")
input()

# ---------------------------- Constants ---------------------------------
# Updated HTTP ports (standard + Cloudflare + extra)
HTTP_PORTS = {80, 591, 8080, 8008, 8880, 2052, 2082, 2086, 2095, 9080, 9999, 60001}
# Updated HTTPS/TLS ports (standard + Cloudflare + extra)
HTTPS_PORTS = {443, 832, 853, 2053, 2083, 2087, 2096, 8443, 9443, 10443}
ALL_L7_PORTS = HTTP_PORTS | HTTPS_PORTS

HTTP_RECV_MAX_BYTES = 8192
PRINT_INTERVAL = 10
MAX_IPV6_PREFIX = 48
MAX_IPV6_TOTAL_IPS = 1_000_000
DNS_TIMEOUT_SEC = 5
MAX_RETRY_EMFILE = 3

CONNECT_QUEUE_SIZE = 5000
SCAN_QUEUE_SIZE = 5000
RESULT_QUEUE_SIZE = 10000

SCRIPT_DIR = os.path.dirname(os.path.realpath(__file__))
LOG_FILE = os.path.join(SCRIPT_DIR, "scan_log.txt")
RESULTS_FILE = os.path.join(SCRIPT_DIR, "results.txt")
RAW_RESULTS_FILE = os.path.join(SCRIPT_DIR, "raw_results.txt")
TEMP_FILE = os.path.join(SCRIPT_DIR, "temp_results.txt")

_print_lock = threading.Lock()
_log_lock = threading.Lock()
_file_lock = threading.Lock()

# ---------------------------- Scan State (IntEnum) ---------------------
class ScanState(IntEnum):
    UNREACHABLE = 0
    TCP_OK = 1               # TCP only, no L7 test performed
    HTTP_OK = 2              # HTTP success (no TLS, no WS)
    HTTP_TIMEOUT = 3         # TCP ok, HTTP request timed out
    HTTP_FAIL = 4            # TCP ok, HTTP connection closed without any data (or no HTTP sent)
    TCP_HTTP = 5             # TCP + HTTP success
    TLS_OK = 6               # TLS success (handshake only, no HTTP/WS)
    TLS_TIMEOUT = 7          # TCP + TLS handshake timeout
    TLS_FAIL = 8             # TCP + TLS handshake error
    TCP_TLS = 9              # TCP + TLS success (no HTTP/WS)
    TCP_HTTP_TLS = 10        # TCP + HTTP + TLS success
    WS = 11                  # WebSocket (no TLS)
    WS_TLS = 12              # WebSocket over TLS

# ---------------------------- Thread‑local SSL context -----------------
_thread_local = threading.local()
def get_ssl_ctx():
    if not hasattr(_thread_local, "ctx"):
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        ctx.set_alpn_protocols(["http/1.1"])
        _thread_local.ctx = ctx
    return _thread_local.ctx

# ---------------------------- Logging ----------------------------------
def safe_print(*args, **kwargs):
    with _print_lock:
        print(*args, **kwargs)

_log_handle = None
def open_log():
    global _log_handle
    _log_handle = open(LOG_FILE, "w", encoding="utf-8")
def close_log():
    global _log_handle
    if _log_handle:
        _log_handle.flush()
        _log_handle.close()
        _log_handle = None
def log_result(ip: str, port: int, tcp_lat: Optional[float], tls_lat: Optional[float],
               http_lat: Optional[float], state: ScanState) -> None:
    with _log_lock:
        if _log_handle:
            _log_handle.write(f"{ip}|{port}|{tcp_lat}|{tls_lat}|{http_lat}|{int(state)}\n")
            _log_handle.flush()

# ---------------------------- Local ISP (robust with retries & fallback) -------------------
def get_local_isp() -> str:
    for attempt in range(2):
        timeout = 8 if attempt == 0 else 5
        try:
            import requests
            r = requests.get("https://api.ip.sb/geoip", timeout=timeout)
            if r.status_code == 200:
                data = r.json()
                isp = data.get("isp")
                if isp and isp != "null":
                    return isp
        except Exception:
            pass
        if attempt < 1:
            time.sleep(1)
    for attempt in range(3):
        try:
            import requests
            r = requests.get("http://ipkit.ir/json", timeout=5)
            if r.status_code == 200:
                data = r.json()
                isp = data.get("asn_organization")
                if isp and isp != "null":
                    return isp
        except Exception:
            pass
        if attempt < 2:
            time.sleep(1)
    return "Unknown"

# ---------------------------- Dependency Check -------------------------
def check_dependencies():
    missing = []
    if sys.version_info < (3, 7):
        missing.append("Python >= 3.7")
    try:
        import requests
    except ImportError:
        missing.append("requests")
    if not missing:
        safe_print("[✓] All dependencies satisfied.")
        return True
    
    safe_print("[!] Missing dependencies:", ", ".join(missing))
    if sys.platform.startswith("linux") and "com.termux" in os.environ.get("PREFIX", ""):
        safe_print("\n[ Termux detected ]\nRun these commands:\n")
        for pkg in missing:
            if pkg == "requests":
                safe_print("    pip install requests")
            elif pkg == "Python >= 3.7":
                safe_print("    pkg install python")
        safe_print("\nThen restart the script.")
    elif sys.platform.startswith("win"):
        safe_print("\n[ Windows detected ]\nRun in Command Prompt as Administrator:\n")
        for pkg in missing:
            if pkg == "requests":
                safe_print(f"    pip install {pkg}")
            elif pkg == "Python >= 3.7":
                safe_print("    Download Python from python.org")
        safe_print("\nThen restart the script.")
    else:
        safe_print("\n[ Linux/macOS detected ]\nRun:\n")
        for pkg in missing:
            if pkg == "requests":
                safe_print(f"    pip3 install {pkg}")
            elif pkg == "Python >= 3.7":
                safe_print("    Use your package manager to upgrade Python")
        safe_print("\nThen restart the script.")
    return False

# ---------------------------- DNS with timeout -------------------------
def resolve_domain(domain: str, timeout: float) -> List[str]:
    from concurrent.futures import ThreadPoolExecutor, TimeoutError as FutureTimeout
    with ThreadPoolExecutor(max_workers=1) as ex:
        fut = ex.submit(socket.getaddrinfo, domain, None, socket.AF_UNSPEC, socket.SOCK_STREAM)
        try:
            result = fut.result(timeout=timeout)
        except (FutureTimeout, Exception):
            return []
    ips = []
    for ai in result:
        ip = ai[4][0]
        if ip not in ips:
            ips.append(ip)
    return ips

# ---------------------------- Helper for Host Header (fixed for IPv6) -------------------
def get_clean_host_header(target: str) -> str:
    try:
        if ":" in target and not target.startswith("[") and target.count(":") > 1:
            return f"[{target}]"
        parsed = urlparse(f"//{target}")
        host = parsed.hostname or target
        if ':' in host and not host.startswith('['):
            return f"[{host}]"
        return host
    except ValueError:
        return f"[{target}]" if ":" in target else target

# ---------------------------- Streaming IP iterators -------------------
def iter_ipv4_range(start_int: int, end_int: int) -> Iterator[str]:
    for i in range(start_int, end_int + 1):
        yield str(ipaddress.IPv4Address(i))

def iter_ipv6_range(start_int: int, end_int: int) -> Iterator[str]:
    total = end_int - start_int + 1
    if total > MAX_IPV6_TOTAL_IPS:
        safe_print(f"Refusing IPv6 range with {total} IPs (limit {MAX_IPV6_TOTAL_IPS})")
        return
    for i in range(start_int, end_int + 1):
        yield str(ipaddress.IPv6Address(i))

def parse_target_stream(target_str: str) -> Iterator[Tuple[str, Optional[str]]]:
    target_str = target_str.strip()
    if not target_str:
        return
    if '\n' in target_str:
        for line in target_str.split('\n'):
            line = line.strip()
            if line:
                yield from parse_target_stream(line)
        return
    if ',' in target_str and '/' not in target_str and '-' not in target_str:
        for part in target_str.split(','):
            part = part.strip()
            if part:
                yield from parse_target_stream(part)
        return
    if '/' in target_str:
        if ':' in target_str:
            try:
                net = ipaddress.ip_network(target_str, strict=False)
                if net.version == 6 and net.prefixlen < MAX_IPV6_PREFIX:
                    safe_print(f"Refusing IPv6 subnet {target_str} (prefix < {MAX_IPV6_PREFIX})")
                    return
                total = 1 << (128 - net.prefixlen) if net.version == 6 else net.num_addresses
                if total > MAX_IPV6_TOTAL_IPS:
                    safe_print(f"Refusing IPv6 subnet {target_str} with {total} IPs (limit {MAX_IPV6_TOTAL_IPS})")
                    return
                for ip in net.hosts():
                    yield str(ip), None
            except Exception as e:
                safe_print(f"IPv6 network error: {e}")
        else:
            try:
                net = ipaddress.ip_network(target_str, strict=False)
                for ip in net.hosts():
                    yield str(ip), None
            except Exception as e:
                safe_print(f"IPv4 CIDR error: {e}")
        return
    if '-' in target_str and '.' in target_str:
        parts = target_str.split('-')
        if len(parts) == 2:
            left, right = parts[0].strip(), parts[1].strip()
            try:
                ipaddress.IPv4Address(left)
                if '.' in right:
                    ipaddress.IPv4Address(right)
                    start = int(ipaddress.IPv4Address(left))
                    end = int(ipaddress.IPv4Address(right))
                    if (end - start + 1) > MAX_IPV6_TOTAL_IPS:
                        safe_print(f"IPv4 range too large, refusing")
                        return
                    for ip in iter_ipv4_range(start, end):
                        yield ip, None
                else:
                    base = left.rsplit('.', 1)[0]
                    start_oct = int(left.split('.')[-1])
                    end_oct = int(right)
                    if (end_oct - start_oct + 1) > 255:
                        safe_print(f"IPv4 abbreviated range too large, refusing")
                        return
                    for octet in range(start_oct, end_oct+1):
                        if 0 <= octet <= 255:
                            yield f"{base}.{octet}", None
                return
            except Exception:
                safe_print(f"Invalid IPv4 range {target_str}")
                return
    if '-' in target_str and ':' in target_str:
        parts = target_str.split('-')
        if len(parts) == 2:
            left, right = parts[0].strip(), parts[1].strip()
            try:
                start = int(ipaddress.IPv6Address(left))
                end = int(ipaddress.IPv6Address(right))
                if (end - start + 1) > MAX_IPV6_TOTAL_IPS:
                    safe_print(f"IPv6 range too large, refusing")
                    return
                for ip in iter_ipv6_range(start, end):
                    yield ip, None
            except Exception:
                safe_print(f"Invalid IPv6 range {target_str}")
        return
    nm = re.match(r'^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s+(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})$', target_str)
    if nm:
        try:
            net = ipaddress.IPv4Network(f"{nm.group(1)}/{nm.group(2)}", strict=False)
            for ip in net.hosts():
                yield str(ip), None
        except Exception as e:
            safe_print(f"Netmask error: {e}")
        return
    try:
        ipaddress.ip_address(target_str)
        yield target_str, None
        return
    except ValueError:
        pass
    if re.match(r'^[a-zA-Z0-9.-]+$', target_str):
        host = target_str
        ips = resolve_domain(host, DNS_TIMEOUT_SEC)
        for ip in ips:
            yield ip, host
        return
    safe_print(f"Unrecognized target format: {target_str}")

# ---------------------------- WebSocket helpers -------------------------
def generate_websocket_key():
    return base64.b64encode(os.urandom(16)).decode()
def compute_websocket_accept(key):
    import hashlib
    GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
    return base64.b64encode(hashlib.sha1((key + GUID).encode()).digest()).decode()
def parse_http_status(response: bytes, ws_key: Optional[str] = None, strict: bool = False):
    try:
        header_end = response.find(b"\r\n\r\n")
        if header_end == -1:
            header_end = response.find(b"\n\n")
            if header_end == -1:
                return None, None, None, False
        raw = response[:header_end].decode(errors="ignore")
        lines = raw.splitlines()
        if not lines:
            return None, None, None, False
        status_line = lines[0]
        parts = status_line.split()
        status_code = int(parts[1]) if len(parts)>=2 and parts[1].isdigit() else None
        lower = raw.lower()
        upgrade = "upgrade: websocket" in lower
        conn = "connection: upgrade" in lower
        if strict:
            if status_code != 101 or not (upgrade and conn):
                return status_line, status_code, raw, False
            for line in lines[1:]:
                if line.lower().startswith("sec-websocket-accept:"):
                    accept = line.split(":",1)[1].strip()
                    if accept and ws_key and accept == compute_websocket_accept(ws_key):
                        return status_line, status_code, raw, True
            return status_line, status_code, raw, False
        else:
            ws_ok = (status_code == 101) and upgrade and conn
            return status_line, status_code, raw, ws_ok
    except Exception:
        return None, None, None, False

# ---------------------------- Raw Connect (fixed FD leak) ------------------
def raw_connect(ip: str, port: int, timeout_sec: float):
    ip_obj = ipaddress.ip_address(ip)
    family = socket.AF_INET6 if ip_obj.version == 6 else socket.AF_INET
    sockaddr = (ip, port, 0, 0) if family == socket.AF_INET6 else (ip, port)
    sock = socket.socket(family, socket.SOCK_STREAM)
    sock.settimeout(timeout_sec)
    try:
        start = time.perf_counter()
        sock.connect(sockaddr)
        latency = (time.perf_counter() - start) * 1000.0
        return sock, latency
    except Exception:
        sock.close()
        raise

# ---------------------------- Pipeline Workers -------------------------
def producer(target_stream, ports, connect_queue, delay_sec):
    for ip, host in target_stream:
        for port in ports:
            connect_queue.put((ip, port, host, 0))
        if delay_sec > 0:
            time.sleep(delay_sec)

def connect_worker(connect_queue, scan_queue, result_queue, tcp_timeout_ms):
    timeout_sec = tcp_timeout_ms / 1000.0
    while True:
        item = connect_queue.get()
        if item is None:
            connect_queue.task_done()
            break
        ip, port, host, retry_count = item
        sock = None
        try:
            sock, tcp_lat = raw_connect(ip, port, timeout_sec)
            scan_queue.put((ip, port, host, sock, tcp_lat))
        except OSError as e:
            is_emfile = (e.errno in (errno.EMFILE, errno.ENFILE)) or (getattr(e, 'winerror', None) == 10024)
            if is_emfile:
                if retry_count < MAX_RETRY_EMFILE:
                    safe_print(f"[!] FD exhaustion, requeue {ip}:{port} (retry {retry_count+1}/{MAX_RETRY_EMFILE})")
                    time.sleep(0.1)   # Reduced from 1 to 0.1 for faster recovery
                    connect_queue.put((ip, port, host, retry_count + 1))
                else:
                    safe_print(f"[!] Max retries exceeded for {ip}:{port}, marking UNREACHABLE")
                    result_queue.put((ip, port, None, None, None, ScanState.UNREACHABLE))
                    if sock:
                        sock.close()
            else:
                result_queue.put((ip, port, None, None, None, ScanState.UNREACHABLE))
                if sock:
                    sock.close()
        except Exception:
            result_queue.put((ip, port, None, None, None, ScanState.UNREACHABLE))
            if sock:
                sock.close()
        finally:
            connect_queue.task_done()

def scan_worker(scan_queue, result_queue,
                http_enabled, tls_enabled, ws_enabled,
                http_timeout_ms, tls_timeout_ms, ws_timeout_ms,
                ws_path, sni_mode, custom_sni, custom_host, ws_host, ws_strict):
    while True:
        item = scan_queue.get()
        if item is None:
            scan_queue.task_done()
            break
        ip, port, host, sock, tcp_lat = item
        is_https = port in HTTPS_PORTS
        effective_sni = None
        if sni_mode == "SIMULATE":
            if ws_enabled and ws_host:
                effective_sni = ws_host
            else:
                effective_sni = "cloudflare.com"
        elif sni_mode == "CUSTOM":
            effective_sni = custom_sni

        if http_enabled or ws_enabled:
            if custom_host == "USE_WS_HOST" and ws_enabled and ws_host:
                final_host_header = ws_host
            elif custom_host and custom_host != "USE_WS_HOST":
                final_host_header = custom_host
            else:
                final_host_header = host if host else ip
            final_host_header = get_clean_host_header(final_host_header)

        tls_success = False
        http_success = False
        ws_success = False
        state = ScanState.TCP_OK
        tls_lat = None
        http_lat = None
        connection_closed = False
        ssl_sock = None

        try:
            cur = sock
            if tls_enabled and is_https:
                ctx = get_ssl_ctx()
                ssl_sock = ctx.wrap_socket(sock, server_hostname=effective_sni, do_handshake_on_connect=False)
                ssl_sock.settimeout(tls_timeout_ms / 1000.0)
                tls_start = time.perf_counter()
                ssl_sock.do_handshake()
                tls_lat = (time.perf_counter() - tls_start) * 1000.0
                cur = ssl_sock
                tls_success = True
                state = ScanState.TCP_TLS

            if http_enabled or ws_enabled:
                ws_key = generate_websocket_key()
                path = ws_path if ws_path else "/"
                if ws_enabled:
                    request = (
                        f"GET {path} HTTP/1.1\r\n"
                        f"Host: {final_host_header}\r\n"
                        f"Connection: Upgrade\r\n"
                        f"Upgrade: websocket\r\n"
                        f"Sec-WebSocket-Key: {ws_key}\r\n"
                        f"Sec-WebSocket-Version: 13\r\n"
                        f"User-Agent: Mozilla/5.0\r\n"
                        f"\r\n"
                    )
                else:
                    request = (
                        f"GET {path} HTTP/1.1\r\n"
                        f"Host: {final_host_header}\r\n"
                        f"User-Agent: Mozilla/5.0\r\n"
                        f"\r\n"
                    )
                cur.sendall(request.encode())
                http_start = time.perf_counter()
                response = b''
                recv_timeout = False
                first_byte = True
                if ws_enabled:
                    recv_timeout_sec = ws_timeout_ms / 1000.0
                elif http_enabled:
                    recv_timeout_sec = http_timeout_ms / 1000.0
                else:
                    recv_timeout_sec = 0

                while len(response) < HTTP_RECV_MAX_BYTES and recv_timeout_sec > 0:
                    time_left = recv_timeout_sec - (time.perf_counter() - http_start)
                    if time_left <= 0:
                        recv_timeout = True
                        break
                    cur.settimeout(time_left)
                    try:
                        chunk = cur.recv(HTTP_RECV_MAX_BYTES)
                        if not chunk:
                            connection_closed = True
                            break
                        if first_byte:
                            http_lat = (time.perf_counter() - http_start) * 1000.0
                            first_byte = False
                        response += chunk
                        if b'\r\n\r\n' in response or b'\n\n' in response:
                            break
                    except socket.timeout:
                        recv_timeout = True
                        break
                    except Exception:
                        break

                if recv_timeout:
                    http_success = False
                    if http_enabled:
                        state = ScanState.HTTP_TIMEOUT
                elif connection_closed and not response:
                    http_success = False
                    if http_enabled:
                        state = ScanState.HTTP_FAIL
                elif response:
                    http_success = True
                    if ws_enabled and response:
                        _, _, _, ws_ok = parse_http_status(response, ws_key if ws_strict else None, ws_strict)
                        if ws_ok:
                            ws_success = True
                else:
                    http_success = False

            if ws_success:
                state = ScanState.WS_TLS if tls_success else ScanState.WS
            else:
                if tls_success and http_success:
                    state = ScanState.TCP_HTTP_TLS
                elif tls_success and not http_success and http_enabled:
                    state = ScanState.TCP_TLS
                elif tls_success and not http_success and not http_enabled:
                    state = ScanState.TCP_TLS
                elif not tls_success and http_success:
                    state = ScanState.TCP_HTTP
                elif not tls_success and not http_success and http_enabled:
                    pass
                elif not tls_success and not http_success:
                    state = ScanState.TCP_OK

            result_queue.put((ip, port, tcp_lat, tls_lat if tls_success else None,
                              http_lat if http_success else None, state))

        except Exception:
            if tls_success and state == ScanState.TCP_TLS:
                result_queue.put((ip, port, tcp_lat, tls_lat, None, ScanState.TCP_TLS))
            elif http_enabled and not is_https:
                result_queue.put((ip, port, tcp_lat, None, None, ScanState.HTTP_FAIL))
            elif tls_enabled and is_https:
                result_queue.put((ip, port, tcp_lat, None, None, ScanState.TLS_FAIL))
            else:
                result_queue.put((ip, port, tcp_lat, None, None, ScanState.TCP_OK))
        finally:
            if ssl_sock:
                with contextlib.suppress(Exception):
                    ssl_sock.close()
            elif sock:
                with contextlib.suppress(Exception):
                    sock.close()
        scan_queue.task_done()

def logger_worker(result_queue, temp_file, raw_file, target_str, ports, local_isp, sort_by, verbose,
                  tcp_timeout, http_enabled, tls_enabled, ws_enabled,
                  http_timeout, tls_timeout, ws_timeout,
                  ws_path, custom_host, ws_host, ws_strict, sni_mode, custom_sni, stop_event):
    with open(raw_file, "w", encoding="utf-8") as raw_f:
        raw_f.write("# RAW RESULTS - survived if scan crashes\n")
        raw_f.write("# Format: IP|PORT|TCP_LAT|TLS_LAT|HTTP_LAT|STATE\n")
        raw_f.flush()

        with open(temp_file, "w", encoding="utf-8") as f:
            f.write("# TEMP\n")
            alive_count = 0
            unreachable_count = 0
            ip_best_state = {}
            state_priority = {
                ScanState.WS_TLS: 12, ScanState.WS: 11,
                ScanState.TCP_HTTP_TLS: 10, ScanState.TCP_HTTP: 9, ScanState.TCP_TLS: 8,
                ScanState.HTTP_OK: 7, ScanState.TCP_OK: 6,
                ScanState.HTTP_FAIL: 5, ScanState.HTTP_TIMEOUT: 4,
                ScanState.TLS_FAIL: 3, ScanState.TLS_TIMEOUT: 2,
                ScanState.UNREACHABLE: 0
            }
            count = 0
            while not stop_event.is_set():
                try:
                    item = result_queue.get(timeout=0.5)
                except Empty:
                    continue
                if item is None:
                    break
                ip, port, tcp, tls, http, state = item
                if state == ScanState.UNREACHABLE:
                    unreachable_count += 1
                    continue
                alive_count += 1
                curr_prio = state_priority.get(ip_best_state.get(ip), 0)
                new_prio = state_priority.get(state, 0)
                if new_prio > curr_prio:
                    ip_best_state[ip] = state
                count += 1
                if verbose:
                    tcp_str = f"{tcp:.1f}ms" if tcp is not None else "?"
                    tls_str = ""
                    if tls_enabled and (port in HTTPS_PORTS):
                        if tls is not None:
                            tls_str = f"TLS={tls:.1f}ms "
                        else:
                            if state == ScanState.TLS_TIMEOUT:
                                tls_str = "TLS=Timeout "
                            elif state == ScanState.TLS_FAIL:
                                tls_str = "TLS=Failed "
                    http_str = ""
                    if http_enabled:
                        if http is not None:
                            http_str = f"HTTP={http:.1f}ms "
                        else:
                            if state == ScanState.HTTP_TIMEOUT:
                                http_str = "HTTP=Timeout "
                            elif state == ScanState.HTTP_FAIL:
                                http_str = "HTTP=Failed "
                            else:
                                http_str = "HTTP=Failed "
                    safe_print(f"[+] {ip}:{port} TCP={tcp_str} {http_str}{tls_str}-> {state.name}")
                elif count % PRINT_INTERVAL == 0:
                    safe_print(f"[Logger] Processed {count} results")
                line = f"{ip}|{port}|{tcp}|{tls}|{http}|{int(state)}\n"
                f.write(line)
                f.flush()
                raw_f.write(line)
                raw_f.flush()
                result_queue.task_done()

    port_data = defaultdict(list)
    try:
        with open(temp_file, "r") as f:
            next(f)
            for line in f:
                line = line.strip()
                if not line:
                    continue
                parts = line.split('|')
                if len(parts) != 6:
                    continue
                ip, port_s, tcp_s, tls_s, http_s, state_s = parts
                port = int(port_s)
                tcp = float(tcp_s) if tcp_s != 'None' else None
                tls = float(tls_s) if tls_s != 'None' else None
                http = float(http_s) if http_s != 'None' else None
                state = ScanState(int(state_s))
                port_data[port].append((ip, tcp, tls, http, state))
    except Exception as e:
        safe_print(f"[!] Error reading temporary results: {e}")
        safe_print("[!] Results may be incomplete. Check temp_results.txt or raw_results.txt")
    finally:
        with _file_lock, open(RESULTS_FILE, "w", encoding="utf-8") as f:
            f.write("# CLEAN_IP_FINDER [Version 2.0] - Made by Mobin\n")
            f.write(f"# Target: {target_str}\n")
            f.write(f"# Ports: {','.join(str(p) for p in ports)}\n")
            f.write(f"# TCP timeout: {tcp_timeout}ms\n")
            f.write(f"# HTTP test: {'y' if http_enabled else 'n'}\n")
            f.write(f"# HTTP timeout: {http_timeout}ms\n")
            f.write(f"# TLS test: {'y' if tls_enabled else 'n'}\n")
            f.write(f"# TLS timeout: {tls_timeout}ms\n")
            f.write(f"# WebSocket test: {'y' if ws_enabled else 'n'}\n")
            f.write(f"# WebSocket timeout: {ws_timeout}ms\n")
            f.write(f"# WebSocket path: {ws_path}\n")
            f.write(f"# Custom Host header: {custom_host if custom_host else 'None'}\n")
            f.write(f"# WebSocket Host: {ws_host if ws_host else 'None'}\n")
            f.write(f"# Strict WebSocket: {ws_strict}\n")
            f.write(f"# SNI mode: {sni_mode}\n")
            if sni_mode == "CUSTOM":
                f.write(f"# Custom SNI: {custom_sni}\n")
            f.write(f"# Sort by: {sort_by}\n")
            f.write(f"# Your ISP: {local_isp}\n")
            f.write("#Free_Iran\n\n")

            for port in sorted(port_data.keys()):
                f.write(f"--- Port {port} ---\n")
                entries = port_data[port]
                if sort_by == "TCP":
                    entries.sort(key=lambda x: x[1] if x[1] is not None else float('inf'))
                elif sort_by == "HTTP":
                    entries.sort(key=lambda x: x[3] if x[3] is not None else float('inf'))
                elif sort_by == "TLS":
                    entries.sort(key=lambda x: x[2] if x[2] is not None else float('inf'))
                else:
                    entries.sort(key=lambda x: x[1] if x[1] is not None else float('inf'))

                for ip, tcp, tls, http, state in entries:
                    tcp_str = f"{tcp:.1f}" if tcp is not None else "?"
                    http_str = ""
                    if http_enabled:
                        if http is not None:
                            http_str = f"HTTP={http:.1f}ms "
                        else:
                            if state == ScanState.HTTP_TIMEOUT:
                                http_str = "HTTP=Timeout "
                            elif state == ScanState.HTTP_FAIL:
                                http_str = "HTTP=Failed "
                            else:
                                http_str = "HTTP=Failed "
                    tls_str = ""
                    if tls_enabled and (port in HTTPS_PORTS):
                        if tls is not None:
                            tls_str = f"TLS={tls:.1f}ms "
                        else:
                            if state == ScanState.TLS_TIMEOUT:
                                tls_str = "TLS=Timeout "
                            elif state == ScanState.TLS_FAIL:
                                tls_str = "TLS=Failed "
                    if state == ScanState.TCP_OK:
                        display = "TCP"
                    elif state == ScanState.HTTP_OK:
                        display = "HTTP"
                    elif state == ScanState.TCP_HTTP:
                        display = "TCP+HTTP"
                    elif state == ScanState.TCP_TLS:
                        display = "TCP+TLS"
                    elif state == ScanState.TCP_HTTP_TLS:
                        display = "TCP+HTTP+TLS"
                    elif state == ScanState.HTTP_TIMEOUT:
                        display = "HTTP_TIMEOUT"
                    elif state == ScanState.HTTP_FAIL:
                        display = "HTTP_FAIL"
                    elif state == ScanState.TLS_TIMEOUT:
                        display = "TLS_TIMEOUT"
                    elif state == ScanState.TLS_FAIL:
                        display = "TLS_FAIL"
                    elif state == ScanState.WS:
                        display = "WS"
                    elif state == ScanState.WS_TLS:
                        display = "WS_TLS"
                    else:
                        display = state.name
                    f.write(f"{ip:<20} TCP={tcp_str}ms {http_str}{tls_str}-> {display}\n")
                f.write("\n")

        safe_print("\n=== SUMMARY ===")
        safe_print(f"Alive IP entries: {alive_count}")
        safe_print(f"Unreachable IP entries: {unreachable_count}")
        def cnt(st):
            return sum(1 for v in ip_best_state.values() if v == st)
        safe_print(f"  TCP: {cnt(ScanState.TCP_OK)}")
        safe_print(f"  TCP+HTTP: {cnt(ScanState.TCP_HTTP)}")
        safe_print(f"  TCP+TLS: {cnt(ScanState.TCP_TLS)}")
        safe_print(f"  TCP+HTTP+TLS: {cnt(ScanState.TCP_HTTP_TLS)}")
        safe_print(f"  HTTP_OK: {cnt(ScanState.HTTP_OK)}")
        safe_print(f"  HTTP_TIMEOUT: {cnt(ScanState.HTTP_TIMEOUT)}")
        safe_print(f"  HTTP_FAIL: {cnt(ScanState.HTTP_FAIL)}")
        safe_print(f"  TLS_FAIL: {cnt(ScanState.TLS_FAIL)}")
        safe_print(f"  TLS_TIMEOUT: {cnt(ScanState.TLS_TIMEOUT)}")
        safe_print(f"  WS: {cnt(ScanState.WS)}")
        safe_print(f"  WS_TLS: {cnt(ScanState.WS_TLS)}")
        safe_print(f"Results saved to {RESULTS_FILE}")
        safe_print(f"Raw results (crash‑safe) saved to {RAW_RESULTS_FILE}")

        with contextlib.suppress(OSError):
            os.remove(temp_file)

# ---------------------------- User input -------------------------------
def input_with_default(prompt, default, is_int=False, is_float=False):
    while True:
        val = input(f"{prompt} [{default}]: ").strip()
        if not val:
            val = default
        try:
            if is_int:
                return int(val)
            if is_float:
                return float(val)
            return val
        except ValueError:
            safe_print("Invalid number")

def input_yn(prompt, default_yes=True):
    default_str = "Y/n" if default_yes else "y/N"
    while True:
        val = input(f"{prompt} [{default_str}]: ").strip().lower()
        if not val:
            return default_yes
        if val in ('y', 'yes'):
            return True
        if val in ('n', 'no'):
            return False
        safe_print("Please enter y or n")

# ---------------------------- Main -------------------------------------
if __name__ == "__main__":
    safe_print("=== CLEAN_IP_FINDER [Version 2.0] – Simple, Fast, Reliable ===")
    safe_print("#Free_Iran\n")
    safe_print("Press Ctrl+C to stop\n")
    
    if not check_dependencies():
        sys.exit(1)
    
    open_log()
    atexit.register(close_log)
    
    with contextlib.suppress(OSError):
        os.remove(RESULTS_FILE)
    with contextlib.suppress(OSError):
        os.remove(TEMP_FILE)
    with contextlib.suppress(OSError):
        os.remove(RAW_RESULTS_FILE)
    
    stop_event = threading.Event()
    
    try:
        target_str = input("IP/Range/Domain: ").strip()
        if not target_str:
            sys.exit(1)
        ports_raw = input("Ports (empty for defaults): ").strip()
        ports = [int(p) for p in ports_raw.split(',') if p.strip().isdigit()] if ports_raw else sorted(ALL_L7_PORTS)
        if not ports:
            sys.exit(1)

        tcp_timeout = int(input_with_default("TCP timeout (ms)", "800", is_int=True))
        http_enabled = input_yn("Enabled HTTP Test", default_yes=True)
        http_timeout = 3000
        if http_enabled:
            http_timeout = int(input_with_default("HTTP timeout (ms)", "3000", is_int=True))
        else:
            http_timeout = 0

        tls_enabled = input_yn("Enabled TLS Test", default_yes=True)
        tls_timeout = 3000
        if tls_enabled:
            tls_timeout = int(input_with_default("TLS timeout (ms)", "3000", is_int=True))
        else:
            tls_timeout = 0

        ws_enabled = input_yn("Enabled WebSocket Test", default_yes=False)
        ws_timeout = 3000
        ws_path = "/"
        ws_strict = True
        ws_host = None
        custom_host = None

        if ws_enabled:
            ws_timeout = int(input_with_default("WebSocket timeout (ms)", "3000", is_int=True))
            ws_strict = input_yn("Strict WebSocket (RFC6455)", default_yes=True)
            
            safe_print("\nWebSocket Host (for WS upgrade):")
            safe_print("  1 - Empty")
            safe_print("  2 - Custom")
            ws_host_choice = input_with_default("Choose (1/2)", "1")
            if ws_host_choice == "2":
                ws_host = input("Enter WebSocket host: ").strip()
                if not ws_host:
                    ws_host = None
            else:
                ws_host = None
            
            ws_path = input_with_default("WebSocket path", "/")
            
            safe_print("\nHost header (for HTTP request):")
            safe_print("  1 - Empty (use IP as Host)")
            safe_print("  2 - Use WebSocket Host (same as WS host below)")
            safe_print("  3 - Custom")
            host_choice = input_with_default("Choose (1/2/3)", "1")
            if host_choice == "1":
                custom_host = None
            elif host_choice == "2":
                custom_host = "USE_WS_HOST"
            else:
                custom_host = input("Enter custom Host header: ").strip()
                if not custom_host:
                    custom_host = None
            
            safe_print("\nSNI modes:")
            safe_print("  1 - EMPTY (no SNI)")
            safe_print("  2 - SIMULATE (WebSocket Host)")
            safe_print("  3 - CUSTOM")
            sni_choice = input_with_default("Choose (1/2/3)", "2")
            if sni_choice == "1":
                sni_mode = "EMPTY"
                custom_sni = None
            elif sni_choice == "2":
                sni_mode = "SIMULATE"
                custom_sni = None
            else:
                sni_mode = "CUSTOM"
                custom_sni = input("SNI domain: ").strip() or None
        else:
            safe_print("\nHost header:")
            safe_print("  1 - Empty (use IP as Host)")
            safe_print("  2 - Custom")
            host_choice = input_with_default("Choose (1/2)", "1")
            if host_choice == "1":
                custom_host = None
            else:
                custom_host = input("Enter custom Host header: ").strip()
                if not custom_host:
                    custom_host = None
            
            safe_print("\nSNI modes:")
            safe_print("  1 - EMPTY (no SNI)")
            safe_print("  2 - SIMULATE (cloudflare.com)")
            safe_print("  3 - CUSTOM")
            sni_choice = input_with_default("Choose (1/2/3)", "2")
            if sni_choice == "1":
                sni_mode = "EMPTY"
                custom_sni = None
            elif sni_choice == "2":
                sni_mode = "SIMULATE"
                custom_sni = None
            else:
                sni_mode = "CUSTOM"
                custom_sni = input("SNI domain: ").strip() or None

        safe_print("\nSort results by latency:")
        safe_print("  1 - TCP (default)")
        safe_print("  2 - HTTP")
        safe_print("  3 - TLS")
        sort_choice = input_with_default("Choose (1/2/3)", "1")
        sort_by = "TCP"
        if sort_choice == "1":
            sort_by = "TCP"
        elif sort_choice == "2":
            sort_by = "HTTP"
        elif sort_choice == "3":
            sort_by = "TLS"

        connect_workers = int(input_with_default("Connect workers (1-100)", "30", is_int=True))
        scan_workers = int(input_with_default("Scan workers (1-200)", "50", is_int=True))
        verbose = input_yn("Verbose output", default_yes=False)
        delay_ms = float(input_with_default("Producer delay (ms)", "0", is_float=True))

        local_isp = get_local_isp()
        safe_print(f"[*] Your ISP: {local_isp}\n")

        connect_q = Queue(maxsize=CONNECT_QUEUE_SIZE)
        scan_q = Queue(maxsize=SCAN_QUEUE_SIZE)
        result_q = Queue(maxsize=RESULT_QUEUE_SIZE)

        target_stream = parse_target_stream(target_str)
        prod_thread = threading.Thread(target=producer,
                                       args=(target_stream, ports, connect_q, delay_ms/1000.0),
                                       daemon=True)
        prod_thread.start()

        connect_threads = []
        for _ in range(connect_workers):
            t = threading.Thread(target=connect_worker,
                                 args=(connect_q, scan_q, result_q, tcp_timeout),
                                 daemon=True)
            t.start()
            connect_threads.append(t)

        scan_threads = []
        for _ in range(scan_workers):
            t = threading.Thread(target=scan_worker,
                                 args=(scan_q, result_q,
                                       http_enabled, tls_enabled, ws_enabled,
                                       http_timeout, tls_timeout, ws_timeout,
                                       ws_path, sni_mode, custom_sni,
                                       custom_host, ws_host, ws_strict),
                                 daemon=True)
            t.start()
            scan_threads.append(t)

        logger_thread = threading.Thread(target=logger_worker,
                                         args=(result_q, TEMP_FILE, RAW_RESULTS_FILE,
                                               target_str, ports, local_isp, sort_by, verbose,
                                               tcp_timeout, http_enabled, tls_enabled, ws_enabled,
                                               http_timeout, tls_timeout, ws_timeout,
                                               ws_path, custom_host, ws_host, ws_strict,
                                               sni_mode, custom_sni, stop_event),
                                         daemon=False)
        logger_thread.start()

        prod_thread.join()

        connect_q.join()
        for _ in connect_threads:
            connect_q.put(None)
        for t in connect_threads:
            t.join()

        scan_q.join()
        for _ in scan_threads:
            scan_q.put(None)
        for t in scan_threads:
            t.join()

        result_q.put(None)
        stop_event.set()
        logger_thread.join()

        safe_print("\nScan finished.")
        with contextlib.suppress(OSError):
            os.remove(LOG_FILE)

    except KeyboardInterrupt:
        safe_print("\n[!] Interrupted by user. Cleaning up...")
        stop_event.set()
        with contextlib.suppress(Exception):
            result_q.put(None)
        time.sleep(0.5)   # Give logger a moment to finalise
    except Exception as e:
        safe_print(f"Fatal error: {e}")
        stop_event.set()
        with contextlib.suppress(Exception):
            result_q.put(None)
    finally:
        close_log()