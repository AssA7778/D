#!/bin/bash
# ═══════════════════════════════════════════════════════════════
#  AssA — All-in-One Server Stress & Recon Toolkit Installer
#  Sets up: deps + WARP (split-tunnel) + AssA.py
# ═══════════════════════════════════════════════════════════════

set -e
R="\033[91m"; G="\033[92m"; Y="\033[93m"; C="\033[96m"; X="\033[0m"
info(){ echo -e "  ${C}▸${X} $1"; }
ok(){ echo -e "  ${G}✓${X} $1"; }
err(){ echo -e "  ${R}✗${X} $1"; }

echo -e "${R}"
echo " █████╗ ███████╗███████╗"
echo "██╔══██╗██╔════╝██╔════╝"
echo "███████║███████╗███████╗"
echo "██╔══██║╚════██║╚════██║"
echo "██║  ██║███████║███████║"
echo "╚═╝  ╚═╝╚══════╝╚══════╝"
echo -e "${X}"
echo -e "  ${Y}AssA Installer${X} — via Cloudflare WARP (no-ban)\n"

# Root check
if [[ $EUID -ne 0 ]]; then err "Run as root (sudo bash install.sh)"; exit 1; fi

# Target for split-tunnel
TARGET="${1:-45.74.159.134}"
info "Target for split-tunnel: $TARGET"

# ── 1. System deps ──
info "Installing system dependencies..."
if command -v apt-get >/dev/null; then
    apt-get update -qq
    apt-get install -y -qq python3 python3-pip wireguard-tools wget curl git unzip >/dev/null 2>&1
elif command -v yum >/dev/null; then
    yum install -y python3 pip wireguard-tools wget curl git unzip >/dev/null 2>&1
fi
pip3 install --break-system-packages -q pysocks requests 2>/dev/null || pip3 install -q pysocks requests 2>/dev/null || true
ok "Dependencies installed"

# ── 2. wgcf binary ──
info "Setting up Cloudflare WARP client (wgcf)..."
if [[ ! -f /usr/local/bin/wgcf ]]; then
    ARCH=$(uname -m)
    case "$ARCH" in
        x86_64) WARCH="amd64" ;;
        aarch64|arm64) WARCH="arm64" ;;
        *) WARCH="amd64" ;;
    esac
    wget -q "https://github.com/ViRb3/wgcf/releases/download/v2.2.3/wgcf_2.2.3_linux_${WARCH}" -O /usr/local/bin/wgcf
    chmod +x /usr/local/bin/wgcf
fi
ok "wgcf ready"

# ── 3. Register WARP + generate split-tunnel profile ──
info "Registering WARP account..."
if [[ ! -f /tmp/wgcf-account.toml ]]; then
    wgcf register --accept-tos >/dev/null 2>&1
fi
ok "WARP account registered"

info "Generating WireGuard profile (split-tunnel to $TARGET)..."
wgcf generate >/dev/null 2>&1
# Rewrite AllowedIPs to ONLY target (prevents SSH drop)
python3 - << PY
import re
with open('/tmp/wgcf-profile.conf') as f:
    cfg = f.read()
cfg = re.sub(r'AllowedIPs = .*', f'AllowedIPs = {__import__("sys").argv[1]}/32', cfg, flags=re.M)
cfg = re.sub(r'\nAllowedIPs = ::/0', '', cfg)
with open('/tmp/wgcf-profile.conf','w') as f:
    f.write(cfg)
PY "$TARGET"
ok "Profile ready at /tmp/wgcf-profile.conf"

# ── 4. Copy AssA.py ──
info "Installing AssA.py..."
cp "$(dirname "$0")/AssA.py" /root/AssA.py 2>/dev/null || cp ./AssA.py /root/AssA.py 2>/dev/null || true
chmod +x /root/AssA.py
ok "AssA.py at /root/AssA.py"

# ── 5. Final ──
echo ""
echo -e "  ${G}══════════════════════════════════════════════════${X}"
echo -e "  ${G}✓ AssA installed!${X}"
echo -e "  ${Y}Usage:${X}"
echo -e "    ${C}wg-quick up /tmp/wgcf-profile.conf${X}   ${Y}# connect WARP (no SSH drop)${X}"
echo -e "    ${C}python3 /root/AssA.py --target $TARGET --mode recycle --yes${X}"
echo -e "    ${C}python3 /root/AssA.py${X}                      ${Y}# interactive menu${X}"
echo -e "    ${C}wg-quick down /tmp/wgcf-profile.conf${X} ${Y}# disconnect${X}"
echo -e "  ${G}══════════════════════════════════════════════════${X}\n"
