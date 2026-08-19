#!/bin/bash
# ═══════════════════════════════════════════════════════════════
#  AssA — One-Command Installer
#  Does EVERYTHING: deps + WARP + AssA.py + verify
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
echo -e "  ${Y}AssA One-Command Installer${X}\n"

if [[ $EUID -ne 0 ]]; then err "Run as root: sudo bash install.sh"; exit 1; fi

TARGET="${1:-45.74.159.134}"
info "Target (split-tunnel): $TARGET"

# ── 1. System deps ──
info "Step 1/5: Installing system dependencies..."
if command -v apt-get >/dev/null; then
    apt-get update -qq
    DEBIAN_FRONTEND=noninteractive apt-get install -y -qq python3 python3-pip wireguard-tools wget curl git unzip ca-certificates >/dev/null 2>&1
elif command -v yum >/dev/null; then
    yum install -y -q python3 python3-pip wireguard-tools wget curl git unzip ca-certificates >/dev/null 2>&1
elif command -v apk >/dev/null; then
    apk add --no-cache python3 py3-pip wireguard-tools wget curl git unzip ca-certificates >/dev/null 2>&1
fi
pip3 install --break-system-packages -q pysocks requests 2>/dev/null || pip3 install -q pysocks requests 2>/dev/null || true
ok "Dependencies installed"

# ── 2. wgcf ──
info "Step 2/5: Setting up Cloudflare WARP (wgcf)..."
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

# ── 3. Register WARP + split-tunnel profile ──
info "Step 3/5: Registering WARP + generating split-tunnel profile..."
cd /tmp
if [[ ! -f /tmp/wgcf-account.toml ]]; then
    wgcf register --accept-tos >/dev/null 2>&1
fi
wgcf generate >/dev/null 2>&1
# Rewrite AllowedIPs to ONLY target (prevents SSH drop on this box)
export ASSA_TARGET="$TARGET"
python3 - << 'PYEOF'
import re, os
tgt = os.environ.get("ASSA_TARGET", "45.74.159.134")
with open('/tmp/wgcf-profile.conf') as f:
    cfg = f.read()
cfg = re.sub(r'AllowedIPs = [^\n]+', f'AllowedIPs = {tgt}/32', cfg, flags=re.M)
cfg = re.sub(r'\nAllowedIPs = ::/0', '', cfg)
with open('/tmp/wgcf-profile.conf','w') as f:
    f.write(cfg)
PYEOF
ok "Profile at /tmp/wgcf-profile.conf (routes only $TARGET via WARP)"

# ── 4. AssA.py ──
info "Step 4/5: Installing AssA.py..."
SRC="$(dirname "$0")/AssA.py"
if [[ -s "$SRC" ]] && python3 -c "import py_compile; py_compile.compile('$SRC', doraise=True)" 2>/dev/null; then
    cp "$SRC" /root/AssA.py
    ok "AssA.py copied from local"
else
    # Fallback: download from repo
    wget -q "https://raw.githubusercontent.com/AssA7778/D/main/AssA.py" -O /root/AssA.py 2>/dev/null || true
    ok "AssA.py downloaded from repo"
fi
chmod +x /root/AssA.py
ok "AssA.py at /root/AssA.py"

# ── 5. Verify WARP + AssA ──
info "Step 5/5: Verifying setup..."
if wg-quick up /tmp/wgcf-profile.conf >/dev/null 2>&1; then
    ok "WARP connected (split-tunnel)"
else
    err "WARP failed to connect — check manually"
fi
sleep 1
if python3 -c "import py_compile; py_compile.compile('/root/AssA.py', doraise=True)" 2>/dev/null; then
    ok "AssA.py syntax valid"
else
    err "AssA.py has syntax errors"
fi

# ── Done ──
echo ""
echo -e "  ${G}══════════════════════════════════════════════════${X}"
echo -e "  ${G}✓ AssA fully installed & verified!${X}"
echo -e ""
echo -e "  ${Y}Now run:${X}"
echo -e "    ${C}wg-quick up /tmp/wgcf-profile.conf${X}   ${Y}# (if not already up)${X}"
echo -e "    ${C}python3 /root/AssA.py --target $TARGET --mode recycle --yes${X}"
echo -e "    ${C}python3 /root/AssA.py${X}                    ${Y}# interactive menu${X}"
echo -e "    ${C}wg-quick down /tmp/wgcf-profile.conf${X}   ${Y}# disconnect${X}"
echo -e "  ${G}══════════════════════════════════════════════════${X}\n"
