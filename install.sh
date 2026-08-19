#!/bin/bash
# ═══════════════════════════════════════════════════════════════
#  AssA — One-Line Installer (from GitHub)
#  Usage: bash <(curl -s https://raw.githubusercontent.com/AssA7778/D/main/install.sh) 45.74.159.134
#  Or:    wget -qO- https://raw.githubusercontent.com/AssA7778/D/main/install.sh | bash -s 45.74.159.134
# ═══════════════════════════════════════════════════════════════

set -e
R="\033[91m"; G="\033[92m"; Y="\033[93m"; C="\033[96m"; X="\033[0m"
info(){ echo -e "  ${C}▸${X} $1"; }
ok(){ echo -e "  ${G}✓${X} $1"; }
err(){ echo -e "  ${R}✗${X} $1"; }

REPO_RAW="https://raw.githubusercontent.com/AssA7778/D/main"
TARGET="${1:-45.74.159.134}"

echo -e "${R}"
echo " █████╗ ███████╗███████╗"
echo "██╔══██╗██╔════╝██╔════╝"
echo "███████║███████╗███████╗"
echo "██╔══██║╚════██║╚════██║"
echo "██║  ██║███████║███████║"
echo "╚═╝  ╚═╝╚══════╝╚══════╝"
echo -e "${X}"
echo -e "  ${Y}AssA One-Line Installer${X}  (target: ${C}$TARGET${X})\n"

if [[ $EUID -ne 0 ]]; then err "Run as root"; exit 1; fi

TMP=$(mktemp -d)
cd "$TMP"

# ── 1. Download AssA.py + run.sh from repo ──
info "Downloading AssA toolkit from GitHub..."
wget -q "$REPO_RAW/AssA.py" -O AssA.py
wget -q "$REPO_RAW/run.sh" -O run.sh
chmod +x AssA.py run.sh
ok "Downloaded"

# ── 2. System deps ──
info "Installing dependencies..."
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

# ── 3. wgcf (WARP client) ──
info "Setting up Cloudflare WARP..."
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

# ── 4. Register WARP + split-tunnel profile ──
info "Registering WARP + generating split-tunnel profile..."
cd /tmp
if [[ ! -f /tmp/wgcf-account.toml ]]; then
    wgcf register --accept-tos >/dev/null 2>&1
fi
wgcf generate >/dev/null 2>&1
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

# ── 5. Install files ──
info "Installing AssA.py + run.sh to /root/..."
cp "$TMP/AssA.py" /root/AssA.py
cp "$TMP/run.sh" /root/run.sh
ok "Installed"

# ── 6. Verify ──
info "Verifying..."
if wg-quick up /tmp/wgcf-profile.conf >/dev/null 2>&1; then
    ok "WARP connected"
else
    err "WARP failed (check manually: wg-quick up /tmp/wgcf-profile.conf)"
fi
if python3 -c "import py_compile; py_compile.compile('/root/AssA.py', doraise=True)" 2>/dev/null; then
    ok "AssA.py valid"
else
    err "AssA.py syntax error"
fi

# ── Done ──
echo ""
echo -e "  ${G}══════════════════════════════════════════════════${X}"
echo -e "  ${G}✓ AssA installed!${X}"
echo -e ""
echo -e "  ${Y}Run now:${X}"
echo -e "    ${C}bash /root/run.sh${X}                    ${Y}# interactive (IP + yes)${X}"
echo -e "    ${C}python3 /root/AssA.py${X}                ${Y}# same${X}"
echo -e "    ${C}python3 /root/AssA.py --target $TARGET --mode recycle --yes${X}"
echo -e "  ${G}══════════════════════════════════════════════════${X}\n"
rm -rf "$TMP"
