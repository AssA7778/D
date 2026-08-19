#!/bin/bash
# AssA quick launcher — connects WARP then runs AssA.py (interactive)
# Usage: bash run.sh
set -e
R="\033[91m"; G="\033[92m"; Y="\033[93m"; C="\033[96m"; X="\033[0m"

echo -e "  ${Y}AssA Launcher${X}"
# Connect WARP (split-tunnel — SSH stays up)
if ! wg show >/dev/null 2>&1; then
    echo -e "  ${C}▸${X} Connecting WARP..."
    wg-quick up /tmp/wgcf-profile.conf 2>&1 | tail -1 || true
    sleep 2
fi
echo -e "  ${G}✓${X} WARP up — type target IP when prompted\n"
python3 /root/AssA.py
echo -e "\n  ${Y}Disconnect WARP when done:${X} wg-quick down /tmp/wgcf-profile.conf"
