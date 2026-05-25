#!/usr/bin/env bash
set -euo pipefail

echo “========================================”
echo “ VLESS Reality Stable Install Script”
echo “========================================”

export DEBIAN_FRONTEND=noninteractive

apt-get update -y
apt-get install -y curl wget unzip openssl uuid-runtime

PUBLIC_IP=$(curl -4 -s –connect-timeout 5 https://api.ip.sb/ip || true)

if [ -z “$PUBLIC_IP” ]; then
PUBLIC_IP=$(curl -4 -s –connect-timeout 5 https://ifconfig.me || true)
fi

if [ -z “$PUBLIC_IP” ]; then
echo “[ERROR] Cannot get public IP”
exit 1
fi

echo “[INFO] Public IP: $PUBLIC_IP”

if ! command -v xray >/dev/null 2>&1; then
echo “[INFO] Installing Xray…”
bash -c “$(curl -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh)” @ install
fi

XRAY_BIN=”/usr/local/bin/xray”

UUID=$(uuidgen)
PORT=443
SHORT_ID=$(openssl rand -hex 8)

KEY_OUTPUT=$($XRAY_BIN x25519)

PRIVATE_KEY=$(echo “$KEY_OUTPUT” | grep “PrivateKey:” | awk ‘{print $2}’)
PUBLIC_KEY=$(echo “$KEY_OUTPUT” | grep “Public” | awk ‘{print $2}’)

if [ -z “$PRIVATE_KEY” ] || [ -z “$PUBLIC_KEY” ]; then
echo “[ERROR] Key generate failed”
exit 1
fi

mkdir -p /usr/local/etc/xray

cat > /usr/local/etc/xray/config.json <<EOF
{
“log”: {
“loglevel”: “warning”
},
“inbounds”: [
{
“listen”: “0.0.0.0”,
“port”: ${PORT},
“protocol”: “vless”,
“settings”: {
“clients”: [
{
“id”: “${UUID}”,
“flow”: “xtls-rprx-vision”
}
],
“decryption”: “none”
},
“streamSettings”: {
“network”: “tcp”,
“security”: “reality”,
“realitySettings”: {
“show”: false,
“dest”: “www.cloudflare.com:443”,
“xver”: 0,
“serverNames”: [
“www.cloudflare.com”
],
“privateKey”: “${PRIVATE_KEY}”,
“shortIds”: [
“${SHORT_ID}”
]
}
}
}
],
“outbounds”: [
{
“protocol”: “freedom”
}
]
}
EOF

systemctl daemon-reload
systemctl enable xray
systemctl restart xray

sleep 2

if command -v ufw >/dev/null 2>&1; then
ufw allow 443/tcp >/dev/null 2>&1 || true
fi

if systemctl is-active –quiet xray; then
echo “[OK] Xray started”
else
echo “[ERROR] Xray failed”
systemctl status xray –no-pager
exit 1
fi

URI=“vless://${UUID}@${PUBLIC_IP}:${PORT}?security=reality&encryption=none&pbk=${PUBLIC_KEY}&headerType=none&type=tcp&flow=xtls-rprx-vision&sni=www.cloudflare.com&fp=chrome&sid=${SHORT_ID}#Reality”

echo
echo “========================================”
echo “ Reality Node”
echo “========================================”
echo
echo “$URI”
echo
echo “========================================”
echo “ Import to Shadowrocket”
echo “========================================”