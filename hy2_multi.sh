#!/usr/bin/env bash
set -euo pipefail

echo “================================================”
echo “      VLESS Reality 自用稳定版一键脚本”
echo “================================================”

export DEBIAN_FRONTEND=noninteractive

apt-get update -y
apt-get install -y curl wget unzip openssl uuid-runtime cron

=========================================================

获取公网 IP

=========================================================

PUBLIC_IP=$(curl -4 -s –connect-timeout 5 https://api.ip.sb/ip || true)

if [ -z “$PUBLIC_IP” ]; then
PUBLIC_IP=$(curl -4 -s –connect-timeout 5 https://ifconfig.me || true)
fi

if [ -z “$PUBLIC_IP” ]; then
echo “[ERROR] 无法获取公网 IP”
exit 1
fi

echo “[INFO] 公网 IP: $PUBLIC_IP”

=========================================================

安装 Xray

=========================================================

if ! command -v xray >/dev/null 2>&1; then
echo “[INFO] 安装 Xray…”
bash -c “$(curl -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh)” @ install
fi

XRAY_BIN=”/usr/local/bin/xray”

=========================================================

生成参数

=========================================================

UUID=$(uuidgen)
PORT=443
SHORT_ID=$(openssl rand -hex 8)

KEY_OUTPUT=$($XRAY_BIN x25519)

PRIVATE_KEY=$(echo “$KEY_OUTPUT” | grep “PrivateKey:” | awk ‘{print $2}’)
PUBLIC_KEY=$(echo “$KEY_OUTPUT” | grep “Public” | awk ‘{print $2}’)

if [ -z “$PRIVATE_KEY” ] || [ -z “$PUBLIC_KEY” ]; then
echo “[ERROR] 密钥生成失败”
exit 1
fi

=========================================================

写入配置

=========================================================

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

=========================================================

systemd

=========================================================

systemctl daemon-reload
systemctl enable xray
systemctl restart xray

sleep 2

=========================================================

防火墙

=========================================================

if command -v ufw >/dev/null 2>&1; then
ufw allow 443/tcp >/dev/null 2>&1 || true
fi

=========================================================

检查状态

=========================================================

if systemctl is-active –quiet xray; then
echo “[OK] Xray 已启动”
else
echo “[ERROR] Xray 启动失败”
systemctl status xray –no-pager
exit 1
fi

=========================================================

输出节点

=========================================================

URI=“vless://${UUID}@${PUBLIC_IP}:${PORT}?security=reality&encryption=none&pbk=${PUBLIC_KEY}&headerType=none&type=tcp&flow=xtls-rprx-vision&sni=www.cloudflare.com&fp=chrome&sid=${SHORT_ID}#Reality”

echo
echo “================================================”
echo “             Reality 节点信息”
echo “================================================”
echo
echo “$URI”
echo
echo “================================================”
echo “导入客户端即可使用”
echo “================================================”