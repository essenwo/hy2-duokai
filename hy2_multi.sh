#!/usr/bin/env bash
set -euo pipefail

echo "=== 安装 VLESS Reality ==="

export DEBIAN_FRONTEND=noninteractive

apt update -y
apt install -y curl openssl uuid-runtime unzip wget

# 获取公网IP
PUBLIC_IP=$(curl -4 -s https://api.ip.sb/ip)

if [ -z "$PUBLIC_IP" ]; then
  echo "获取公网IP失败"
  exit 1
fi

# 安装 Xray
bash -c "$(curl -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh)" @ install

XRAY_BIN=$(command -v xray)

if [ -z "$XRAY_BIN" ]; then
  echo "Xray 安装失败"
  exit 1
fi

# 生成 Reality 密钥
KEYS=$($XRAY_BIN x25519)

PRIVATE_KEY=$(echo "$KEYS" | awk '/Private key:/ {print $3}')
PUBLIC_KEY=$(echo "$KEYS" | awk '/Public key:/ {print $3}')

UUID=$(uuidgen)
SHORT_ID=$(openssl rand -hex 8)

mkdir -p /usr/local/etc/xray

cat > /usr/local/etc/xray/config.json <<EOF
{
  "log": {
    "loglevel": "warning"
  },
  "inbounds": [
    {
      "listen": "0.0.0.0",
      "port": 443,
      "protocol": "vless",
      "settings": {
        "clients": [
          {
            "id": "$UUID",
            "flow": "xtls-rprx-vision"
          }
        ],
        "decryption": "none"
      },
      "streamSettings": {
        "network": "tcp",
        "security": "reality",
        "realitySettings": {
          "show": false,
          "dest": "www.microsoft.com:443",
          "xver": 0,
          "serverNames": [
            "www.microsoft.com"
          ],
          "privateKey": "$PRIVATE_KEY",
          "shortIds": [
            "$SHORT_ID"
          ]
        }
      }
    }
  ],
  "outbounds": [
    {
      "protocol": "freedom"
    }
  ]
}
EOF

# systemd
systemctl daemon-reload
systemctl enable xray
systemctl restart xray

sleep 2

# 检查服务
if ! systemctl is-active --quiet xray; then
  echo "Xray 启动失败"
  journalctl -u xray --no-pager -n 30
  exit 1
fi

# 开放防火墙
if command -v ufw >/dev/null 2>&1; then
  ufw allow 443/tcp || true
fi

# 输出节点
echo
echo "=============================="
echo "Reality 节点部署成功"
echo "=============================="

URI="vless://${UUID}@${PUBLIC_IP}:443?security=reality&encryption=none&pbk=${PUBLIC_KEY}&headerType=none&fp=chrome&type=tcp&sni=www.microsoft.com&flow=xtls-rprx-vision&sid=${SHORT_ID}#Reality"

echo
echo "$URI"
echo
echo "=============================="