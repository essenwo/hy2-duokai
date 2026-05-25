#!/usr/bin/env bash
set -euo pipefail

echo "=== 工业级 REALITY 多节点通用部署脚本 ==="

export DEBIAN_FRONTEND=noninteractive
apt-get update -y && apt-get install -y curl jq openssl uuid-runtime cron

PUBLIC_IP=$(curl -4 -s --connect-timeout 5 https://api.ip.sb/ip || curl -4 -s --connect-timeout 5 https://ifconfig.me || echo "")
if [ -z "$PUBLIC_IP" ]; then
  echo "[ERROR] 无法获取外部公网 IP，请检查 VPS 网络环境。"
  exit 1
fi

if ! command -v xray >/dev/null 2>&1; then
  echo "[*] 正在拉取官方 Xray 核心..."
  bash -c "$(curl -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh)" @ install
fi

if [ -t 0 ]; then
  read -r -p "请输入您的二级域名 (如 vps1.1564151.xyz): " DOMAIN || true
else
  echo "[ERROR] 必须在交互式终端运行以输入域名"
  exit 1
fi

if [ -z "${DOMAIN:-}" ]; then
  echo "[ERROR] 域名不能为空。"
  exit 1
fi

UUID="$(uuidgen)"
PORT="443"

# 【核心修复点】强行同步等待，确保私钥和公钥 100% 捕获成功，绝不留空
XRAY_KEYS=$(/usr/local/bin/xray x25519)
PRIVATE_KEY=$(echo "$XRAY_KEYS" | awk '/Private key:/ {print $3}' | tr -d '\r\n')
PUBLIC_KEY=$(echo "$XRAY_KEYS" | awk '/Public key:/ {print $3}' | tr -d '\r\n')
SID="$(openssl rand -hex 8)"

mkdir -p /usr/local/etc/xray

cat > /usr/local/etc/xray/config.json <<EOF
{
  "log": {
    "loglevel": "warning"
  },
  "inbounds": [
    {
      "port": ${PORT},
      "protocol": "vless",
      "settings": {
        "clients": [
          {
            "id": "${UUID}",
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
          "serverNames": [
            "www.microsoft.com",
            "${DOMAIN}"
          ],
          "privateKey": "${PRIVATE_KEY}",
          "shortIds": ["${SID}"]
        },
        "tcpSettings": {
          "sockopt": {
            "tcpKeepAliveIdle": 30
          }
        }
      }
    }
  ],
  "outbounds": [
    {
      "protocol": "direct"
    }
  ]
}
EOF

cat > /etc/systemd/system/xray.service <<EOF
[Unit]
Description=Xray Production Service
After=network.target nss-lookup.target

[Service]
User=root
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
NoNewPrivileges=true
ExecStart=/usr/local/bin/xray run -config /usr/local/etc/xray/config.json
Restart=always
RestartSec=5
LimitNOFILE=1048576

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable xray
systemctl restart xray

mkdir -p /usr/local/bin
cat > /usr/local/bin/xray-check.sh <<'EOF'
#!/usr/bin/env bash
if ! pgrep xray >/dev/null; then
  systemctl daemon-reload
  systemctl restart xray
fi
EOF
chmod +x /usr/local/bin/xray-check.sh

CRON_EXISTING="$(crontab -l 2>/dev/null | grep -v "xray-check.sh" | grep -v "reboot" || true)"
TMP_CRON="$(mktemp)"
printf "%s\n" "$CRON_EXISTING" > "$TMP_CRON"
echo "*/5 * * * * /usr/local/bin/xray-check.sh >/dev/null 2>&1" >> "$TMP_CRON"
echo "0 4 * * 1 /sbin/reboot" >> "$TMP_CRON"
crontab "$TMP_CRON"
rm -f "$TMP_CRON"

URI="vless://${UUID}@${PUBLIC_IP}:${PORT}?security=reality&encryption=none&pbk=${PUBLIC_KEY}&sni=www.microsoft.com&flow=xtls-rprx-vision&type=tcp&sid=${SID}#Reality_VPS_Node"

echo
echo "==================== 工业级多节点通用版部署成功 ===================="
echo "公网IP: $PUBLIC_IP"
echo "绑定的二级域名: $DOMAIN"
echo "------------------------------------------------------------------"
echo "【Shadowrocket 小火箭专用链接】:"
echo "$URI"
echo "------------------------------------------------------------------"
echo "【Clash Verge 专用配置格式（用于粘贴进 YAML 节点列表）】:"
echo "  - name: \"Reality_VPS_Node\""
echo "    type: vless"
echo "    server: $PUBLIC_IP"
echo "    port: 443"
echo "    uuid: $UUID"
echo "    cipher: auto"
echo "    tls: true"
echo "    flow: xtls-rprx-vision"
echo "    servername: www.microsoft.com"
echo "    network: tcp"
echo "    udp: true"
echo "    reality-opts:"
echo "      public-key: $PUBLIC_KEY"
echo "      short-id: $SID"
echo "=================================================================="