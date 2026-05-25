#!/usr/bin/env bash
set -euo pipefail

echo "=========================================================="
echo "   真正工业级 REALITY 自用部署脚本 (全客户端支持终极版)   "
echo "=========================================================="

export DEBIAN_FRONTEND=noninteractive
apt-get update -y && apt-get install -y curl jq openssl uuid-runtime cron net-tools wget unzip

# 1. 自动获取准确的公网 IPv4
PUBLIC_IP=$(curl -4 -s --connect-timeout 5 https://api.ip.sb/ip || curl -4 -s --connect-timeout 5 https://ifconfig.me || echo "")
if [ -z "$PUBLIC_IP" ]; then
  echo "[ERROR] 无法获取外部公网 IP，请检查 VPS 网络环境。"
  exit 1
fi

# 2. 强行安装官方 Xray 核心 (使用稳固的物理覆盖，解决国内连接 GitHub 闪断问题)
echo "[*] 正在部署官方 Xray 核心结构..."
mkdir -p /usr/local/bin /usr/local/etc/xray
cd /tmp
wget -O xray.zip https://github.com/XTLS/Xray-core/releases/download/v24.11.21/Xray-linux-64.zip || {
  echo "[*] GitHub 直连微弱，正在切换备用高加速源..."
  wget -O xray.zip https://mirror.ghproxy.com/https://github.com/XTLS/Xray-core/releases/download/v24.11.21/Xray-linux-64.zip
}
unzip -o xray.zip -d /usr/local/bin/
chmod +x /usr/local/bin/xray
rm -f xray.zip

# 3. 死锁官方唯一标准绝对路径
XRAY_BIN="/usr/local/bin/xray"

# 4. 交互式获取域名 (仅用于你的本地节点识别命名)
if [ -t 0 ]; then
  read -r -p "请输入您在 Cloudflare 解析的域名 (如 1564151.xyz): " DOMAIN || true
else
  echo "[ERROR] 必须在交互式终端运行"
  exit 1
fi

if [ -z "${DOMAIN:-}" ]; then
  echo "[ERROR] 域名不能为空。"
  exit 1
fi

# 5. 安全提取密钥对 (使用完全死锁的绝对路径，彻底杜绝留空 Bug)
UUID="$(uuidgen)"
PORT="443"
SID="$(openssl rand -hex 8)"

# 用绝对路径生成密钥，确保 100% 捕获成功
$XRAY_BIN x25519 > /tmp/xray_keys.txt
PRIVATE_KEY=$(awk '/Private key:/ {print $3}' /tmp/xray_keys.txt | tr -d '[:space:]')
PUBLIC_KEY=$(awk '/Public key:/ {print $3}' /tmp/xray_keys.txt | tr -d '[:space:]')
rm -f /tmp/xray_keys.txt

if [ -z "$PRIVATE_KEY" ] || [ -z "$PUBLIC_KEY" ]; then
  echo "[ERROR] 密钥对生成异常，脚本自动终止。"
  exit 1
fi

# 6. 写入极致纯净的 Xray 配置文件 (徹底去除私人域名痕跡，純淨偽裝微軟)
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
            "www.microsoft.com"
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

# 7. 配置 Systemd 系统服务守护
cat > /etc/systemd/system/xray.service <<EOF
[Unit]
Description=Xray Production Service
After=network.target nss-lookup.target

[Service]
User=root
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
NoNewPrivileges=true
ExecStart=${XRAY_BIN} run -config /usr/local/etc/xray/config.json
Restart=always
RestartSec=5
LimitNOFILE=1048576

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable xray
systemctl restart xray

# 8. 配置 5 分钟进程探活自愈看门狗 (零机场特征)
mkdir -p /usr/local/bin
cat > /usr/local/bin/xray-check.sh <<EOF
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
crontab "$TMP_CRON"
rm -f "$TMP_CRON"

# 9. 拼装客户端输出
URI="vless://${UUID}@${PUBLIC_IP}:${PORT}?security=reality&encryption=none&pbk=${PUBLIC_KEY}&sni=www.microsoft.com&flow=xtls-rprx-vision&type=tcp&sid=${SID}#Reality_${DOMAIN}"

echo
echo "==================== 工业级自用终极版部署成功 ===================="
echo "公网IP: $PUBLIC_IP"
echo "管理标识域名: $DOMAIN"
echo "------------------------------------------------------------------"
echo "【📱 Shadowrocket 小火箭专用单行链接】(直接整行复制导入):"
echo "$URI"
echo "------------------------------------------------------------------"
echo "【💻 Clash Verge 专用配置格式】(复制粘贴进 YAML 的 proxies 列表下):"
echo "  - name: \"Reality_${DOMAIN}\""
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