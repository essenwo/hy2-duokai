#!/bin/bash

set -euo pipefail

# ================= 配置区域 =================
# 起始端口 (将占用从该端口开始的5个UDP端口，例如 20000-20004)
START_PORT=20000

# HTTP 订阅链接端口 (TCP)
HTTP_PORT=8080

# 节点名称前缀
NAME_PREFIX="MyHy2_Node"

# 安装目录
HY_DIR="/etc/hysteria_multi"
WEB_DIR="/var/www/html/clash"

# ===========================================

# 检查是否为 root
if [ "$(id -u)" != "0" ]; then
    echo "错误: 必须使用 root 权限运行此脚本"
    exit 1
fi

echo "=== Hysteria2 多端口一键部署脚本 ==="
echo "将部署 5 个节点，端口范围: ${START_PORT} - $((START_PORT+4))"
echo "HTTP 订阅服务器端口: ${HTTP_PORT}"
echo "注意：请确保防火墙已放行上述端口 (UDP) 和 HTTP端口 (TCP)"
echo "========================================"
sleep 2

# 1. 环境清理与准备
echo "[1/8] 清理旧环境..."
systemctl stop hysteria-server >/dev/null 2>&1 || true
systemctl disable hysteria-server >/dev/null 2>&1 || true
# 清理我们这个脚本创建的服务
for i in {0..4}; do
    systemctl stop "hysteria-$i" >/dev/null 2>&1 || true
    systemctl disable "hysteria-$i" >/dev/null 2>&1 || true
done
rm -rf "${HY_DIR}"
rm -rf "${WEB_DIR}"
mkdir -p "${HY_DIR}/certs"
mkdir -p "${WEB_DIR}"

# 2. 依赖安装
echo "[2/8] 安装依赖..."
export DEBIAN_FRONTEND=noninteractive
if command -v apt-get >/dev/null 2>&1; then
    apt-get update -y >/dev/null 2>&1
    apt-get install -y curl jq openssl nginx >/dev/null 2>&1
elif command -v yum >/dev/null 2>&1; then
    yum install -y curl jq openssl nginx
else
    echo "不支持的系统，请手动安装 curl, jq, openssl, nginx"
    exit 1
fi

# 3. 获取 IP 和 域名
echo "[3/8] 获取网络信息..."
PUBLIC_IP=$(curl -s4 https://ipinfo.io/ip || curl -s4 https://ifconfig.me)
if [[ -z "$PUBLIC_IP" ]]; then
    echo "无法获取公网 IP"
    exit 1
fi
# 使用 sslip.io，因为它最稳定
DOMAIN="${PUBLIC_IP//./-}.sslip.io"
echo "使用域名: ${DOMAIN} (解析到 ${PUBLIC_IP})"

# 4. 下载 Hysteria2 核心
echo "[4/8] 下载 Hysteria2..."
if ! command -v hysteria >/dev/null 2>&1; then
    arch=$(uname -m)
    case $arch in
        x86_64) file="hysteria-linux-amd64" ;;
        aarch64) file="hysteria-linux-arm64" ;;
        *) echo "不支持的架构: $arch"; exit 1 ;;
    esac
    ver=$(curl -fsSL https://api.github.com/repos/apernet/hysteria/releases/latest | jq -r '.tag_name')
    curl -L -o /usr/local/bin/hysteria "https://github.com/apernet/hysteria/releases/download/${ver}/${file}"
    chmod +x /usr/local/bin/hysteria
fi

# 5. 部署主节点 (Node 0) - 负责申请证书
echo "[5/8] 部署主节点 (端口 ${START_PORT}) - 用于获取证书..."
PASS_0=$(openssl rand -hex 16)
OBFS_0=$(openssl rand -hex 8)

cat > "${HY_DIR}/config_0.yaml" <<EOF
listen: :${START_PORT}
auth:
  type: password
  password: "${PASS_0}"
obfs:
  type: salamander
  salamander:
    password: "${OBFS_0}"
acme:
  domains:
    - "${DOMAIN}"
  email: "admin@${DOMAIN}"
  dir: "${HY_DIR}/certs"
  type: http
EOF

# 创建主服务文件
cat > "/etc/systemd/system/hysteria-0.service" <<EOF
[Unit]
Description=Hysteria2 Master Node
After=network.target

[Service]
User=root
ExecStart=/usr/local/bin/hysteria server -c ${HY_DIR}/config_0.yaml
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable --now hysteria-0

# 等待证书生成
echo "等待证书申请 (最多 60秒)..."
CERT_FILE="${HY_DIR}/certs/${DOMAIN}.crt"
KEY_FILE="${HY_DIR}/certs/${DOMAIN}.key"
FOUND_CERT=0
for i in {1..12}; do
    if [[ -f "$CERT_FILE" ]] && [[ -f "$KEY_FILE" ]]; then
        echo "证书获取成功！"
        FOUND_CERT=1
        break
    fi
    echo "等待证书中... ($((i*5))s)"
    sleep 5
done

if [[ $FOUND_CERT -eq 0 ]]; then
    echo "错误: 证书申请超时。请检查:"
    echo "1. 80 端口是否开放"
    echo "2. 域名 ${DOMAIN} 是否能 ping 通"
    echo "查看日志: journalctl -u hysteria-0 -n 20"
    exit 1
fi

# 6. 部署从节点 (Node 1-4) - 复用证书
echo "[6/8] 部署其余 4 个节点..."

# 生成 Clash 模板函数
generate_clash() {
    local idx=$1
    local port=$2
    local pass=$3
    local obfs=$4
    local filename="${WEB_DIR}/sub_${port}.yaml"
    
    cat > "$filename" <<EOF
port: 7890
socks-port: 7891
allow-lan: true
mode: rule
log-level: info
external-controller: 127.0.0.1:9090
dns:
  enable: true
  listen: 0.0.0.0:53
  enhanced-mode: fake-ip
  nameserver:
    - 8.8.8.8
    - 1.1.1.1

proxies:
  - name: "${NAME_PREFIX}_${port}"
    type: hysteria2
    server: ${PUBLIC_IP}
    port: ${port}
    password: ${pass}
    obfs: salamander
    obfs-password: ${obfs}
    sni: ${DOMAIN}
    skip-cert-verify: false

proxy-groups:
  - name: "Auto"
    type: select
    proxies:
      - "${NAME_PREFIX}_${port}"
      - DIRECT

rules:
  - GEOIP,CN,DIRECT
  - MATCH,Auto
EOF
}

# 保存主节点的订阅
generate_clash 0 ${START_PORT} "${PASS_0}" "${OBFS_0}"

# 循环创建剩下的节点
for i in {1..4}; do
    CURRENT_PORT=$((START_PORT + i))
    CURRENT_PASS=$(openssl rand -hex 16)
    CURRENT_OBFS=$(openssl rand -hex 8)
    
    # 配置文件 - 直接指向证书路径
    cat > "${HY_DIR}/config_${i}.yaml" <<EOF
listen: :${CURRENT_PORT}
auth:
  type: password
  password: "${CURRENT_PASS}"
obfs:
  type: salamander
  salamander:
    password: "${CURRENT_OBFS}"
tls:
  cert: "${CERT_FILE}"
  key: "${KEY_FILE}"
EOF

    # 服务文件
    cat > "/etc/systemd/system/hysteria-${i}.service" <<EOF
[Unit]
Description=Hysteria2 Node ${i}
After=network.target

[Service]
User=root
ExecStart=/usr/local/bin/hysteria server -c ${HY_DIR}/config_${i}.yaml
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
EOF

    systemctl enable --now "hysteria-${i}"
    generate_clash $i ${CURRENT_PORT} "${CURRENT_PASS}" "${CURRENT_OBFS}"
done

# 7. 配置 Nginx 提供订阅
echo "[7/8] 配置 Nginx..."
rm -f /etc/nginx/sites-enabled/default

cat > /etc/nginx/sites-available/clash-multi.conf <<EOF
server {
    listen ${HTTP_PORT} default_server;
    root ${WEB_DIR};
    
    location / {
        autoindex on;
        default_type application/x-yaml;
    }
}
EOF

ln -sf /etc/nginx/sites-available/clash-multi.conf /etc/nginx/sites-enabled/
nginx -t && systemctl restart nginx

# 8. 输出结果
echo ""
echo "===================================================="
echo "部署完成！已生成 5 个独立端口的订阅链接"
echo "===================================================="
echo "公网 IP: ${PUBLIC_IP}"
echo "HTTP 端口: ${HTTP_PORT}"
echo "域名: ${DOMAIN}"
echo "----------------------------------------------------"

for i in {0..4}; do
    P=$((START_PORT + i))
    echo "节点 $i (端口 $P) Clash 订阅链接:"
    echo "http://${PUBLIC_IP}:${HTTP_PORT}/sub_${P}.yaml"
    echo ""
done

echo "提示："
echo "1. 请务必在 Clash Verge / Clash Meta 中使用。"
echo "2. 如果无法下载订阅，请检查防火墙是否放行 TCP ${HTTP_PORT}。"
echo "3. 如果节点超时，请检查防火墙是否放行 UDP ${START_PORT}-$((START_PORT+4))。"
echo "===================================================="
