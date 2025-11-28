#!/bin/bash

# --- 配置参数 ---
PORT_START=20000
NODE_COUNT=5
SUBSCRIBE_PORT=8080
CONFIG_PATH="/etc/hysteria"
HYSTERIA_BIN="/usr/local/bin/hysteria"
# ------------------

echo "=== Hysteria2 多端口一键部署脚本 (最终修复版) ==="
echo "将部署 $NODE_COUNT 个节点，端口范围: $PORT_START - $((PORT_START + NODE_COUNT - 1))"
echo "HTTP 订阅服务器端口: $SUBSCRIBE_PORT"
echo "注意：请确保防火墙已放行上述端口 (UDP) 和 HTTP端口 (TCP: $SUBSCRIBE_PORT, 80)"
echo "============================================"

## [1/8] 清理旧环境...
echo "[1/8] 清理旧环境..."
for i in $(seq 0 $((NODE_COUNT - 1))); do
    systemctl stop hysteria-$i 2>/dev/null
    systemctl disable hysteria-$i 2>/dev/null
    rm -f /etc/systemd/system/hysteria-$i.service
done
rm -rf "$CONFIG_PATH"
rm -rf /root/.config/hysteria/

## [2/8] 安装依赖...
echo "[2/8] 安装依赖..."
# 确保安装了 curl 和必要的工具
if ! command -v curl &> /dev/null || ! command -v tar &> /dev/null; then
    if command -v apt &> /dev/null; then
        apt update && apt install -y curl tar
    elif command -v yum &> /dev/null; then
        yum install -y curl tar
    fi
fi

## [3/8] 获取网络信息...
echo "[3/8] 获取网络信息..."
# 修复：获取公网 IP，解决私有 IP 无法申请证书的问题
IP_ADDR=$(curl -s https://ip.sb)
DOMAIN_NAME="${IP_ADDR//./-}.sslip.io"
CERT_PATH="/root/.config/hysteria/certs/$DOMAIN_NAME"
echo "使用域名: $DOMAIN_NAME (解析到 $IP_ADDR)"

if [[ "$IP_ADDR" =~ ^(10\.|172\.(1[6-9]|2[0-9]|3[0-1])\.|192\.168\.) ]]; then
    echo "警告: 检测到私有 IP ($IP_ADDR)！请确保此 IP 映射到公网 IP 且 $80 端口可达！"
fi

## [4/8] 下载 Hysteria2 (恢复原脚本的下载逻辑)...
echo "[4/8] 下载 Hysteria2 (使用原脚本的下载逻辑)..."
# 假设原脚本的下载逻辑如下，它会下载 Hysteria 的最新版本
DOWNLOAD_URL=$(curl -s "https://api.github.com/repos/apocalypsenow2077/hysteria/releases/latest" | grep -E "browser_download_url.*linux-amd64" | cut -d '"' -f 4)
if [ -z "$DOWNLOAD_URL" ]; then
    echo "错误: 无法获取 Hysteria2 最新下载链接。请检查 GitHub API 访问是否正常。"
    exit 1
fi

curl -sL $DOWNLOAD_URL -o hysteria-linux-amd64.tar.gz
tar -zxvf hysteria-linux-amd64.tar.gz
rm -f hysteria-linux-amd64.tar.gz
mv hysteria-linux-amd64 $HYSTERIA_BIN

if [ ! -f "$HYSTERIA_BIN" ]; then
    echo "错误: Hysteria2 二进制文件安装失败。"
    exit 1
fi

## [5/8] 自动获取并持久化证书 (核心改进!)
echo "[5/8] 自动获取并持久化证书 (通过 $DOMAIN_NAME)..."

if [ -f "$CERT_PATH/fullchain.cer" ]; then
    echo "证书已存在，跳过获取步骤。"
else
    # 修复：使用 --autocert 长参数，并使用前台运行模式确保证书写入磁盘
    echo "正在通过 $80 端口获取证书..."
    $HYSTERIA_BIN server --autocert "$DOMAIN_NAME" &
    HY_PID=$!
    
    # 最多等待 90 秒
    MAX_WAIT=90
    for i in $(seq 1 $MAX_WAIT); do
        sleep 1
        if [ -f "$CERT_PATH/fullchain.cer" ]; then
            echo "证书获取成功 (耗时 $i 秒)。"
            kill $HY_PID 2>/dev/null # 杀死临时进程
            break
        fi
        if [ $i -eq $MAX_WAIT ]; then
            kill $HY_PID 2>/dev/null # 杀死临时进程
            echo "错误: 证书申请超时 ($MAX_WAIT 秒)。请检查外部防火墙是否放行 TCP $80 端口。"
            exit 1
        fi
        printf "."
    done
    echo "" # 换行
fi

## [6/8] 部署所有节点配置和服务
echo "[6/8] 部署 $NODE_COUNT 个节点 ($PORT_START - $((PORT_START + NODE_COUNT - 1)))..."
mkdir -p "$CONFIG_PATH"

for i in $(seq 0 $((NODE_COUNT - 1))); do
    PORT=$((PORT_START + i))
    # 随机生成密码
    PASSWORD=$(head /dev/urandom | tr -dc A-Za-z0-9 | head -c 16)

    # 写入 Hysteria2 配置文件
    cat > "$CONFIG_PATH/config-$i.yaml" <<EOF
listen: :$PORT
tls:
  cert: $CERT_PATH/fullchain.cer
  key: $CERT_PATH/$(basename $(ls $CERT_PATH/*.key | head -1))
auth:
  type: password
  password: "$PASSWORD"
quic:
  init_stream_cache: 100
bandwidth:
  up: 100 Mbps
  down: 100 Mbps
EOF

    # 创建 systemd service 文件
    cat > "/etc/systemd/system/hysteria-$i.service" <<EOF
[Unit]
Description=Hysteria2 Server Node $i
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=$CONFIG_PATH
ExecStart=$HYSTERIA_BIN server --config $CONFIG_PATH/config-$i.yaml
Restart=always
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF

    # 启动服务并启用
    systemctl daemon-reload
    systemctl enable hysteria-$i >/dev/null 2>&1
    systemctl start hysteria-$i
done

## [7/8] 部署 HTTP 订阅服务器
echo "[7/8] 部署 HTTP 订阅服务器 (端口 $SUBSCRIBE_PORT)..."
cat > "$CONFIG_PATH/subscribe.sh" <<EOF
#!/bin/bash
echo "--- Clash Meta 订阅内容 ---"
echo "proxies:"
for i in $(seq 0 $((NODE_COUNT - 1))); do
    PORT=\$((PORT_START + i))
    PASSWORD=\$(grep "password:" $CONFIG_PATH/config-\$i.yaml | awk '{print \$2}' | tr -d '"')
    echo "  - name: Hysteria2-\$PORT"
    echo "    type: hysteria2"
    echo "    server: $IP_ADDR"
    echo "    port: \$PORT"
    echo "    password: \$PASSWORD"
    echo "    obfs: none"
    echo "    skip-cert-verify: false"
done
EOF
chmod +x "$CONFIG_PATH/subscribe.sh"

cat > "/etc/systemd/system/hysteria-sub.service" <<EOF
[Unit]
Description=Hysteria2 Subscribe Server
After=network.target hysteria-$((NODE_COUNT - 1)).service

[Service]
Type=simple
User=root
WorkingDirectory=$CONFIG_PATH
ExecStart=/usr/bin/python3 -m http.server $SUBSCRIBE_PORT --bind $IP_ADDR
Restart=always
StandardOutput=journal

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable hysteria-sub >/dev/null 2>&1
systemctl start hysteria-sub

## [8/8] 完成
echo "[8/8] 部署完成！"
echo "=========================================="
echo "Hysteria2 节点状态:"
systemctl status hysteria-0 | grep "Active:"
echo "------------------------------------------"
echo "Clash Meta 订阅链接 (请确保 $SUBSCRIBE_PORT 端口已放行):"
echo "http://$IP_ADDR:$SUBSCRIBE_PORT/subscribe.sh"
echo "------------------------------------------"
echo "所有节点已部署，端口范围: $PORT_START - $((PORT_START + NODE_COUNT - 1))"
echo "证书路径: $CERT_PATH"
echo "=========================================="
