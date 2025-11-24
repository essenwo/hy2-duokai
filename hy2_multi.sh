#!/usr/bin/env bash
set -euo pipefail

# ===== 可改参数（循环外）=====
COUNT=5                               # **修改为：要生成的节点数量 (5条)**
HY2_PORT_START="${HY2_PORT_START:-30001}" # Hysteria2 起始 UDP 端口
NAME_TAG_BASE="${NAME_TAG_BASE:-MyHysteria_}" # 节点名称前缀

CLASH_WEB_DIR="${CLASH_WEB_DIR:-/etc/hysteria}" # 订阅文件存放目录
HTTP_PORT="${HTTP_PORT:-8080}"                   # Nginx 监听的 HTTP 端口

# ---- helper: escape replacement for sed (escape & and / and @ and newline) ----
escape_for_sed() {
  printf '%s' "$1" | sed -e 's/[\/&@]/\\&/g' -e ':a' -e 'N' -e '$!ba' -e 's/\n/\\n/g'
}

# ===========================
# 0) 获取公网 IPv4 并安装依赖
# ===========================
echo "[INFO] 模式 1：全新安装 ${COUNT} 个节点"

# 获取 IP
SELECTED_IP="$(ip -4 addr show scope global | awk '/inet /{print $2}' | head -n1 | cut -d/ -f1 || true)"
if [ -z "${SELECTED_IP}" ]; then
  echo "[ERR] 未检测到公网 IPv4，脚本退出"
  exit 1
fi
echo "[OK] 使用 IP: ${SELECTED_IP}"

# 安装依赖
export DEBIAN_FRONTEND=noninteractive
pkgs=(curl jq openssl python3 nginx)
MISSING=0
for p in "${pkgs[@]}"; do
  if ! command -v "$p" >/dev/null 2>&1; then MISSING=1; break; fi
done
if [ "$MISSING" -eq 1 ]; then
  echo "[*] 安装依赖..."
  apt-get update -y >/dev/null 2>&1
  apt-get install -y "${pkgs[@]}" >/dev/null 2>&1
fi

# ===========================
# 1) 生成域名/IP 并安装 Hysteria 二进制
# ===========================
IP_DASH="${SELECTED_IP//./-}"
HY2_DOMAIN="${IP_DASH}.sslip.io" # 简化：直接使用 sslip.io
echo "[OK] 使用域名/IP：${HY2_DOMAIN} -> ${SELECTED_IP}"

# 安装 hysteria 二进制
if ! command -v hysteria >/dev/null 2>&1; then
  echo "[*] 安装 hysteria ..."
  # 逻辑与原脚本一致
  arch="$(uname -m)"; asset="hysteria-linux-amd64"
  case "$arch" in aarch64|arm64) asset="hysteria-linux-arm64" ;; esac
  ver="$(curl -fsSL https://api.github.com/repos/apernet/hysteria/releases/latest | jq -r '.tag_name')"
  curl -fL "https://github.com/apernet/hysteria/releases/download/${ver}/${asset}" -o /usr/local/bin/hysteria
  chmod +x /usr/local/bin/hysteria
fi

# ===========================
# 2) 检查或申请证书 (一次性操作)
# ===========================
mkdir -p /etc/hysteria
HY2_CONFIG_BASE="/etc/hysteria/base_config.yaml"
USE_EXISTING_CERT=0
USE_CERT_PATH=""
USE_KEY_PATH=""
ACME_BASE="/acme"

# 证书扫描逻辑（与原脚本一致）
if [ -d "$ACME_BASE" ]; then
  while IFS= read -r -d '' cert_dir; do
    FULLCHAIN="${cert_dir}/fullchain.pem"
    PRIVKEY="${cert_dir}/privkey.pem"
    if [ -f "$FULLCHAIN" ] && [ -f "$PRIVKEY" ]; then
      USE_EXISTING_CERT=1
      USE_CERT_PATH="$FULLCHAIN"
      USE_KEY_PATH="$PRIVKEY"
      echo "[OK] 检测到现有证书：$FULLCHAIN"
      break
    fi
  done < <(find "$ACME_BASE" -type d -print0)
fi

# 生成一个临时的基础配置用于 ACME 申请
if [ "$USE_EXISTING_CERT" -eq 0 ]; then
  echo "[INFO] /acme 下未找到证书，尝试 ACME HTTP-01..."
  cat >"${HY2_CONFIG_BASE}" <<EOF
listen: :${HY2_PORT_START} # 仅用于 ACME 申请
auth:
  type: password
  password: acme_temp_pass
obfs:
  type: salamander
  salamander:
    password: acme_temp_obfs
acme:
  domains:
    - ${HY2_DOMAIN}
  disable_http_challenge: false
  disable_tlsalpn_challenge: true
EOF
  # 部署并运行一次服务申请证书 (hysteria-acme.service)
  cat >/etc/systemd/system/hysteria-acme.service <<'SVC'
[Unit]
Description=Hysteria ACME Client (Temp)
After=network.target

[Service]
User=root
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
AmbientCapabilities=CAP_NET_BIND_SERVICE
ExecStart=/usr/local/bin/hysteria server -c /etc/hysteria/base_config.yaml
Restart=on-failure
RestartSec=3

[Install]
WantedBy=multi-user.target
SVC
  systemctl daemon-reload
  systemctl enable --now hysteria-acme
  
  # 等待 ACME 成功 (最多 60 秒)
  TRIES=0; ACME_OK=0
  echo "[*] 等待 ACME 证书申请完成（最多 60 秒）..."
  while [ $TRIES -lt 12 ]; do
    if journalctl -u hysteria-acme --no-pager -n 200 | grep -E -iq "(certificate obtained successfully|authorization finalized|acme.*valid)"; then
      ACME_OK=1
      break
    fi
    sleep 5
    TRIES=$((TRIES+1))
  done
  
  # 停止临时服务
  systemctl disable --now hysteria-acme 2>/dev/null || true
  rm -f /etc/systemd/system/hysteria-acme.service
  
  if [ "$ACME_OK" -ne 1 ]; then
    echo "[ERROR] ACME 证书申请失败或超时，请检查 80 端口是否开放！"
    exit 1
  fi
  echo "[OK] ACME 证书申请成功"

  # 重新扫描获取新证书路径
  while IFS= read -r -d '' cert_dir; do
    FULLCHAIN="${cert_dir}/fullchain.pem"
    PRIVKEY="${cert_dir}/privkey.pem"
    if [ -f "$FULLCHAIN" ] && [ -f "$PRIVKEY" ]; then
      USE_EXISTING_CERT=1
      USE_CERT_PATH="$FULLCHAIN"
      USE_KEY_PATH="$PRIVKEY"
      break
    fi
  done < <(find "$ACME_BASE" -type d -print0)
fi

# ===========================
# 3) 循环部署 5 个 Hysteria 2 节点
# ===========================
echo
echo "=== 开始部署 ${COUNT} 个 Hysteria 2 实例 ==="

for ((i = 1; i <= COUNT; i++)); do
  HY2_PORT=$((HY2_PORT_START + i - 1))
  SERVICE_NAME="hysteria-server-${i}"
  CONFIG_PATH="/etc/hysteria/config_${i}.yaml"
  YAML_PATH="${CLASH_WEB_DIR}/clash_subscription_${i}.yaml"
  NAME_TAG="${NAME_TAG_BASE}${i}"

  # 随机生成密码 (每次循环都不同)
  HY2_PASS="$(openssl rand -hex 16)"
  OBFS_PASS="$(openssl rand -hex 8)"

  echo "[$i/$COUNT] 部署节点: 端口 ${HY2_PORT}, 服务名 ${SERVICE_NAME}"

  # 写 hysteria 配置（使用已找到的证书）
  cat >"${CONFIG_PATH}" <<EOF
listen: :${HY2_PORT}

auth:
  type: password
  password: ${HY2_PASS}

obfs:
  type: salamander
  salamander:
    password: ${OBFS_PASS}

tls:
  cert: ${USE_CERT_PATH}
  key: ${USE_KEY_PATH}
EOF
  echo "  - 配置写入: ${CONFIG_PATH}"

  # systemd 服务
  cat >/etc/systemd/system/"${SERVICE_NAME}".service <<SVC
[Unit]
Description=Hysteria Server ${i}
After=network.target

[Service]
User=root
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
AmbientCapabilities=CAP_NET_BIND_SERVICE
ExecStart=/usr/local/bin/hysteria server -c ${CONFIG_PATH}
Restart=on-failure
RestartSec=3

[Install]
WantedBy=multi-user.target
SVC

  systemctl daemon-reload
  systemctl enable --now "${SERVICE_NAME}"
  echo "  - 服务启动: ${SERVICE_NAME}"

  # 构造 URI (供调试或非Clash客户端使用)
  PASS_ENC="$(python3 -c "import sys,urllib.parse as u; print(u.quote(sys.argv[1], safe=''))" "$HY2_PASS")"
  OBFS_ENC="$(python3 -c "import sys,urllib.parse as u; print(u.quote(sys.argv[1], safe=''))" "$OBFS_PASS")"
  NAME_ENC="$(python3 -c "import sys,urllib.parse as u; print(u.quote(sys.argv[1], safe=''))" "$NAME_TAG")"
  URI_i="hysteria2://${PASS_ENC}@${SELECTED_IP}:${HY2_PORT}/?protocol=udp&obfs=salamander&obfs-password=${OBFS_ENC}&sni=${HY2_DOMAIN}&insecure=0#${NAME_ENC}"
  
  echo "  - URI: ${URI_i}"

  # 生成 Clash 订阅（YAML）
  cat > "${YAML_PATH}.tmp" <<'EOF'
mixed-port: 7890
allow-lan: true
bind-address: '*'
mode: rule
log-level: info
external-controller: '127.0.0.1:9090'

dns:
  enable: true
  ipv6: false
  default-nameserver:
    - 223.5.5.5
    - 8.8.8.8
  enhanced-mode: fake-ip
  fake-ip-range: 198.18.0.1/16
  nameserver:
    - https://doh.pub/dns-query
    - https://dns.alidns.com/dns-query

proxies:
  - name: "__NAME_TAG__"
    type: hysteria2
    server: __SELECTED_IP__
    port: __HY2_PORT__
    password: __HY2_PASS__
    obfs: salamander
    obfs-password: __OBFS_PASS__
    sni: __HY2_DOMAIN__

proxy-groups:
  - name: "🚀 节点选择"
    type: select
    proxies:
      - "__NAME_TAG__"
      - DIRECT

rules:
  - DOMAIN-SUFFIX,cn,DIRECT
  - DOMAIN-KEYWORD,baidu,DIRECT
  - DOMAIN-KEYWORD,taobao,DIRECT
  - DOMAIN-KEYWORD,qq,DIRECT
  - DOMAIN-KEYWORD,weixin,DIRECT
  - DOMAIN-KEYWORD,alipay,DIRECT
  - GEOIP,CN,DIRECT
  - MATCH,🚀 节点选择
EOF

  # 执行变量替换
  TMPF="${YAML_PATH}.tmp"
  TARGET="${YAML_PATH}"
  
  NAME_ESC="$(escape_for_sed "${NAME_TAG}")"
  IP_ESC="$(escape_for_sed "${SELECTED_IP}")"
  PORT_ESC="$(escape_for_sed "${HY2_PORT}")"
  PASS_ESC="$(escape_for_sed "${HY2_PASS}")"
  OBFS_ESC="$(escape_for_sed "${OBFS_PASS}")"
  DOMAIN_ESC="$(escape_for_sed "${HY2_DOMAIN}")"
  
  sed -e "s@__NAME_TAG__@${NAME_ESC}@g" \
      -e "s@__SELECTED_IP__@${IP_ESC}@g" \
      -e "s@__HY2_PORT__@${PORT_ESC}@g" \
      -e "s@__HY2_PASS__@${PASS_ESC}@g" \
      -e "s@__OBFS_PASS__@${OBFS_ESC}@g" \
      -e "s@__HY2_DOMAIN__@${DOMAIN_ESC}@g" \
      "${TMPF}" > "${TARGET}"
  rm -f "${TMPF}"
  
  echo "  - Clash 订阅生成: ${TARGET}"
  echo
done

# ===========================
# 4) 配置 nginx 提供订阅
# ===========================

cat >/etc/nginx/sites-available/clash.conf <<EOF
server {
    listen ${HTTP_PORT} default_server;
    listen [::]:${HTTP_PORT} default_server;

    root ${CLASH_WEB_DIR};

    # 匹配 clash_subscription_1.yaml 到 clash_subscription_5.yaml
    location ~ /clash_subscription_[1-5]\.yaml$ {
        default_type application/x-yaml;
        try_files \$uri =404;
    }

    access_log /var/log/nginx/clash_access.log;
    error_log /var/log/nginx/clash_error.log;
}
EOF

ln -sf /etc/nginx/sites-available/clash.conf /etc/nginx/sites-enabled/clash.conf
nginx -t
systemctl restart nginx

echo "================================================="
echo "✅ 部署成功！共生成 ${COUNT} 个 Hysteria 2 节点"
echo "================================================="
echo "所有节点共享相同的证书和域名：${HY2_DOMAIN}"
echo "Nginx 订阅服务端口：${HTTP_PORT}"
echo "-------------------------------------------------"

for ((i = 1; i <= COUNT; i++)); do
  HY2_PORT=$((HY2_PORT_START + i - 1))
  echo "🚀 节点 ${i} (端口 ${HY2_PORT}) 的订阅链接："
  echo "    http://${SELECTED_IP}:${HTTP_PORT}/clash_subscription_${i}.yaml"
done
echo "-------------------------------------------------"
