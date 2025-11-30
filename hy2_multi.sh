#!/usr/bin/env bash
set -euo pipefail

# ===== 可改参数 =====
# 修改为端口数组，用于创建5个不同端口的实例
HY2_PORTS=(20000 20001 20002 20003 20004)
HY2_PASS="${HY2_PASS:-}"              # HY2 密码（所有端口共享，留空自动生成）
OBFS_PASS="${OBFS_PASS:-}"            # 混淆密码（所有端口共享，留空自动生成）
NAME_TAG="${NAME_TAG:-MyHysteria}"    # 节点名称前缀
PIN_SHA256="${PIN_SHA256:-}"          # 证书指纹（可留空）

CLASH_WEB_DIR="/etc/hysteria" # 将 Clash 订阅文件也放在 /etc/hysteria
HTTP_PORT="${HTTP_PORT:-80}"  # 您已开启80端口，默认使用80

# ---- helper: escape replacement for sed (escape & and / and @ and newline) ----
escape_for_sed() {
  printf '%s' "$1" | sed -e 's/[\/&@]/\\&/g' -e ':a' -e 'N' -e '$!ba' -e 's/\n/\\n/g'
}

# ===========================
# helper: 定义定时维护任务（每天清缓存+硬重启）
# ===========================
setup_auto_reboot_cron() {
  if [ "${ENABLE_AUTO_REBOOT_CACHE:-1}" != "1" ]; then
    echo "[INFO] 自动维护任务已禁用（ENABLE_AUTO_REBOOT_CACHE=0）"
    return 0
  fi
  local SHUTDOWN_BIN; SHUTDOWN_BIN="$(command -v shutdown || echo /sbin/shutdown)"
  local SYNC_BIN; SYNC_BIN="$(command -v sync || echo /usr/bin/sync)"
  local DROP_CACHES="/proc/sys/vm/drop_caches"
  if [ ! -w "$DROP_CACHES" ]; then echo "[WARN] 无法写入 $DROP_CACHES"; fi
  local CRON_LINE="0 3 * * * ${SYNC_BIN} && echo 3 > ${DROP_CACHES} && ${SHUTDOWN_BIN} -r now"
  if ! command -v crontab >/dev/null; then
      if command -v apt-get >/dev/null; then
        echo "[INFO] 安装 cron..."
        DEBIAN_FRONTEND=noninteractive apt-get update >/dev/null 2>&1 && apt-get install -y cron >/dev/null 2>&1
      else
        echo "[WARN] 未找到 crontab 且无法自动安装。"
      fi
  fi
  if command -v crontab >/dev/null; then
    (crontab -l 2>/dev/null | grep -Fv "$CRON_LINE"; echo "$CRON_LINE") | crontab -
    echo "[OK] 已添加 root 定时任务：每天 03:00 清缓存并重启"
  fi
}


# ===========================
# 模式选择
# ===========================
SCRIPT_MODE="${SCRIPT_MODE:-}"
if [ -z "$SCRIPT_MODE" ] && [ -t 0 ]; then
  # 接收用户输入，y/Y/1 都视为模式1
  read -r -p "请选择模式: 1) 全新安装  2) 仅添加每天自动清缓存+硬重启 [默认1]: " SCRIPT_MODE || true
fi
case "${SCRIPT_MODE}" in
  2) echo "[INFO] 模式2：仅添加维护任务"; setup_auto_reboot_cron; echo "[OK] 任务已添加"; exit 0 ;;
  *) echo "[INFO] 模式1：全新安装" ;;
esac

# ===========================
# 0) 获取公网 IPv4 (已优化，可适应内网/公网环境)
# ===========================
echo "[*] 正在检测 IP 地址..."
# 优先尝试从本机网络接口获取
LOCAL_IP="$(ip -4 addr show scope global | awk '/inet /{print $2}' | head -n1 | cut -d/ -f1 || true)"
IS_PRIVATE=0
case "${LOCAL_IP}" in
    10.*|192.168.*|172.1[6-9].*|172.2[0-9].*|172.3[0-1].*) IS_PRIVATE=1 ;;
esac
if [ "$IS_PRIVATE" -eq 1 ] || [ -z "$LOCAL_IP" ]; then
    echo "[INFO] 本地IP (${LOCAL_IP:-"未找到"}) 为内网IP，尝试从外部服务获取公网IP..."
    SELECTED_IP=$(curl -s4 --connect-timeout 5 ifconfig.me || curl -s4 --connect-timeout 5 api.ipify.org || curl -s4 --connect-timeout 5 ip.sb)
else
    echo "[INFO] 本地检测到公网IP: ${LOCAL_IP}"
    SELECTED_IP="$LOCAL_IP"
fi
if [ -z "${SELECTED_IP}" ]; then
  echo "[ERR] 无法通过任何方式获取到有效的公网 IPv4 地址，脚本退出。" >&2; exit 1
fi
echo "[OK] 确认使用公网 IP: ${SELECTED_IP}"


# ===========================
# 1) 安装依赖
# ===========================
export DEBIAN_FRONTEND=noninteractive
pkgs=(curl jq openssl python3 nginx systemd)
# 检查 systemd-journald 是否需要单独处理
if ! command -v journalctl >/dev/null; then pkgs+=(systemd-container); fi

NEEDS_INSTALL=0
for p in "${pkgs[@]}"; do
  if ! dpkg -s "$p" >/dev/null 2>&1; then NEEDS_INSTALL=1; break; fi
done
if [ "$NEEDS_INSTALL" -eq 1 ]; then
  echo "[*] 正在安装缺失的依赖包..."
  apt-get update -y && apt-get install -y "${pkgs[@]}"
fi

# ===========================
# 2) 生成域名
# ===========================
IP_DASH="${SELECTED_IP//./-}"
DOMAIN_SERVICES=("sslip.io" "nip.io")
HY2_DOMAIN=""
for service in "${DOMAIN_SERVICES[@]}"; do
  test_domain="${IP_DASH}.${service}"
  echo "[*] 测试 ${service}: ${test_domain}"
  resolved_ip="$(getent ahostsv4 "$test_domain" 2>/dev/null | awk '{print $1}' | head -n1 || true)"
  if [ "$resolved_ip" = "$SELECTED_IP" ]; then
    HY2_DOMAIN="$test_domain"
    echo "[OK] ${service} 解析正常: ${test_domain}"
    break
  else
    echo "[WARN] ${service} 解析失败或不匹配"
  fi
done
if [ -z "$HY2_DOMAIN" ]; then
  HY2_DOMAIN="${IP_DASH}.sslip.io"
  echo "[WARN] 所有域名服务均无法正确解析。将使用 ${HY2_DOMAIN}，ACME 可能失败。"
fi
echo "[OK] 使用域名: ${HY2_DOMAIN}"

# ===========================
# 3) 安装 hysteria 二进制
# ===========================
if ! command -v hysteria >/dev/null; then
  echo "[*] 安装 hysteria ..."
  arch="$(uname -m)"; case "$arch" in x86_64|amd64) asset="hysteria-linux-amd64" ;; aarch64|arm64) asset="hysteria-linux-arm64" ;; *) asset="hysteria-linux-amd64" ;; esac
  ver="$(curl -fsSL https://api.github.com/repos/apernet/hysteria/releases/latest | jq -r '.tag_name')"
  curl -fL "https://github.com/apernet/hysteria/releases/download/${ver}/${asset}" -o /usr/local/bin/hysteria
  chmod +x /usr/local/bin/hysteria
fi

# ===========================
# 4) 密码生成
# ===========================
if [ -z "${HY2_PASS}" ]; then HY2_PASS="$(openssl rand -hex 16)"; fi
if [ -z "${OBFS_PASS}" ]; then OBFS_PASS="$(openssl rand -hex 8)"; fi

# ===========================
# 5) 在 /acme 下扫描现有证书
# ===========================
USE_EXISTING_CERT=0; USE_CERT_PATH=""; USE_KEY_PATH=""
CERT_SEARCH_PATHS=("/acme" "/etc/hysteria/certs/certs")
for path in "${CERT_SEARCH_PATHS[@]}"; do
    if [ -d "$path" ]; then
        FOUND_DIR=$(find "$path" -type f -name "fullchain.pem" -exec dirname {} \; -print -quit)
        if [ -n "$FOUND_DIR" ] && [ -f "${FOUND_DIR}/fullchain.pem" ] && ([ -f "${FOUND_DIR}/privkey.pem" ] || [ -f "${FOUND_DIR}/private.key" ]); then
            USE_EXISTING_CERT=1
            USE_CERT_PATH="${FOUND_DIR}/fullchain.pem"
            if [ -f "${FOUND_DIR}/privkey.pem" ]; then USE_KEY_PATH="${FOUND_DIR}/privkey.pem"; else USE_KEY_PATH="${FOUND_DIR}/private.key"; fi
            echo "[OK] 检测到现有证书: ${USE_CERT_PATH}"
            break
        fi
    fi
done

# ===========================
# 6, 7, 8) 创建 Hysteria 配置, Systemd 服务并启动
# ===========================
mkdir -p /etc/hysteria/certs

# 6.1) 创建 Systemd 模板服务
cat >/etc/systemd/system/hysteria-server@.service <<'SVC'
[Unit]
Description=Hysteria Server (Port %i)
After=network.target
[Service]
User=root
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
AmbientCapabilities=CAP_NET_BIND_SERVICE
ExecStart=/usr/local/bin/hysteria server -c /etc/hysteria/config-%i.yaml
Restart=on-failure
RestartSec=3
[Install]
WantedBy=multi-user.target
SVC
systemctl daemon-reload

# 6.2) 根据证书情况，处理所有端口的配置和启动
if [ "$USE_EXISTING_CERT" -eq 1 ]; then
  echo "[INFO] 使用现有证书为所有端口配置..."
  for port in "${HY2_PORTS[@]}"; do
    echo "[*] 为端口 ${port} 生成配置文件..."
    cat >"/etc/hysteria/config-${port}.yaml" <<EOF
listen: :${port}
auth: {type: password, password: ${HY2_PASS}}
obfs: {type: salamander, salamander: {password: ${OBFS_PASS}}}
tls: {cert: ${USE_CERT_PATH}, key: ${USE_KEY_PATH}}
EOF
  done
  echo "[*] 启动所有 Hysteria 服务..."
  for port in "${HY2_PORTS[@]}"; do systemctl enable --now "hysteria-server@${port}"; done
else
  PRIMARY_PORT=${HY2_PORTS[0]}
  echo "[INFO] 未找到证书，将使用端口 ${PRIMARY_PORT} 进行 ACME 申请..."
  
  cat >"/etc/hysteria/config-${PRIMARY_PORT}.yaml" <<EOF
listen: :${PRIMARY_PORT}
auth: {type: password, password: ${HY2_PASS}}
obfs: {type: salamander, salamander: {password: ${OBFS_PASS}}}
acme:
  domains: [- ${HY2_DOMAIN}]
  email: user@example.com
  storage: /etc/hysteria/certs
  disable_http_challenge: false
  disable_tlsalpn_challenge: true
EOF

  # 【关键改进】确保日志服务可用
  echo "[*] 正在检查并确保日志服务 (journald) 正常运行..."
  mkdir -p /var/log/journal && systemctl restart systemd-journald
  sleep 2

  echo "[*] 启动主服务 (hysteria-server@${PRIMARY_PORT}) 以申请证书..."
  systemctl enable --now "hysteria-server@${PRIMARY_PORT}"
  
  echo "[*] 等待 ACME 证书申请完成（最多 90 秒）..."
  TRIES=0; ACME_OK=0; CERT_FILE="/etc/hysteria/certs/certs/${HY2_DOMAIN}/fullchain.pem"
  
  while [ $TRIES -lt 18 ]; do
    # 【关键改进】方法一：检查日志
    if journalctl -u "hysteria-server@${PRIMARY_PORT}" --no-pager --since "5 minutes ago" | grep -iq "acme: certificate obtained successfully"; then
      echo "[INFO] 在日志中检测到证书申请成功！"
      ACME_OK=1; break
    fi
    # 【关键改进】方法二：检查证书文件是否已生成（更可靠）
    if [ -f "$CERT_FILE" ]; then
      echo "[INFO] 检测到证书文件已生成！"
      ACME_OK=1; break
    fi
    sleep 5; TRIES=$((TRIES+1))
  done

  if [ "$ACME_OK" -ne 1 ]; then echo "[ERROR] ACME 证书申请失败，请检查日志: journalctl -u hysteria-server@${PRIMARY_PORT}" >&2; exit 1; fi
  
  echo "[OK] ACME 证书申请成功！"
  USE_CERT_PATH="/etc/hysteria/certs/certs/${HY2_DOMAIN}/fullchain.pem"
  USE_KEY_PATH="/etc/hysteria/certs/certs/${HY2_DOMAIN}/private.key"

  echo "[*] 为其余端口配置并启动服务..."
  for port in "${HY2_PORTS[@]}"; do
    if [ "$port" -eq "$PRIMARY_PORT" ]; then continue; fi
    cat >"/etc/hysteria/config-${port}.yaml" <<EOF
listen: :${port}
auth: {type: password, password: ${HY2_PASS}}
obfs: {type: salamander, salamander: {password: ${OBFS_PASS}}}
tls: {cert: ${USE_CERT_PATH}, key: ${USE_KEY_PATH}}
EOF
    systemctl enable --now "hysteria-server@${port}"
  done
fi

sleep 3
setup_auto_reboot_cron

LISTEN_PORTS_GREP=$(IFS="|"; echo "${HY2_PORTS[*]}")
echo "=== 监听检查 (UDP/${LISTEN_PORTS_GREP}) ==="
ss -lunp | grep -E ":(${LISTEN_PORTS_GREP})\b" || echo "[WARN] 未在 ss 中检测到所有监听端口。"

# ===========================
# 9, 10) 构造 URI 和 Clash 订阅
# ===========================
echo -e "\n============================================================"
echo "=========== Hysteria2 配置信息 (共 ${#HY2_PORTS[@]} 个) ==========="
echo "============================================================"

PASS_ENC="$(python3 -c "import urllib.parse as u, sys; print(u.quote(sys.argv[1]))" "$HY2_PASS")"
OBFS_ENC="$(python3 -c "import urllib.parse as u, sys; print(u.quote(sys.argv[1]))" "$OBFS_PASS")"
PIN_ENC="$(python3 -c "import urllib.parse as u, sys; print(u.quote(sys.argv[1]))" "${PIN_SHA256:-}")"

CLASH_TEMPLATE=$(cat <<'EOF'
mixed-port: 7890
allow-lan: true
mode: rule
log-level: info
external-controller: 127.0.0.1:9090
dns: {enable: true, ipv6: false, default-nameserver: [223.5.5.5, 8.8.8.8], enhanced-mode: fake-ip, fake-ip-range: 198.18.0.1/16, nameserver: [https://doh.pub/dns-query, https://dns.alidns.com/dns-query]}
proxies:
  - {name: "__NAME_TAG__", type: hysteria2, server: __SELECTED_IP__, port: __HY2_PORT__, password: __HY2_PASS__, obfs: salamander, obfs-password: __OBFS_PASS__, sni: __HY2_DOMAIN__}
proxy-groups:
  - {name: "🚀 节点选择", type: select, proxies: ["__NAME_TAG__", DIRECT]}
rules:
  - DOMAIN-SUFFIX,cn,DIRECT
  - GEOIP,CN,DIRECT
  - MATCH,🚀 节点选择
EOF
)

for port in "${HY2_PORTS[@]}"; do
  CURRENT_NAME_TAG="${NAME_TAG}-${port}"
  NAME_ENC="$(python3 -c "import urllib.parse as u, sys; print(u.quote(sys.argv[1]))" "$CURRENT_NAME_TAG")"
  
  URI="hysteria2://${PASS_ENC}@${SELECTED_IP}:${port}/?protocol=udp&obfs=salamander&obfs-password=${OBFS_ENC}&sni=${HY2_DOMAIN}&insecure=0&pinSHA256=${PIN_ENC}#${NAME_ENC}"
  
  echo -e "\n--- 端口: ${port} ---"
  echo "Hysteria2 URI: ${URI}"
  
  TARGET_CLASH_FILE="${CLASH_WEB_DIR}/clash_sub_${port}.yaml"
  
  NAME_ESC="$(escape_for_sed "${CURRENT_NAME_TAG}")"
  IP_ESC="$(escape_for_sed "${SELECTED_IP}")"
  PORT_ESC="$(escape_for_sed "${port}")"
  PASS_ESC="$(escape_for_sed "${HY2_PASS}")"
  OBFS_ESC="$(escape_for_sed "${OBFS_PASS}")"
  DOMAIN_ESC="$(escape_for_sed "${HY2_DOMAIN}")"

  echo "$CLASH_TEMPLATE" | \
    sed -e "s@__NAME_TAG__@${NAME_ESC}@g" -e "s@__SELECTED_IP__@${IP_ESC}@g" \
        -e "s@__HY2_PORT__@${PORT_ESC}@g" -e "s@__HY2_PASS__@${PASS_ESC}@g" \
        -e "s@__OBFS_PASS__@${OBFS_ESC}@g" -e "s@__HY2_DOMAIN__@${DOMAIN_ESC}@g" > "${TARGET_CLASH_FILE}"
        
  echo "Clash 订阅: http://${SELECTED_IP}:${HTTP_PORT}/clash/${port}.yaml"
done

# ===========================
# 11) 配置 nginx 提供订阅
# ===========================
echo -e "\n[*] 配置 nginx 提供 Clash 订阅..."
cat >/etc/nginx/sites-available/clash.conf <<EOF
server {
    listen ${HTTP_PORT} default_server;
    listen [::]:${HTTP_PORT} default_server;
    root ${CLASH_WEB_DIR};
    index index.html;
    location ~ ^/clash/(\d+)\.yaml$ {
        default_type application/x-yaml;
        try_files /clash_sub_\$1.yaml =404;
    }
    location = / {
        default_type text/html;
        return 200 '<html><head><title>Clash Subscriptions</title></head><body><h1>Hysteria2 Clash Subscriptions</h1><ul><li><a href="http://${SELECTED_IP}:${HTTP_PORT}/clash/20000.yaml">Port 20000</a></li><li><a href="http://${SELECTED_IP}:${HTTP_PORT}/clash/20001.yaml">Port 20001</a></li><li><a href="http://${SELECTED_IP}:${HTTP_PORT}/clash/20002.yaml">Port 20002</a></li><li><a href="http://${SELECTED_IP}:${HTTP_PORT}/clash/20003.yaml">Port 20003</a></li><li><a href="http://${SELECTED_IP}:${HTTP_PORT}/clash/20004.yaml">Port 20004</a></li></ul></body></html>';
    }
    access_log /var/log/nginx/clash_access.log;
    error_log /var/log/nginx/clash_error.log;
}
EOF

if [ -L /etc/nginx/sites-enabled/default ]; then
    echo "[INFO] 删除默认 Nginx 站点以避免端口冲突..."
    rm -f /etc/nginx/sites-enabled/default
fi
ln -sf /etc/nginx/sites-available/clash.conf /etc/nginx/sites-enabled/clash.conf
if nginx -t; then
  systemctl restart nginx
else
  echo "[ERROR] Nginx 配置测试失败: nginx -t" >&2; exit 1
fi

echo -e "\n============================================================"
echo "[OK] 所有服务已配置完毕！"
echo "您可以访问 http://${SELECTED_IP}:${HTTP_PORT}/ 来查看所有订阅链接。"
echo "============================================================"

