#!/usr/bin/env bash
set -euo pipefail

# =============================================================
# 整合版 Hysteria2 一键脚本 (修正版)
# 功能：
# 1. 自动安装 Hysteria2 并配置多端口
# 2. 自动安装 Cloudflare WARP (Proxy模式)
# 3. 配置 Hysteria2 分流：领英(LinkedIn)走 WARP，其他走直连
# 4. 自动生成 Clash 订阅并由 Nginx 托管
# =============================================================

# ===== 可改参数 =====
HY2_PORT="${HY2_PORT:-8443}"          # Hysteria2 主端口
HY2_PORTS="${HY2_PORTS:-}"            # 多端口列表（逗号分隔，留空则使用计数生成）
HY2_PORT_COUNT="${HY2_PORT_COUNT:-}"  # 端口数量（交互式输入会覆盖此值）
HY2_PASS="${HY2_PASS:-}"              # 密码（留空自动生成）
OBFS_PASS="${OBFS_PASS:-}"            # 混淆密码（留空自动生成）
NAME_TAG="${NAME_TAG:-MyHysteria}"    # 节点名称

CLASH_WEB_DIR="${CLASH_WEB_DIR:-/etc/hysteria}"
CLASH_OUT_PATH="${CLASH_OUT_PATH:-${CLASH_WEB_DIR}/clash_subscription.yaml}"
HTTP_PORT="${HTTP_PORT:-8080}"

# ---- helper: 特殊字符转义 ----
escape_for_sed() {
  printf '%s' "$1" | sed -e 's@[\/&@]@\\&@g' -e ':a' -e 'N' -e '$!ba' -e 's/\n/\\n/g'
}

# ---- helper: 交互式询问端口数量 ----
maybe_init_ports_from_input() {
  if [ -n "${HY2_PORTS:-}" ]; then return 0; fi

  local count="${HY2_PORT_COUNT:-}"
  # 交互式询问逻辑
  if [ -z "$count" ] && [ -t 0 ]; then
    echo "======================================================="
    echo "   多端口生成设置"
    echo "======================================================="
    read -r -p "请输入需要生成的订阅链接(端口)数量 [默认1, 最大30]: " count || true
  fi

  case "${count:-}" in
    "" ) count=1 ;;
    *[!0-9]* ) count=1 ;;
  esac

  if [ "$count" -lt 1 ]; then count=1; fi
  if [ "$count" -gt 30 ]; then count=30; fi

  # 生成连续端口列表
  local base="$HY2_PORT"
  local out="$base"
  local i=1
  while [ "$i" -lt "$count" ]; do
    local next=$((base + i))
    if [ "$next" -gt 65535 ]; then break; fi
    out="${out},${next}"
    i=$((i + 1))
  done
  HY2_PORTS="$out"
  echo "[OK] 将配置以下端口：${HY2_PORTS}"
}

# ---- helper: 解析端口列表 ----
parse_port_list() {
  local raw="${HY2_PORTS:-}"
  local out=""
  if [ -n "$raw" ]; then
    IFS=',' read -r -a parts <<<"$raw"
    for p in "${parts[@]}"; do
      p="$(echo "$p" | tr -d ' ' )"
      if echo "$p" | grep -Eq '^[0-9]{2,5}$'; then
        case ",$out," in
          *",$p,"*) ;;
          *) out="${out:+$out,}$p" ;;
        esac
      fi
    done
  fi
  if [ -z "$out" ]; then out="$HY2_PORT"; fi
  echo "$out"
}

# ---- helper: 生成密码 ----
gen_credentials_for_ports() {
  local list_csv="$1"
  declare -gA PASS_MAP
  declare -gA OBFS_MAP
  IFS=',' read -r -a ports <<<"$list_csv"
  for pt in "${ports[@]}"; do
    local pass obfs
    if [ "$pt" = "$HY2_PORT" ] && [ -n "${HY2_PASS:-}" ]; then
      pass="$HY2_PASS"
    else
      pass="$(openssl rand -hex 16)"
    fi
    if [ "$pt" = "$HY2_PORT" ] && [ -n "${OBFS_PASS:-}" ]; then
      obfs="$OBFS_PASS"
    else
      obfs="$(openssl rand -hex 8)"
    fi
    PASS_MAP[$pt]="$pass"
    OBFS_MAP[$pt]="$obfs"
  done
}

# =============================================================
# [核心新增] 安装并配置 WARP (Proxy模式)
# =============================================================
install_and_configure_warp() {
  echo ">>> 检查 WARP 环境..."
  if command -v warp-cli >/dev/null 2>&1; then
    # 检查本地代理端口是否通
    if curl -s -x socks5h://127.0.0.1:40000 https://www.cloudflare.com/cdn-cgi/trace | grep -q "warp=on"; then
      echo "[OK] WARP 已安装且代理端口 40000 正常，跳过安装。"
      return 0
    fi
  fi

  echo "[*] 开始安装 Cloudflare WARP..."
  if ! command -v gpg >/dev/null 2>&1; then apt-get install -y gnupg; fi
  
  # 添加源
  curl -fsSL https://pkg.cloudflareclient.com/pubkey.gpg | gpg --yes --dearmor --output /usr/share/keyrings/cloudflare-warp-archive-keyring.gpg
  echo "deb [arch=amd64 signed-by=/usr/share/keyrings/cloudflare-warp-archive-keyring.gpg] https://pkg.cloudflareclient.com/ $(lsb_release -cs) main" | tee /etc/apt/sources.list.d/cloudflare-client.list

  apt-get update -y
  apt-get install -y cloudflare-warp

  echo "[*] 注册并配置 WARP..."
  warp-cli --accept-tos registration new >/dev/null 2>&1 || true
  # 设置为 proxy 模式，不接管系统流量
  warp-cli --accept-tos mode proxy
  # 连接
  warp-cli --accept-tos connect
  
  sleep 5
  if curl -s -x socks5h://127.0.0.1:40000 https://www.cloudflare.com/cdn-cgi/trace | grep -q "warp=on"; then
    echo "[OK] WARP 安装成功且代理已启动 (Socks5: 40000)"
  else
    echo "[WARN] WARP 安装完成但连接测试失败，请手动检查 'warp-cli status'。"
  fi
}

# ---- [修改版] 写单端口配置（包含分流规则） ----
write_hysteria_config_for_port() {
  local port="$1"; local pass="$2"; local obfsp="$3"; local use_tls="$4"
  mkdir -p /etc/hysteria
  
  # 定义分流规则：领英走 warp_out，其他走 direct_out
  local RULES_BLOCK
  read -r -d '' RULES_BLOCK <<'CONFIG_END' || true
outbounds:
  - name: direct_out
    type: direct
  - name: warp_out
    type: socks5
    socks5:
      addr: 127.0.0.1:40000

acl:
  inline:
    - warp_out(domain:linkedin.com)
    - warp_out(domain:linkedin.cn)
    - warp_out(domain:www.linkedin.com)
    - warp_out(domain:scamalytics.com)
    - warp_out(domain:ip.sb)
    - direct_out(all)
CONFIG_END

  if [ "$use_tls" = "1" ]; then
    cat >"/etc/hysteria/config-${port}.yaml" <<EOF
listen: :${port}
protocol: udp
auth:
  type: password
  password: ${pass}
obfs:
  type: salamander
  salamander:
    password: ${obfsp}
tls:
  cert: ${USE_CERT_PATH}
  key: ${USE_KEY_PATH}
${RULES_BLOCK}
EOF
  else
    mkdir -p /acme/autocert
    cat >"/etc/hysteria/config-${port}.yaml" <<EOF
listen: :${port}
protocol: udp
auth:
  type: password
  password: ${pass}
obfs:
  type: salamander
  salamander:
    password: ${obfsp}
acme:
  domains:
    - ${HY2_DOMAIN}
  dir: /acme/autocert
  type: http
  listenHost: 0.0.0.0
${RULES_BLOCK}
EOF
  fi
}

# ---- [修改版] 写主端口配置（包含分流规则） ----
write_hysteria_main_config() {
  local use_tls="$1"
  mkdir -p /etc/hysteria /acme/autocert

  local RULES_BLOCK
  read -r -d '' RULES_BLOCK <<'CONFIG_END' || true
outbounds:
  - name: direct_out
    type: direct
  - name: warp_out
    type: socks5
    socks5:
      addr: 127.0.0.1:40000

acl:
  inline:
    - warp_out(domain:linkedin.com)
    - warp_out(domain:linkedin.cn)
    - warp_out(domain:www.linkedin.com)
    - warp_out(domain:scamalytics.com)
    - warp_out(domain:ip.sb)
    - direct_out(all)
CONFIG_END

  if [ "$use_tls" = "1" ]; then
    cat >/etc/hysteria/config.yaml <<EOF
listen: :${HY2_PORT}
protocol: udp
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
${RULES_BLOCK}
EOF
  else
    cat >/etc/hysteria/config.yaml <<EOF
listen: :${HY2_PORT}
protocol: udp
auth:
  type: password
  password: ${HY2_PASS}
obfs:
  type: salamander
  salamander:
    password: ${OBFS_PASS}
acme:
  domains:
    - ${HY2_DOMAIN}
  dir: /acme/autocert
  type: http
  listenHost: 0.0.0.0
${RULES_BLOCK}
EOF
  fi
}

# ---- Helper functions for Service Management ----

ensure_systemd_template() {
  cat >/etc/systemd/system/hysteria-server@.service <<'SVC'
[Unit]
Description=Hysteria Server (config-%i.yaml)
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
}

start_main_service_direct() {
  mkdir -p /var/log /var/run
  nohup /usr/local/bin/hysteria server -c /etc/hysteria/config.yaml >/var/log/hysteria-main.log 2>&1 &
}

start_port_service_direct() {
  local port="$1"
  mkdir -p /var/log /var/run
  nohup /usr/local/bin/hysteria server -c "/etc/hysteria/config-${port}.yaml" >/var/log/hysteria-${port}.log 2>&1 &
}

start_hysteria_instance() {
  local port="$1"
  if command -v systemctl >/dev/null 2>&1; then
    systemctl enable --now "hysteria-server@${port}" || true
  else
    start_port_service_direct "$port"
  fi
}

start_additional_instances_with_tls() {
  [ -n "${HY2_PORTS:-}" ] || return 0
  ensure_systemd_template
  IFS=',' read -r -a ports_all <<<"$PORT_LIST_CSV"
  for pt in "${ports_all[@]}"; do
    [ "$pt" = "$HY2_PORT" ] && continue
    # 此处调用已包含分流规则的 config writer
    write_hysteria_config_for_port "$pt" "${PASS_MAP[$pt]}" "${OBFS_MAP[$pt]}" "1"
    start_hysteria_instance "$pt"
  done
}

# ===========================
# 主逻辑开始
# ===========================

# 0. 模式选择
SCRIPT_MODE="${SCRIPT_MODE:-}"
if [ -z "$SCRIPT_MODE" ]; then
  if [ -t 0 ]; then
    read -r -p "模式: 1) 全新安装(含WARP+分流)  2) 仅维护 [默认1]: " SCRIPT_MODE || true
  else
    SCRIPT_MODE="1"
  fi
fi

if [ "${SCRIPT_MODE}" = "2" ]; then
  echo "维护模式...（此处省略维护代码，实际使用请完整复制原脚本维护部分）"
  exit 0
fi

# 1. 获取 IP
SELECTED_IP="$(ip -4 addr show scope global | awk '/inet /{print $2}' | head -n1 | cut -d/ -f1 || true)"
[ -z "${SELECTED_IP}" ] && exit 1
echo "[OK] 本机 IP: ${SELECTED_IP}"

# 2. 安装基础依赖
export DEBIAN_FRONTEND=noninteractive
pkgs=(curl jq openssl python3 nginx)
apt-get update -y
apt-get install -y "${pkgs[@]}"

# >>> [修复点] 安装完 Nginx 后立刻停止它，释放 80 端口给 Hysteria 申请证书用 <<<
systemctl stop nginx || true

# >>> [关键步骤] 安装 WARP <<<
install_and_configure_warp

# 3. 域名生成 (nip.io / sslip.io)
IP_DASH="${SELECTED_IP//./-}"
HY2_DOMAIN="${IP_DASH}.sslip.io"
echo "[OK] 使用域名: ${HY2_DOMAIN}"

# 4. 安装 Hysteria 二进制
if ! command -v hysteria >/dev/null 2>&1; then
  echo "[*] 下载安装 Hysteria..."
  curl -fsSL https://github.com/apernet/hysteria/releases/latest/download/hysteria-linux-amd64 -o /usr/local/bin/hysteria
  chmod +x /usr/local/bin/hysteria
fi

# 5. 端口与密码处理
maybe_init_ports_from_input
PORT_LIST_CSV="$(parse_port_list)"
gen_credentials_for_ports "$PORT_LIST_CSV"

# 6. 证书申请 (简化版逻辑)
mkdir -p /acme/autocert
USE_EXISTING_CERT=0

# 7. 写入配置并启动
echo "[*] 生成配置文件..."
# 尝试 ACME 启动 (80端口现在是空闲的，因为我们在第2步关掉了Nginx)
write_hysteria_main_config 0

cat >/etc/systemd/system/hysteria-server.service <<'SVC'
[Unit]
Description=Hysteria Server
After=network.target
[Service]
ExecStart=/usr/local/bin/hysteria server -c /etc/hysteria/config.yaml
Restart=on-failure
[Install]
WantedBy=multi-user.target
SVC
systemctl daemon-reload
systemctl enable --now hysteria-server || true

# 启动多端口
start_additional_instances_with_tls

# 8. 生成 Clash 订阅
mkdir -p "${CLASH_WEB_DIR}"
IFS=',' read -r -a clash_ports <<<"$PORT_LIST_CSV"

for pt in "${clash_ports[@]}"; do
  curr_pass="${PASS_MAP[$pt]}"
  curr_obfs="${OBFS_MAP[$pt]}"
  
  cat > "${CLASH_WEB_DIR}/clash_${pt}.yaml" <<EOF
port: 7890
socks-port: 7891
allow-lan: true
mode: rule
log-level: info
proxies:
  - name: "${NAME_TAG}_${pt}"
    type: hysteria2
    server: ${SELECTED_IP}
    port: ${pt}
    password: ${curr_pass}
    obfs: salamander
    obfs-password: ${curr_obfs}
    sni: ${HY2_DOMAIN}
proxy-groups:
  - name: "Select"
    type: select
    proxies:
      - "${NAME_TAG}_${pt}"
      - DIRECT
rules:
  - DOMAIN-SUFFIX,cn,DIRECT
  - GEOIP,CN,DIRECT
  - MATCH,Select
EOF
  echo ">>> 生成订阅: http://${SELECTED_IP}:${HTTP_PORT}/clash_${pt}.yaml"
done

# 9. Nginx 配置
# 配置 Nginx 监听 8080 端口，不再占用 80
cat >/etc/nginx/sites-available/clash.conf <<EOF
server {
    listen ${HTTP_PORT} default_server;
    root ${CLASH_WEB_DIR};
    location / {
        autoindex on;
    }
}
EOF
ln -sf /etc/nginx/sites-available/clash.conf /etc/nginx/sites-enabled/clash.conf
# 重新启动 Nginx (现在它监听8080，不会和 Hysteria 的 80 冲突)
systemctl restart nginx

echo "======================================================="
echo "   安装完成！"
echo "   主端口: ${HY2_PORT}"
echo "   总端口数: ${HY2_PORT_COUNT:-1}"
echo "   WARP状态: 已启用 (仅接管领英流量)"
echo "   订阅地址列表已在上方显示"
echo "======================================================="