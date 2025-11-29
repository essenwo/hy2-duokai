#!/usr/bin/env bash

set -euo pipefail

# ===== Script Parameters =====

COUNT=5
HY2_PORT_START="${HY2_PORT_START:-30001}"
NAME_TAG_BASE="${NAME_TAG_BASE:-MyHysteria_}"
CLASH_WEB_DIR="${CLASH_WEB_DIR:-/etc/hysteria}"
HTTP_PORT="${HTTP_PORT:-8080}"

# ---- helper: escape replacement for sed ----
escape_for_sed() {
  printf '%s' "$1" | sed -e 's/[\\/&@]/\\\\&/g' -e ':a' -e 'N' -e '$!ba' -e 's/\\n/\\\\n/g'
}

# ===========================
# 0) Get Public IP and Install Dependencies
# ===========================
echo "[INFO] Mode 1: Installing ${COUNT} new nodes"

SELECTED_IP="$(curl -s --max-time 10 https://ip.sb || ip -4 addr show scope global | awk '/inet /{print $2}' | head -n1 | cut -d/ -f1)"
if [[ "$SELECTED_IP" =~ ^(10\.|172\.(1[6-9]|2[0-9]|3[0-1])\.|192\.168\.) || -z "${SELECTED_IP}" ]]; then
  echo "[WARN] No public IPv4 detected or IP query failed. Trying local IP."
  SELECTED_IP="$(ip -4 addr show scope global | awk '/inet /{print $2}' | head -n1 | cut -d/ -f1 || true)"
  if [ -z "${SELECTED_IP}" ]; then
    echo "[ERR] No IP detected, exiting script."
    exit 1
  fi
  echo "[WARN] Using local IP: ${SELECTED_IP}. Ensure port 80 is mapped correctly!"
else
  echo "[OK] Using public IP: ${SELECTED_IP}"
fi

export DEBIAN_FRONTEND=noninteractive
pkgs=(curl jq openssl python3 nginx)
MISSING=0
for p in "${pkgs[@]}"; do
  if ! command -v "$p" >/dev/null 2>&1; then MISSING=1; break; fi
done
if [ "$MISSING" -eq 1 ]; then
  echo "[*] Installing dependencies..."
  apt-get update -y >/dev/null 2>&1
  apt-get install -y "${pkgs[@]}" >/dev/null 2>&1
fi

# ===========================
# 1) Generate Domain/IP and Install Hysteria
# ===========================
IP_DASH="${SELECTED_IP//./-}"
HY2_DOMAIN="${IP_DASH}.sslip.io"
echo "[OK] Using domain/IP: ${HY2_DOMAIN} -> ${SELECTED_IP}"

if ! command -v hysteria >/dev/null 2>&1; then
  echo "[*] Installing hysteria..."
  arch="$(uname -m)"; asset="hysteria-linux-amd64"
  case "$arch" in aarch64|arm64) asset="hysteria-linux-arm64" ;; esac
  ver="$(curl -fsSL https://api.github.com/repos/apernet/hysteria/releases/latest | jq -r '.tag_name')"
  if [ -z "$ver" ]; then
    echo "[ERR] Could not get Hysteria version from GitHub API. Check network or install manually."
    exit 1
  fi
  curl -fL "https://github.com/apernet/hysteria/releases/download/${ver}/${asset}" -o /usr/local/bin/hysteria
  chmod +x /usr/local/bin/hysteria
fi

# ===========================
# 2) Check for or Request Certificate
# ===========================
mkdir -p /etc/hysteria
HY2_CONFIG_BASE="/etc/hysteria/base_config.yaml"
HYSTERIA_CERT_BASE="/root/.config/hysteria/certs"
ACME_BASE="$HYSTERIA_CERT_BASE"
USE_EXISTING_CERT=0
USE_CERT_PATH=""
USE_KEY_PATH=""

CERT_DOMAIN_PATH="$ACME_BASE/$HY2_DOMAIN"
if [ -d "$CERT_DOMAIN_PATH" ]; then
    FULLCHAIN_FILE=$(find "$CERT_DOMAIN_PATH" -type f -name "fullchain*" | head -n1)
    PRIVKEY_FILE=$(find "$CERT_DOMAIN_PATH" -type f -name "*.key" -o -name "privkey*" | head -n1)
    if [ -f "$FULLCHAIN_FILE" ] && [ -f "$PRIVKEY_FILE" ]; then
        USE_EXISTING_CERT=1
        USE_CERT_PATH="$FULLCHAIN_FILE"
        USE_KEY_PATH="$PRIVKEY_FILE"
        echo "[OK] Existing certificate found: $FULLCHAIN_FILE"
    fi
fi

if [ "$USE_EXISTING_CERT" -eq 0 ]; then
  echo "[INFO] Certificate not found, attempting ACME HTTP-01..."
  
  systemctl disable --now hysteria-acme 2>/dev/null || true
  rm -f /etc/systemd/system/hysteria-acme.service
  
  cat >"${HY2_CONFIG_BASE}" <<EOF
listen: :${HY2_PORT_START}
acme:
  domains:
    - ${HY2_DOMAIN}
  disable_http_challenge: false
  disable_tlsalpn_challenge: true
auth:
  type: password
  password: acme_temp_pass
obfs:
  type: salamander
  salamander:
    password: acme_temp_obfs
EOF

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
  
  TRIES=0; ACME_OK=0
  echo "[*] Waiting for ACME certificate acquisition (up to 60 seconds)..."
  while [ $TRIES -lt 12 ]; do
    if journalctl -u hysteria-acme --no-pager -n 200 | grep -E -iq "certificate obtained successfully"; then
      ACME_OK=1
      break
    fi
    sleep 5
    TRIES=$((TRIES+1))
  done
  
  systemctl disable --now hysteria-acme 2>/dev/null || true
  rm -f /etc/systemd/system/hysteria-acme.service
  
  if [ "$ACME_OK" -ne 1 ]; then
    echo "[ERROR] ACME certificate acquisition failed or timed out. Check if port 80 is open to the public!"
    exit 1
  fi
  echo "[OK] ACME certificate acquired successfully."

  CERT_DOMAIN_PATH="$ACME_BASE/$HY2_DOMAIN"
  FULLCHAIN_FILE=$(find "$CERT_DOMAIN_PATH" -type f -name "fullchain*" | head -n1)
  PRIVKEY_FILE=$(find "$CERT_DOMAIN_PATH" -type f -name "*.key" -o -name "privkey*" | head -n1)
  if [ -f "$FULLCHAIN_FILE" ] && [ -f "$PRIVKEY_FILE" ]; then
      USE_EXISTING_CERT=1
      USE_CERT_PATH="$FULLCHAIN_FILE"
      USE_KEY_PATH="$PRIVKEY_FILE"
  else
      echo "[ERR] Certificate was acquired but files not found in $CERT_DOMAIN_PATH. Exiting."
      exit 1
  fi
fi

# ===========================
# 3) Loop Deploy Hysteria 2 Nodes
# ===========================
echo
echo "=== Starting deployment of ${COUNT} Hysteria 2 instances ==="
for ((i = 1; i <= COUNT; i++)); do
  HY2_PORT=$((HY2_PORT_START + i - 1))
  SERVICE_NAME="hysteria-server-${i}"
  CONFIG_PATH="/etc/hysteria/config_${i}.yaml"
  YAML_PATH="${CLASH_WEB_DIR}/clash_subscription_${i}.yaml"
  NAME_TAG="${NAME_TAG_BASE}${i}"

  HY2_PASS="$(openssl rand -hex 16)"
  OBFS_PASS="$(openssl rand -hex 8)"
  echo "[$i/$COUNT] Deploying node: Port ${HY2_PORT}, Service ${SERVICE_NAME}"

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
  echo "  - Config written: ${CONFIG_PATH}"

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
  echo "  - Service started: ${SERVICE_NAME}"

  PASS_ENC="$(python3 -c "import sys,urllib.parse as u; print(u.quote(sys.argv[1], safe=''))" "$HY2_PASS")"
  OBFS_ENC="$(python3 -c "import sys,urllib.parse as u; print(u.quote(sys.argv[1], safe=''))" "$OBFS_PASS")"
  NAME_ENC="$(python3 -c "import sys,urllib.parse as u; print(u.quote(sys.argv[1], safe=''))" "$NAME_TAG")"
  URI_i="hysteria2://${PASS_ENC}@${SELECTED_IP}:${HY2_PORT}/?protocol=udp&obfs=salamander&obfs-password=${OBFS_ENC}&sni=${HY2_DOMAIN}&insecure=0#${NAME_ENC}"
  
  echo "  - URI: ${URI_i}"

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
  default-nameserver: [223.5.5.5, 8.8.8.8]
  enhanced-mode: fake-ip
  fake-ip-range: 198.18.0.1/16
  nameserver: [https://doh.pub/dns-query, https://dns.alidns.com/dns-query]
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
  - name: "🚀 Node Selection"
    type: select
    proxies: ["__NAME_TAG__", DIRECT]
rules:
  - DOMAIN-SUFFIX,cn,DIRECT
  - DOMAIN-KEYWORD,baidu,DIRECT
  - DOMAIN-KEYWORD,taobao,DIRECT
  - DOMAIN-KEYWORD,qq,DIRECT
  - DOMAIN-KEYWORD,weixin,DIRECT
  - DOMAIN-KEYWORD,alipay,DIRECT
  - GEOIP,CN,DIRECT
  - MATCH,🚀 Node Selection
EOF

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
  
  echo "  - Clash subscription generated: ${TARGET}"
  echo
done

# ===========================
# 4) Configure Nginx for Subscription
# ===========================
cat >/etc/nginx/sites-available/clash.conf <<EOF
server {
    listen ${HTTP_PORT} default_server;
    listen [::]:${HTTP_PORT} default_server;
    root ${CLASH_WEB_DIR};
    location ~ /clash_subscription_[0-9]+\.yaml$ {
        default_type application/x-yaml;
        try_files \$uri =404;
    }
    access_log /var/log/nginx/clash_access.log;
    error_log /var/log/nginx/clash_error.log;
}
EOF

ln -sf /etc/nginx/sites-available/clash.conf /etc/nginx/sites-enabled/clash.conf 2>/dev/null || true
nginx -t
systemctl restart nginx

echo "================================================="
echo "✅ Deployment successful! ${COUNT} Hysteria 2 nodes generated."
echo "================================================="
echo "All nodes share the same certificate and domain: ${HY2_DOMAIN}"
echo "Nginx subscription service port: ${HTTP_PORT}"
echo "-------------------------------------------------"
for ((i = 1; i <= COUNT; i++)); do
  HY2_PORT=$((HY2_PORT_START + i - 1))
  echo "🚀 Node ${i} (Port ${HY2_PORT}) subscription link:"
  echo "    http://${SELECTED_IP}:${HTTP_PORT}/clash_subscription_${i}.yaml"
done
echo "-------------------------------------------------"
