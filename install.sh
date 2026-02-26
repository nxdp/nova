#!/usr/bin/env bash
set -euo pipefail

detect_primary_ip() {
    local ip_addr
    ip_addr="$(ip -4 route get 1.1.1.1 2>/dev/null | awk '{for (i=1; i<=NF; i++) if ($i=="src") {print $(i+1); exit}}')"
    if [ -z "${ip_addr:-}" ]; then
        ip_addr="$(hostname -I 2>/dev/null | awk '{print $1}')"
    fi
    if [ -z "${ip_addr:-}" ]; then
        echo "Unable to detect primary IPv4. Set NOVA_HOST explicitly." >&2
        exit 1
    fi
    echo "$ip_addr"
}

is_ip() {
    python3 - "$1" <<'PY'
import ipaddress
import sys
try:
    ipaddress.ip_address(sys.argv[1])
    sys.exit(0)
except ValueError:
    sys.exit(1)
PY
}

HOST="${NOVA_HOST:-$(detect_primary_ip)}"
UUID="${NOVA_UUID:-$(cat /proc/sys/kernel/random/uuid)}"
WS_PATH="${NOVA_WS_PATH:-"/api/v1/$(openssl rand -hex 4)"}"
ACME_STAGING="${NOVA_STAGING:+--staging}"
ACME_FORCE="${NOVA_FORCE:+--force}"

INSTANCE=$(echo "$HOST" | tr '.:' '--')
XRAY_PORT=$(shuf -i 10000-60000 -n 1)

IS_IP_CERT=0
if is_ip "$HOST"; then
    IS_IP_CERT=1
fi

ACME_DOMAIN_DIR="$HOME/.acme.sh/${HOST}_ecc"
CERT_FULLCHAIN="$ACME_DOMAIN_DIR/fullchain.cer"
CERT_KEY="$ACME_DOMAIN_DIR/${HOST}.key"

if command -v apt-get >/dev/null 2>&1; then
    export DEBIAN_FRONTEND=noninteractive
    apt-get update -qq >/dev/null 2>&1
    apt-get install -yq --no-install-recommends nginx unzip curl qrencode socat >/dev/null 2>&1
elif command -v dnf >/dev/null 2>&1; then
    dnf -y makecache >/dev/null 2>&1
    dnf install -y nginx unzip curl qrencode socat >/dev/null 2>&1
else
    echo "Unsupported distro: need apt-get or dnf."
    exit 1
fi

if [ ! -x "$HOME/.acme.sh/acme.sh" ]; then
    curl -s https://get.acme.sh | sh >/dev/null 2>&1
fi

if [ ! -f "$CERT_FULLCHAIN" ] || [ ! -f "$CERT_KEY" ]; then
    systemctl stop nginx 2>/dev/null || true
    ACME_ARGS=(--issue --standalone -d "$HOST" --server letsencrypt --keylength ec-256 --debug 0 --log-level 1)
    if [ "$IS_IP_CERT" -eq 1 ]; then
        ACME_ARGS+=(--certificate-profile shortlived --days 6)
    fi
    if [ -n "${ACME_STAGING:-}" ]; then
        ACME_ARGS+=(--staging)
    fi
    if [ -n "${ACME_FORCE:-}" ]; then
        ACME_ARGS+=(--force)
    fi
    "$HOME/.acme.sh/acme.sh" "${ACME_ARGS[@]}" >/dev/null 2>&1
fi

if [ ! -f /usr/local/bin/xray ]; then
    curl -fsSL -o /tmp/xray.zip https://github.com/XTLS/Xray-core/releases/latest/download/Xray-linux-64.zip
    unzip -oq /tmp/xray.zip xray -d /usr/local/bin
    chmod +x /usr/local/bin/xray
    rm -f /tmp/xray.zip
fi

mkdir -p /usr/local/etc/xray
cat > "/usr/local/etc/xray/$INSTANCE.json" <<EOF
{
  "log": {"loglevel": "warning"},
  "routing": {
    "rules": [{"outboundTag": "blocked", "protocol": ["bittorrent"], "type": "field"}]
  },
  "inbounds": [{
    "listen": "127.0.0.1",
    "port": $XRAY_PORT,
    "protocol": "vless",
    "settings": {
      "clients": [{"id": "$UUID"}],
      "decryption": "none"
    },
    "streamSettings": {
      "network": "ws",
      "wsSettings": {"path": "$WS_PATH"}
    }
  }],
  "outbounds": [
    {"protocol": "freedom", "tag": "direct"},
    {"protocol": "blackhole", "tag": "blocked"}
  ]
}
EOF

cat > /etc/systemd/system/xray@.service <<'EOF'
[Unit]
Description=Xray Service %i
After=network.target

[Service]
Type=simple
ExecStart=/usr/local/bin/xray run -config /usr/local/etc/xray/%i.json
Restart=always
RestartSec=3
LimitNPROC=10000
LimitNOFILE=1000000

[Install]
WantedBy=multi-user.target
EOF

rm -f /etc/nginx/sites-enabled/default /etc/nginx/conf.d/default.conf

cat > "/etc/nginx/conf.d/$INSTANCE.conf" <<EOF
map \$http_upgrade \$connection_upgrade {
    default upgrade;
    '' close;
}

server {
    listen 80$( [ "$IS_IP_CERT" -eq 1 ] && echo " default_server");
    server_name $HOST;
    return 301 https://\$host\$request_uri;
}

server {
    listen 443 ssl$( [ "$IS_IP_CERT" -eq 1 ] && echo " default_server");
    server_name $HOST;

    ssl_certificate $CERT_FULLCHAIN;
    ssl_certificate_key $CERT_KEY;
    ssl_protocols       TLSv1.2 TLSv1.3;
    ssl_ciphers         TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384;
    ssl_prefer_server_ciphers off;
    ssl_session_cache   shared:SSL:10m;
    ssl_session_timeout 1d;
    ssl_session_tickets off;

    add_header Strict-Transport-Security "max-age=63072000" always;
    add_header X-Content-Type-Options nosniff;
    add_header X-Frame-Options DENY;
    
    location / {
        root /var/www/html;
        index index.html;
        try_files \$uri \$uri/ /index.html;
    }

    location $WS_PATH {
        proxy_pass http://127.0.0.1:$XRAY_PORT;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection \$connection_upgrade;
        proxy_set_header Host \$host;
        proxy_read_timeout 86400;
        proxy_send_timeout 86400;
        proxy_buffering off;
        tcp_nodelay on;
    }
}
EOF

mkdir -p /var/www/html
cat > /var/www/html/index.html <<'EOF'
<!doctype html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>DeepFlow Lab</title>
<script src="https://cdn.tailwindcss.com"></script>
<style>body{background:#080808;font-family:ui-sans-serif,system-ui,sans-serif}</style>
</head>
<body class="min-h-screen text-gray-300 flex flex-col">
<nav class="flex items-center justify-between px-8 py-5 border-b border-white/5">
<span class="font-mono text-xs text-white tracking-wider">DEEPFLOW LAB</span>
<span class="font-mono text-xs text-emerald-400">● live</span>
</nav>
<main class="flex-1 flex flex-col justify-center px-8 max-w-2xl mx-auto w-full py-24">
<p class="font-mono text-xs text-gray-600 mb-6">// neural architecture research</p>
<h1 class="text-4xl font-light text-white leading-snug tracking-tight mb-6">
Building models that<br>
<span class="font-medium text-cyan-400">push the deep frontier.</span>
</h1>
<p class="text-sm text-gray-500 leading-relaxed max-w-md mb-10">
Foundation model research. Distributed training, efficient transformers, novel optimization.
</p>
<div class="flex gap-3">
<a href="#" class="font-mono text-xs px-5 py-2.5 bg-white text-black hover:bg-cyan-400 transition-colors">READ PAPERS</a>
<a href="#" class="font-mono text-xs px-5 py-2.5 border border-white/10 text-gray-400 hover:border-white/30 hover:text-white transition-colors">CONTACT</a>
</div>
</main>
<footer class="px-8 py-5 border-t border-white/5 flex justify-between">
<span class="font-mono text-xs text-gray-700">© 2026 DeepFlow Lab</span>
<span class="font-mono text-xs text-gray-700">research purposes only</span>
</footer>
</body>
</html>
EOF

systemctl daemon-reload
systemctl --no-block enable -q xray@$INSTANCE nginx 2>/dev/null
systemctl restart xray@$INSTANCE nginx 2>/dev/null

ENCODED_PATH=$(python3 -c "import urllib.parse; print(urllib.parse.quote('$WS_PATH'))")
INSECURE="${NOVA_STAGING:+&allowInsecure=1}"
URI_HOST="$HOST"
if [[ "$HOST" == *:* ]]; then
    URI_HOST="[$HOST]"
fi
SNI_PARAM=""
if [ "$IS_IP_CERT" -eq 0 ]; then
    SNI_PARAM="&sni=$HOST"
fi

VLESS_URI="vless://$UUID@$URI_HOST:443?type=ws&security=tls&path=$ENCODED_PATH$SNI_PARAM&alpn=h2%2Chttp%2F1.1$INSECURE#NOVA"

echo "$VLESS_URI" | qrencode -t utf8
echo ""
echo "$VLESS_URI"
echo ""
