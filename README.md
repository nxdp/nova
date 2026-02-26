# NOVA

One-command VLESS+WS proxy server with TLS.

## Requirements

- Debian 12/13 or Ubuntu 22/24, or RHEL 9/10
- Domain pointing to your server IP
- `curl`, `openssl` available
- Root access

## Usage

```bash
export NOVA_DOMAIN=sub.domain.tld
bash <(curl -fsSL https://raw.githubusercontent.com/nxdp/nova/main/install.sh)
```

Outputs a QR code and `vless://` URI ready to import into your client.

## Configuration

All variables are optional except `NOVA_DOMAIN`.

| Variable | Required | Default |
|---|---|---|
| `NOVA_DOMAIN` | **YES** | — |
| `NOVA_UUID` | **NO** | auto-generated |
| `NOVA_WS_PATH` | **NO** | auto-generated |
| `NOVA_STAGING` | **NO** | — |

## Examples

```bash
# production
export NOVA_DOMAIN=sub.example.com
curl -fsSL https://raw.githubusercontent.com/nxdp/nova/main/install.sh | bash

# testing (staging cert)
export NOVA_DOMAIN=sub.example.com
export NOVA_STAGING=1

curl -fsSL https://raw.githubusercontent.com/nxdp/nova/main/install.sh | bash
```

## Client

Import the output `vless://` URI into any xray-based client (v2rayN, v2rayNG, Hiddify).

Set `alpn` to `h2,http/1.1` if your client doesn't parse it from the URI.
