# NOVA

One-command VLESS+WS proxy server with TLS.

## Requirements

- Debian/Ubuntu server
- Domain pointing to your server IP
- Root access

## Install

```bash
export NOVA_DOMAIN=sub.domain.tld
bash <(curl -fsSL https://raw.githubusercontent.com/nxdp/nova/main/install.sh)
```

Outputs a `vless://` URI ready to import into your client.

## Options

| Variable | Required | Default |
|---|---|---|
| `NOVA_DOMAIN` | **YES** | — |
| `NOVA_UUID` | **NO** | auto-generated |
| `NOVA_WS_PATH` | **NO** | auto-generated |
| `NOVA_STAGING` | **NO** | — |

## Example

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
