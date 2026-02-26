# NOVA

One-command VLESS+WS proxy server with TLS.

## Requirements

- Debian 12/13 or Ubuntu 22/24, or RHEL 9/10
- Public IPv4 on server (domain is optional)
- `curl`, `openssl` available
- Root access

## Usage

```bash
curl -fsSL https://raw.githubusercontent.com/nxdp/nova/main/install.sh | bash
```

Outputs a QR code and `vless://` URI ready to import into your client.

## Configuration

All variables are optional.

| Variable | Required | Default |
|---|---|---|
| `NOVA_HOST` | **NO** | server primary IPv4 |
| `NOVA_UUID` | **NO** | auto-generated |
| `NOVA_WS_PATH` | **NO** | auto-generated |
| `NOVA_STAGING` | **NO** | — |
| `NOVA_FORCE` | **NO** | — |

`NOVA_HOST` accepts either a domain or an IP.

- If `NOVA_HOST` is an IP (or unset and auto-detected as IP), the script requests an IP certificate via acme.sh using Let's Encrypt short-lived profile.
- If `NOVA_HOST` is a domain, the script requests a normal domain certificate.

## Examples

```bash
# production (auto primary IP cert)
curl -fsSL https://raw.githubusercontent.com/nxdp/nova/main/install.sh | bash

# production (domain cert)
export NOVA_HOST=sub.example.com
curl -fsSL https://raw.githubusercontent.com/nxdp/nova/main/install.sh | bash

# testing (staging cert)
export NOVA_HOST=203.0.113.10
export NOVA_STAGING=1
curl -fsSL https://raw.githubusercontent.com/nxdp/nova/main/install.sh | bash

# force re-issue certificate
export NOVA_HOST=203.0.113.10
export NOVA_FORCE=1
curl -fsSL https://raw.githubusercontent.com/nxdp/nova/main/install.sh | bash
```

## Client

Import the output `vless://` URI into any xray-based client (v2rayN, v2rayNG, Hiddify).

Set `alpn` to `h2,http/1.1` if your client doesn't parse it from the URI.
