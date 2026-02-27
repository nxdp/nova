# F99

One-command VLESS proxy server with TLS.
Supports VLESS+XHTTP by default, with optional VLESS+WS.

## Requirements

- Debian 12/13 or Ubuntu 22/24, or RHEL 9/10
- Public IPv4 on server (domain is optional)
- `curl`, `openssl` available
- Root access

## Usage

```bash
curl -fsSL https://raw.githubusercontent.com/nxdp/f99/main/install.sh | bash
```

Outputs a QR code and `vless://` URI ready to import into your client.

## Configuration

All variables are optional.

| Variable | Required | Default |
|---|---|---|
| `F99_HOST` | **NO** | server primary IPv4 |
| `F99_XHTTP` | **NO** | `1` (enabled) |
| `F99_WS` | **NO** | `0` (disabled) |
| `F99_XHTTP_PATH` | **NO** | auto-generated |
| `F99_UUID` | **NO** | auto-generated |
| `F99_UUID_XHTTP` | **NO** | `F99_UUID` |
| `F99_UUID_WS` | **NO** | `F99_UUID` |
| `F99_WS_PATH` | **NO** | auto-generated |
| `F99_STAGING` | **NO** | — |
| `F99_FORCE` | **NO** | — |

`F99_HOST` accepts either a domain or an IP.

- If `F99_HOST` is an IP (or unset and auto-detected as IP), the script requests an IP certificate via acme.sh using Let's Encrypt short-lived profile.
- If `F99_HOST` is a domain, the script requests a normal domain certificate.
- `F99_XHTTP=1` enables XHTTP transport (default).
- `F99_WS=1` enables WebSocket transport.
- You can run both transports at the same time.
- UUID precedence:
- XHTTP uses `F99_UUID_XHTTP`, then `F99_UUID`, then auto-generated UUID.
- WS uses `F99_UUID_WS`, then `F99_UUID`, then auto-generated UUID.

## Examples

```bash
# production (auto primary IP cert)
curl -fsSL https://raw.githubusercontent.com/nxdp/f99/main/install.sh | bash

# production (domain cert)
export F99_HOST=sub.example.com
curl -fsSL https://raw.githubusercontent.com/nxdp/f99/main/install.sh | bash

# xhttp + ws together
export F99_XHTTP=1
export F99_WS=1
curl -fsSL https://raw.githubusercontent.com/nxdp/f99/main/install.sh | bash

# ws only
export F99_XHTTP=0
export F99_WS=1
curl -fsSL https://raw.githubusercontent.com/nxdp/f99/main/install.sh | bash

# testing (staging cert)
export F99_HOST=203.0.113.10
export F99_STAGING=1
curl -fsSL https://raw.githubusercontent.com/nxdp/f99/main/install.sh | bash

# force re-issue certificate
export F99_HOST=203.0.113.10
export F99_FORCE=1
curl -fsSL https://raw.githubusercontent.com/nxdp/f99/main/install.sh | bash
```

## Client

Import the output `vless://` URI into any xray-based client (v2rayN, v2rayNG, Hiddify).

Set `alpn` to `h2,http/1.1` if your client doesn't parse it from the URI.
