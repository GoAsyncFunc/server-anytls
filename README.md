# server-anytls

AnyTLS server node for V2Board / UniProxy panels, built on
[`github.com/anytls/sing-anytls`](https://github.com/anytls/sing-anytls).

## Features

- **Protocol**: AnyTLS over TLS 1.2+
- **Panel integration**: pulls users / node config and reports traffic +
  online IPs through the UniProxy v1 API
- **Per-user policy**: speed limit (Mbps), device count cap (distinct
  source IPs)
- **Routing subset**: `block`, `block_ip`, `block_port` rules from the
  panel are honoured (`protocol`, `dns`, `route`, `route_ip`,
  `default_out` are logged once and skipped — they need a multi-outbound
  manager that is out of scope for this server)
- **Private-network guard**: refuses outbound connections to RFC1918,
  loopback, link-local, CGNAT, and multicast destinations unless
  `--allow-private-outbound` is set
- **Hot reload**: re-opens the listener when `server_port`,
  `server_name`, `padding_scheme`, routes, or the cert files change
- **Idempotent shutdown**: every periodic task and the listener tolerate
  repeated `Close` calls

## Build

```bash
make build              # produces build/anytls-node
# or
go build -v ./cmd/server
```

The version reported by `anytls-node version` is injected at link time:

```bash
make build VERSION=v1.2.3
# or
go build -ldflags "-X main.Version=v1.2.3" ./cmd/server
```

## Usage

```bash
./build/anytls-node \
    --api    "https://your-panel.example" \
    --token  "<server token from panel>" \
    --node   1 \
    --cert_file /etc/anytls/server.crt \
    --key_file  /etc/anytls/server.key \
    --log_mode info
```

### Flags

| Flag | Env | Default | Notes |
|---|---|---|---|
| `--api` | `API` | required | Panel base URL |
| `--token` | `TOKEN` | required | Server token from V2Board |
| `--node` | `NODE` | required | Node ID |
| `--cert_file` | `CERT_FILE` | `/root/.cert/server.crt` | TLS server cert (PEM) |
| `--key_file` | `KEY_FILE` | `/root/.cert/server.key` | TLS server key (PEM) |
| `--fetch_users_interval`, `--fui` | `FETCH_USER_INTERVAL` | `60s` | Pull users from panel |
| `--report_traffics_interval`, `--rti` | `REPORT_TRAFFICS_INTERVAL` | `80s` | Push traffic to panel |
| `--heartbeat_interval`, `--hbi` | `HEARTBEAT_INTERVAL` | `3m` | Push online IP table |
| `--log_mode` | `LOG_LEVEL` | `error` | One of `debug` / `info` / `error` |

### Per-user policy

`SpeedLimit` (Mbps) and `DeviceLimit` come straight from the v2board
UserInfo and apply per uid:

- `speed_limit > 0` enforces a token bucket shared across uplink and
  downlink.
- `device_limit > 0` rejects new client IPs once that user already has
  the configured number of distinct source IPs in flight; existing IPs
  may open additional concurrent streams freely.

## Docker

```bash
docker build -f build/package/Dockerfile -t anytls-node .

docker run --rm \
    -e API=https://your-panel.example \
    -e TOKEN=<server token> \
    -e NODE=1 \
    -v /etc/anytls/server.crt:/root/.cert/server.crt:ro \
    -v /etc/anytls/server.key:/root/.cert/server.key:ro \
    -p 8443:8443 \
    anytls-node
```

The image bundles `tzdata` and `ca-certificates`. Override the cert path
via `CERT_FILE` / `KEY_FILE` if you mount them elsewhere.

## systemd

`scripts/server-anytls.service` ships a hardened unit:

```bash
sudo cp build/anytls-node /usr/local/bin/
sudo cp scripts/server-anytls.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now server-anytls
```

Pass configuration through `/etc/default/anytls-node` (env file) or by
adding `Environment=` directives to a drop-in.

## Development

```bash
make test       # unit tests + race detector
make build      # binary into build/
go test -tags=e2e ./internal/pkg/service/...   # end-to-end loopback test
```

## Status

The control plane (panel polling) and the data plane (TLS + AnyTLS +
freedom outbound + traffic accounting + online tracking) are
implemented. The repo intentionally omits multi-outbound routing and
protocol sniffing; see the deferred-actions list in the route mapping
table above.
