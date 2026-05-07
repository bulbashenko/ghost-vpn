# Ghost

A VPN that tunnels traffic inside standard HTTPS. From a network observer's perspective it looks like a Chrome browser making API requests to a web service.

## How it works

Ghost is a TUN-based VPN, not a proxy. The client creates a `ghost0` network interface; all IP traffic from the machine goes into it. On the wire, everything is wrapped in a single TLS 1.3 connection that matches the Chrome 133 fingerprint byte-for-byte.

Five layers, each independently addressable:

| Layer | What it does |
|-------|-------------|
| **L1** `internal/transport` | TLS 1.3 via uTLS — ClientHello matches Chrome 133 (GREASE, X25519MLKEM768, ALPS, ECH placeholder) |
| **L2** `internal/camouflage` | HTTP/2 POST as the tunnel carrier; all other paths reverse-proxy to a real website |
| **L3** `internal/auth` | Noise IK handshake (`Noise_IK_25519_ChaChaPoly_BLAKE2s`) — mutual authentication, replay protection, constant-time |
| **L4** `internal/mux` | Binary stream multiplexer over the authenticated channel |
| **L5** `internal/shaper` | Write coalescer that batches frames into MTU-sized chunks and pads idle periods with cover traffic |

The connection rotates every ~90 seconds. Each rotation gets a fresh TLS handshake with new GREASE values — the same pattern a browser produces when it refreshes a long-lived connection to a web service.

If anything other than a valid Ghost client connects — a scanner, a probe, a browser — the server transparently reverse-proxies the request to the configured `fallback_target`. The response is byte-identical to what that site would have returned.

## Requirements

- Go 1.25+
- Linux (TUN interface, netlink). Cross-compile from macOS/Windows for the server.
- A domain with a valid TLS certificate (Let's Encrypt works).

## Build

```bash
make build          # local OS
make build-linux    # Linux amd64, output to ./bin/
```

Or directly:

```bash
go build ./...
```

## Quick start

### 1. Generate keypairs

On each machine (server and client):

```bash
ghost-tools keygen
# prints: private_key: <base64>  public_key: <base64>
```

Or via make after building:

```bash
make keygen
```

Store private keys locally. Exchange public keys between machines.

### 2. Server config

Copy `examples/server.yaml`:

```yaml
listen: ":443"

cert_file: /etc/letsencrypt/live/example.com/fullchain.pem
key_file:  /etc/letsencrypt/live/example.com/privkey.pem

private_key: "YOUR_SERVER_PRIVATE_KEY"

allowed_clients:
  - "CLIENT_PUBLIC_KEY"

fallback_target: "https://example.com"

tun:
  name:    ghost0
  address: "10.7.0.1/24"
  mtu:     1400
```

### 3. Client config

Copy `examples/client.yaml`:

```yaml
server_addr: "example.com:443"

private_key:       "YOUR_CLIENT_PRIVATE_KEY"
server_public_key: "SERVER_PUBLIC_KEY"

fingerprint: chrome

tun:
  name:    ghost0
  address: "10.7.0.2/24"
  mtu:     1400
```

### 4. Run

```bash
# server
sudo ghost-server -config server.yaml

# client
sudo ghost-client -config client.yaml
```

The `ghost0` interface comes up. Route traffic through `10.7.0.1`.

## Deployment

Run as a systemd service:

```ini
[Unit]
Description=Ghost VPN Server
After=network.target

[Service]
ExecStart=/usr/local/bin/ghost-server -config /etc/ghost/server.yaml
Restart=on-failure
RestartSec=5s
AmbientCapabilities=CAP_NET_ADMIN

[Install]
WantedBy=multi-user.target
```

Install binaries:

```bash
make install   # ghost-server, ghost-client, ghost-tools → /usr/local/bin
```

## NetworkManager integration

Ghost ships an optional NetworkManager VPN plugin for `nmcli` and GNOME integration.

```bash
make install-nm-plugin
```

See [`examples/ghost.nmconnection`](examples/ghost.nmconnection) for a connection file template.

## Detection harness

`test/detection/` is a Python ML harness for measuring how detectable the traffic is:

```bash
cd test/detection
pip install -r requirements.txt

python features/extract.py --pcap capture.pcap --out features.csv
python classifier/train_xgboost.py --features features.csv
python classifier/evaluate.py
```

## Testing

```bash
make test   # go test ./...
make vet
```

## License

MIT
