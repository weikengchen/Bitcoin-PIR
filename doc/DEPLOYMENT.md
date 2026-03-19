# Bitcoin PIR Deployment Guide

This guide explains how to deploy the Bitcoin PIR system on two servers.

## Architecture Overview

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                              USER BROWSER                                   │
│                                                                             │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │                    Web Client (HTML/JS)                              │   │
│  │           Hosted on GitHub Pages / Static Hosting                    │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
│                              │                                              │
│                ┌─────────────┴─────────────┐                               │
│                ▼                           ▼                                │
│         WebSocket                   WebSocket                               │
│         Connection                  Connection                              │
└─────────────────────────────────────────────────────────────────────────────┘
                │                           │
                ▼                           ▼
┌───────────────────────────┐   ┌───────────────────────────┐
│        SERVER 1           │   │        SERVER 2           │
│                           │   │                           │
│  ┌─────────────────────┐  │   │  ┌─────────────────────┐  │
│  │  WebSocket Server   │  │   │  │  WebSocket Server   │  │
│  │  (Rust binary)      │  │   │  │  (Rust binary)      │  │
│  │  Port: 8091         │  │   │  │  Port: 8092         │  │
│  └──────────┬──────────┘  │   │  └──────────┬──────────┘  │
│             │             │   │             │             │
│  ┌──────────▼──────────┐  │   │  ┌──────────▼──────────┐  │
│  │  Database Files     │  │   │  │  Database Files     │  │
│  │  (Same on both)     │  │   │  │  (Same on both)     │  │
│  │                     │  │   │  │                     │  │
│  │  • utxo_chunks.bin  │  │   │  │  • utxo_chunks.bin  │  │
│  │  • utxo_chunks_     │  │   │  │  • utxo_chunks_     │  │
│  │    cuckoo.bin       │  │   │  │    cuckoo.bin       │  │
│  └─────────────────────┘  │   │  └─────────────────────┘  │
└───────────────────────────┘   └───────────────────────────┘
```

**PIR Security Model**: The two servers MUST NOT collude. Each server independently holds a copy of the database. Privacy is guaranteed as long as at least one server doesn't learn the user's query.

---

## Part 1: Server Setup (Both Servers)

### 1.1 Prerequisites

Install on both servers:

```bash
# Ubuntu/Debian
sudo apt update
sudo apt install -y build-essential pkg-config libssl-dev

# Install Rust
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source $HOME/.cargo/env
```

### 1.2 Clone and Build

```bash
git clone https://github.com/weikengchen/Bitcoin-PIR.git
cd Bitcoin-PIR

# Build the release binary
cargo build --release --bin server
```

### 1.3 Database Files

Place your database files in a consistent location on each server:

```bash
# Create data directory
sudo mkdir -p /data/pir
sudo chown $USER:$USER /data/pir

# Required files (identical on both servers):
#   /data/pir/utxo_chunks.bin         (~6 GB, UTXO chunk data)
#   /data/pir/utxo_chunks_cuckoo.bin  (~1.4 GB, cuckoo hash index)
```

### 1.4 Update Configuration

Edit `dpf_pir/src/server_config.rs` to point to your database paths:

```rust
let cuckoo_path = "/data/pir/utxo_chunks_cuckoo.bin";
let chunks_path = "/data/pir/utxo_chunks.bin";
```

After modifying, rebuild:

```bash
cargo build --release --bin server
```

---

## Part 2: Running the Servers

### Option A: Using systemd (Recommended for Production)

Create a systemd service file on each server:

**Server 1:** `/etc/systemd/system/pir-server1.service`

```ini
[Unit]
Description=Bitcoin PIR Server 1
After=network.target

[Service]
Type=simple
User=your-username
WorkingDirectory=/home/your-username/Bitcoin-PIR
ExecStart=/home/your-username/Bitcoin-PIR/target/release/server --port 8091
Restart=always
RestartSec=5
Environment=RUST_LOG=info

[Install]
WantedBy=multi-user.target
```

**Server 2:** `/etc/systemd/system/pir-server2.service`

```ini
[Unit]
Description=Bitcoin PIR Server 2
After=network.target

[Service]
Type=simple
User=your-username
WorkingDirectory=/home/your-username/Bitcoin-PIR
ExecStart=/home/your-username/Bitcoin-PIR/target/release/server --port 8092
Restart=always
RestartSec=5
Environment=RUST_LOG=info

[Install]
WantedBy=multi-user.target
```

Enable and start:

```bash
sudo systemctl daemon-reload
sudo systemctl enable pir-server1
sudo systemctl start pir-server1
sudo systemctl status pir-server1
```

### Option B: Simple Script (Development/Testing)

```bash
cd Bitcoin-PIR
./scripts/start_pir_servers.sh

# Or with small databases:
./scripts/start_pir_servers.sh --small
```

---

## Part 3: Network Configuration

### Understanding HTTPS and WSS

**Browser Security Policy**: If your web client is served over HTTPS, browsers will block insecure WebSocket (`ws://`) connections. You MUST use secure WebSocket (`wss://`) in production.

**Solutions:**
1. **Cloudflare Tunnel** (Recommended — Free, no port exposure)
2. **Native TLS** (Built-in server support)
3. **nginx + Let's Encrypt** (Traditional SSL termination)

---

### 3.1 Option A: Cloudflare Tunnel (Recommended)

Cloudflare Tunnel provides free SSL termination without opening ports or managing certificates.

#### Install cloudflared on each server:

```bash
curl -L https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-amd64 -o cloudflared
chmod +x cloudflared
sudo mv cloudflared /usr/local/bin/

# Authenticate with your Cloudflare account
cloudflared tunnel login
```

#### Create tunnels:

```bash
# On Server 1
cloudflared tunnel create pir-server1

# On Server 2
cloudflared tunnel create pir-server2
```

#### Configure DNS:

```bash
cloudflared tunnel route dns pir-server1 pir1.yourdomain.com
cloudflared tunnel route dns pir-server2 pir2.yourdomain.com
```

#### Run tunnels:

```bash
# Server 1
cloudflared tunnel run --url localhost:8091 pir-server1

# Server 2
cloudflared tunnel run --url localhost:8092 pir-server2
```

**Your WebSocket URLs become:**
- `wss://pir1.yourdomain.com`
- `wss://pir2.yourdomain.com`

---

### 3.2 Option B: Native TLS Support

The server supports native TLS for secure WebSocket connections.

```bash
# Self-signed certificate (testing)
openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 365 -nodes

# Let's Encrypt (production)
sudo certbot certonly --standalone -d pir1.yourdomain.com

# Run server with TLS
./target/release/server --port 8091 \
    --tls-cert /path/to/cert.pem \
    --tls-key /path/to/key.pem
```

---

### 3.3 Option C: nginx + Let's Encrypt

```bash
sudo apt install nginx certbot python3-certbot-nginx
```

**nginx config:** `/etc/nginx/sites-available/pir-server1`

```nginx
server {
    listen 80;
    server_name pir1.yourdomain.com;

    location / {
        proxy_pass http://127.0.0.1:8091;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host $host;
        proxy_read_timeout 300s;
        proxy_send_timeout 300s;
    }
}
```

```bash
sudo ln -s /etc/nginx/sites-available/pir-server1 /etc/nginx/sites-enabled/
sudo certbot --nginx -d pir1.yourdomain.com
```

---

## Part 4: Web Client Hosting

### GitHub Pages (Recommended)

The repository includes a GitHub Actions workflow (`.github/workflows/deploy-web.yml`) that automatically deploys the web client to GitHub Pages on every push to `main`.

The workflow runs `npm run build-web` in `web_client/` and deploys `web_client/dist-web/` to GitHub Pages.

To enable: Go to your repo's Settings → Pages → Source: GitHub Actions.

### Other Options

- **Vercel/Netlify**: Connect GitHub repo, set root to `web_client`
- **Self-hosted**: Serve `web_client/dist-web/` with nginx or any static file server

---

## Part 5: Quick Reference

### Server Ports

| Server | Default Port | WebSocket URL |
|--------|-------------|---------------|
| Server 1 | 8091 | `ws://server1-ip:8091` |
| Server 2 | 8092 | `ws://server2-ip:8092` |

### Database Files Required

| File | Description | Approximate Size |
|------|-------------|-----------------|
| `utxo_chunks.bin` | UTXO data in 32KB chunks | ~6 GB |
| `utxo_chunks_cuckoo.bin` | Cuckoo hash index | ~1.4 GB |

### Useful Commands

```bash
# Check server status
sudo systemctl status pir-server1

# View server logs
sudo journalctl -u pir-server1 -f

# Check if port is listening
ss -tlnp | grep 8091

# Test WebSocket connection
wscat -c ws://localhost:8091
```

---

## Troubleshooting

### "Connection refused" from browser

1. Check server is running: `sudo systemctl status pir-server1`
2. Check firewall: `sudo ufw status`
3. Check port binding: `ss -tlnp | grep 8091`

### "WebSocket connection failed" in browser console

1. **Mixed content:** HTTPS page requires WSS WebSocket
2. **CORS:** The server allows all origins by default
3. **Certificate issues:** Ensure SSL cert is valid

### Server crashes on startup

1. Check database file paths in `server_config.rs`
2. Check file permissions on database files
3. Check available RAM (databases load into memory by default)
4. View logs: `sudo journalctl -u pir-server1 -n 50`

---

## Security Considerations

1. **Two Non-Colluding Servers**: Use different hosting providers or jurisdictions
2. **HTTPS/WSS**: Always use encrypted connections in production
3. **Rate Limiting**: Consider adding rate limiting in nginx
4. **Database Integrity**: Verify database file checksums periodically
