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
│  │  • utxo_4b_to_32b_  │  │   │  │  • utxo_4b_to_32b_  │  │
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
# Clone the repository
git clone https://github.com/weikengchen/Bitcoin-PIR.git
cd Bitcoin-PIR

# Build the release binary
cargo build --release --bin server
```

### 1.3 Database Files

Place your database files in a consistent location on each server. Recommended:

```bash
# Create data directory
sudo mkdir -p /data/pir
sudo chown $USER:$USER /data/pir

# Copy your database files
# (You mentioned these are already uploaded)
# Expected files:
#   /data/pir/utxo_chunks.bin
#   /data/pir/utxo_chunks_cuckoo.bin
#   /data/pir/utxo_4b_to_32b_cuckoo.bin
```

### 1.4 Update Configuration

Edit `dpf_pir/src/server_config.rs` to point to your database paths:

```rust
// Change these paths to match your server's file locations
let cuckoo_config = DatabaseConfig::new(
    "utxo_cuckoo_index",
    "/data/pir/utxo_chunks_cuckoo.bin",  // <-- Update this path
    // ... other params stay the same
);

let chunks_config = DatabaseConfig::new(
    "utxo_chunks_data",
    "/data/pir/utxo_chunks.bin",  // <-- Update this path
    // ... other params stay the same
);

match TxidMappingDatabase::new(
    "utxo_4b_to_32b",
    "/data/pir/utxo_4b_to_32b_cuckoo.bin",  // <-- Update this path
    // ... other params stay the same
)
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
# On Server 1
sudo systemctl daemon-reload
sudo systemctl enable pir-server1
sudo systemctl start pir-server1
sudo systemctl status pir-server1

# On Server 2
sudo systemctl daemon-reload
sudo systemctl enable pir-server2
sudo systemctl start pir-server2
sudo systemctl status pir-server2
```

### Option B: Simple Script (Development/Testing)

```bash
# On each server, run in a tmux or screen session
cd Bitcoin-PIR
RUST_LOG=info ./target/release/server --port 8091  # Server 1
RUST_LOG=info ./target/release/server --port 8092  # Server 2
```

---

## Part 3: Network Configuration

### Understanding HTTPS and WSS

**Browser Security Policy**: If your web client is served over HTTPS, browsers will block insecure WebSocket (`ws://`) connections. You MUST use secure WebSocket (`wss://`) in production.

**Solutions:**
1. **Cloudflare Tunnel** (Recommended - Free, no port exposure)
2. **nginx + Let's Encrypt** (Traditional SSL)

---

### 3.1 Option A: Cloudflare Tunnel (Recommended)

Cloudflare Tunnel provides free SSL termination without opening ports or managing certificates.

#### Install cloudflared on each server:

```bash
# Download and install
curl -L https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-amd64 -o cloudflared
chmod +x cloudflared
sudo mv cloudflared /usr/local/bin/

# Authenticate with your Cloudflare account
cloudflared tunnel login
# This will open a browser - select your domain
```

#### Create tunnels:

```bash
# On Server 1
cloudflared tunnel create pir-server1
# Note the tunnel ID: e.g., 6ff42ae2-765d-4f19-9d2b-123456789abc

# On Server 2
cloudflared tunnel create pir-server2
# Note the tunnel ID
```

#### Configure DNS:

```bash
# On Server 1 - create DNS record pointing to tunnel
cloudflared tunnel route dns pir-server1 pir1.yourdomain.com

# On Server 2
cloudflared tunnel route dns pir-server2 pir2.yourdomain.com
```

#### Run tunnels (for testing):

```bash
# Server 1
cloudflared tunnel run --url localhost:8091 pir-server1

# Server 2
cloudflared tunnel run --url localhost:8092 pir-server2
```

#### Create systemd service for persistent tunnel:

**Server 1:** `/etc/systemd/system/cloudflared-server1.service`

```ini
[Unit]
Description=Cloudflare Tunnel for PIR Server 1
After=network.target

[Service]
Type=simple
User=your-username
ExecStart=/usr/local/bin/cloudflared tunnel run --url localhost:8091 pir-server1
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl daemon-reload
sudo systemctl enable cloudflared-server1
sudo systemctl start cloudflared-server1
```

Repeat for Server 2.

**Your WebSocket URLs become:**
- `wss://pir1.yourdomain.com`
- `wss://pir2.yourdomain.com`

**Benefits:**
- ✅ Free SSL certificates
- ✅ No open ports needed (servers can be behind NAT)
- ✅ Server IP hidden (DDoS protection)
- ✅ No nginx configuration needed

---

### 3.2 Option B: Native TLS Support (Self-Hosted)

The server now supports native TLS for secure WebSocket connections. You just need SSL certificates.

#### Generate SSL Certificates

**Option 1: Self-signed certificate (for testing):**
```bash
# Generate self-signed certificate (valid for 365 days)
openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 365 -nodes

# Answer the prompts (or use -subj to skip):
# Common Name (CN) should be your server's domain or IP
```

**Option 2: Let's Encrypt (recommended for production):**
```bash
# Install certbot
sudo apt install certbot

# Get certificate (standalone mode)
sudo certbot certonly --standalone -d pir1.yourdomain.com

# Certificates will be at:
#   /etc/letsencrypt/live/pir1.yourdomain.com/fullchain.pem (cert)
#   /etc/letsencrypt/live/pir1.yourdomain.com/privkey.pem (key)

# Copy to accessible location (or use sudo to run server)
sudo cp /etc/letsencrypt/live/pir1.yourdomain.com/fullchain.pem /data/pir/cert.pem
sudo cp /etc/letsencrypt/live/pir1.yourdomain.com/privkey.pem /data/pir/key.pem
sudo chown $USER:$USER /data/pir/cert.pem /data/pir/key.pem
```

#### Run Server with TLS

```bash
# Build the server
cargo build --release --bin server

# Run with TLS
./target/release/server --port 8091 \
    --tls-cert /data/pir/cert.pem \
    --tls-key /data/pir/key.pem
```

**Your WebSocket URL:** `wss://your-server-ip:8091` or `wss://pir1.yourdomain.com:8091`

#### systemd Service with TLS

Update the service file:

```ini
[Unit]
Description=Bitcoin PIR Server 1 (Secure WebSocket)
After=network.target

[Service]
Type=simple
User=your-username
WorkingDirectory=/home/your-username/Bitcoin-PIR
ExecStart=/home/your-username/Bitcoin-PIR/target/release/server --port 8091 --tls-cert /data/pir/cert.pem --tls-key /data/pir/key.pem
Restart=always
RestartSec=5
Environment=RUST_LOG=info

[Install]
WantedBy=multi-user.target
```

---

### 3.3 Option C: nginx + Let's Encrypt

For production, use nginx as a reverse proxy with SSL certificates (Let's Encrypt).

**Install nginx:**

```bash
sudo apt install nginx certbot python3-certbot-nginx
```

**nginx config for Server 1:** `/etc/nginx/sites-available/pir-server1`

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
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        
        # Increase timeout for long-running queries
        proxy_read_timeout 300s;
        proxy_send_timeout 300s;
    }
}
```

**Enable and get SSL certificate:**

```bash
sudo ln -s /etc/nginx/sites-available/pir-server1 /etc/nginx/sites-enabled/
sudo nginx -t
sudo systemctl reload nginx

# Get SSL certificate
sudo certbot --nginx -d pir1.yourdomain.com
```

Repeat for Server 2 with `pir2.yourdomain.com` and port 8092.

**After SSL, your WebSocket URLs become:**
- `wss://pir1.yourdomain.com`
- `wss://pir2.yourdomain.com`

---

## Part 4: Web Client Hosting

### Option A: GitHub Pages (Recommended - Free)

1. **Enable GitHub Pages in your repo:**
   - Go to Settings → Pages
   - Source: Deploy from a branch
   - Branch: `main` (or your branch), folder: `/ (root)`
   
   **Note:** This will publish the entire repo. For a cleaner URL, you can:
   - Create a `gh-pages` branch with only the `web_client/` contents
   - Or use GitHub Actions to deploy just the web_client folder

2. **Create a `.nojekyll` file** (to prevent Jekyll processing):

   ```bash
   touch web_client/.nojekyll
   ```

3. **Access your site at:**
   ```
   https://weikengchen.github.io/Bitcoin-PIR/web_client/
   ```

### Option B: Separate GitHub Pages Repo (Cleaner URL)

1. **Create a new repository** (e.g., `bitcoin-pir-client`)

2. **Copy only the web_client files:**

   ```bash
   # In a new directory
   git clone https://github.com/YOUR_USERNAME/bitcoin-pir-client.git
   cd bitcoin-pir-client
   
   # Copy files from your main repo
   cp -r /path/to/Bitcoin-PIR/web_client/* .
   
   # Add .nojekyll
   touch .nojekyll
   
   git add .
   git commit -m "Initial web client"
   git push origin main
   ```

3. **Enable GitHub Pages** in repo settings

4. **Access at:** `https://YOUR_USERNAME.github.io/bitcoin-pir-client/`

### Option C: Static Hosting Services

- **Vercel:** Connect your GitHub repo, set root directory to `web_client`
- **Netlify:** Similar to Vercel, drag-and-drop deployment available
- **Cloudflare Pages:** Free with unlimited bandwidth

### Option D: Self-Hosted with nginx

If you want to host on your own servers:

```nginx
server {
    listen 80;
    server_name pir.yourdomain.com;
    
    root /var/www/pir-client;
    index index.html;
    
    location / {
        try_files $uri $uri/ =404;
    }
}
```

Copy the web_client files:

```bash
sudo mkdir -p /var/www/pir-client
sudo cp -r Bitcoin-PIR/web_client/* /var/www/pir-client/
sudo chown -R www-data:www-data /var/www/pir-client
```

---

## Part 5: Update Web Client Server URLs

After deploying, users need to update the server URLs in the web interface.

**Default URLs in the HTML:**
```html
<input type="text" id="server1Url" value="ws://localhost:8091">
<input type="text" id="server2Url" value="ws://localhost:8092">
```

**For production (with SSL), update to:**
```html
<input type="text" id="server1Url" value="wss://pir1.yourdomain.com">
<input type="text" id="server2Url" value="wss://pir2.yourdomain.com">
```

Or users can simply edit the URLs in the browser before clicking "Connect".

---

## Part 6: Quick Reference

### Server Ports

| Server | Default Port | WebSocket URL |
|--------|-------------|---------------|
| Server 1 | 8091 | `ws://server1-ip:8091` |
| Server 2 | 8092 | `ws://server2-ip:8092` |

### Database Files Required

| File | Description | Size Example |
|------|-------------|--------------|
| `utxo_chunks.bin` | UTXO data chunks | ~1 GB |
| `utxo_chunks_cuckoo.bin` | Cuckoo hash index | ~600 MB |
| `utxo_4b_to_32b_cuckoo.bin` | TXID mapping | ~1.1 GB |

### Useful Commands

```bash
# Check server status
sudo systemctl status pir-server1

# View server logs
sudo journalctl -u pir-server1 -f

# Restart server
sudo systemctl restart pir-server1

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
4. Check nginx logs if using reverse proxy: `sudo tail -f /var/log/nginx/error.log`

### "WebSocket connection failed" in browser console

1. **Mixed content:** If web client is on HTTPS, WebSocket must be WSS
2. **CORS:** The server already allows all origins, but check nginx config
3. **Certificate issues:** Ensure SSL cert is valid

### Server crashes on startup

1. Check database file paths in `server_config.rs`
2. Check file permissions on database files
3. Check available RAM (database may load into memory)
4. View logs: `sudo journalctl -u pir-server1 -n 50`

---

## Security Considerations

1. **Two Non-Colluding Servers**: The PIR security model requires that the two server operators do not collude. Use different hosting providers or jurisdictions.

2. **HTTPS/WSS**: Always use encrypted connections in production.

3. **Rate Limiting**: Consider adding rate limiting in nginx to prevent abuse:

   ```nginx
   limit_req_zone $binary_remote_addr zone=pir_limit:10m rate=10r/s;
   
   location / {
       limit_req zone=pir_limit burst=20;
       # ... rest of config
   }
   ```

4. **Database Integrity**: Verify database file checksums periodically.

---

## Next Steps

1. ✅ Build the Rust server binary on each server
2. ✅ Update `server_config.rs` with correct database paths
3. ✅ Set up systemd services
4. ✅ Configure firewall
5. ✅ Set up nginx reverse proxy with SSL
6. ✅ Deploy web client to GitHub Pages or static hosting
7. ✅ Test end-to-end from browser
</task_progress>
</write_to_file>