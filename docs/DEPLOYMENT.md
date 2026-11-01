# Deployment

Two honest facts first:

1. **A local server cannot receive internet visitors.** `127.0.0.1:8000` is reachable only from the machine running it.
2. **KINGDOM X's dashboard is read-only and unauthenticated by design.** It exposes module metadata, not findings or credentials. Do not expose it publicly expecting it to be protected — it is not a multi-user application.

---

## Local only (default, safe)

```bash
python kingdomx.py web          # http://127.0.0.1:8000
```

Reachable from that machine. On Termux, reachable from that device.

To reach it from another machine **on your own network**:

```bash
python kingdomx.py web --host 0.0.0.0 --port 8000
```

You now have an unauthenticated read-only page on your LAN. That is acceptable for a home lab behind a router; it is not acceptable on a shared network.

---

## LAN with a warning

If you bind `0.0.0.0`, understand what you exposed:

- anyone on the LAN can read module status, host diagnostics and audit results
- there is no login, no session, no rate limit beyond what uvicorn provides
- `--host 0.0.0.0` should be a deliberate, temporary choice

---

## Public deployment (if you really need it)

The dashboard is not designed for public exposure. If you must, put a real reverse proxy in front of it and add authentication **at the proxy**, not in KINGDOM X.

### nginx + TLS

```nginx
server {
    listen 443 ssl http2;
    server_name kingdomx.example.com;

    ssl_certificate     /etc/letsencrypt/live/kingdomx.example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/kingdomx.example.com/privkey.pem;
    ssl_protocols       TLSv1.2 TLSv1.3;

    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
    add_header X-Content-Type-Options    "nosniff" always;
    add_header X-Frame-Options           "DENY" always;
    add_header Referrer-Policy           "no-referrer" always;

    # HTTP Basic auth at the proxy — the only access control that will exist
    auth_basic           "KINGDOM X";
    auth_basic_user_file /etc/nginx/.htpasswd;

    location / {
        proxy_pass         http://127.0.0.1:8000;
        proxy_set_header   Host $host;
        proxy_set_header   X-Real-IP $remote_addr;
        proxy_set_header   X-Forwarded-Proto $scheme;
    }
}
```

```bash
sudo apt install -y nginx apache2-utils
sudo htpasswd -c /etc/nginx/.htpasswd youruser
sudo systemctl reload nginx
```

Keep the app bound to `127.0.0.1` — only the proxy should see it.

### systemd unit

```ini
# /etc/systemd/system/kingdomx.service
[Unit]
Description=KINGDOM X dashboard
After=network.target

[Service]
Type=simple
User=kingdomx
WorkingDirectory=/opt/kingdom-x
Environment="PATH=/opt/kingdom-x/.venv/bin"
ExecStart=/opt/kingdom-x/.venv/bin/python kingdomx.py web --host 127.0.0.1 --port 8000
Restart=on-failure
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/opt/kingdom-x/data

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now kingdomx
sudo journalctl -u kingdomx -f
```

`ProtectSystem=strict` plus `ProtectHome=true` means the process genuinely cannot write outside `/opt/kingdom-x/data` — worth keeping.

---

## Termux exposure

Termux has no privileged ports and no systemd. To reach it from outside:

```bash
# Cloudflare Tunnel (needs a Cloudflare account)
pkg install -y cloudflared
cloudflared tunnel --url http://127.0.0.1:8000
```

That gives a real HTTPS URL — but the page behind it is still the unauthenticated dashboard. Add auth at Cloudflare Access, or do not publish it.

**Do not** use a public port-forward on the device without authentication in front.

---

## Docker

No Dockerfile ships with this project. A container would need `/proc` and host-level reads to be useful, which usually means `--privileged` — that defeats the point. If you want one, mount read-only and accept the reduced feature set.

---

## Backups

```bash
python - <<'PY'
from kingdomx.core.config import Config
from kingdomx.core.storage import Database
db = Database(Config.load().db_path)
db.backup_to("/backup/kingdomx-$(date +%F).db")
print("backed up")
db.close()
PY
```

Uses SQLite's backup API, so it is consistent while the app is running.

---

## What is *not* verified here

The documentation above is written from configuration knowledge, but **this repository's maintainer has not executed an nginx + TLS + systemd deployment of this project.** Treat the snippets as a starting point to test, not a certified recipe. The local and LAN cases are the tested paths.
