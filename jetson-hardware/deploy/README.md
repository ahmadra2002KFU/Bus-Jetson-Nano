# Server deployment — Cloudflare tunnel + Docker

This directory builds and runs the Al-Ahsa Smart Bus server. The server
sits behind a Cloudflare tunnel, so the VPS never needs a public port.

## Prerequisites

- A Linux VPS with Docker + docker compose v2.
- A Cloudflare account with the domain `testingdomainzforprototypes.website`.
- A Cloudflare Zero-Trust tunnel (create one in the Cloudflare dashboard —
  Networks → Tunnels → Create a tunnel). Add a public hostname:
  `jetson.testingdomainzforprototypes.website` → `http://app:3232`.

## Bring up

```bash
cd jetson-hardware/deploy
cp .env.example .env      # then edit .env and paste the tunnel token
docker compose build
docker compose up -d
docker compose logs -f app
```

Verify from any machine on the internet:

```bash
curl https://jetson.testingdomainzforprototypes.website/health
# {"status":"ok","build":"dev"}
```

Open the dashboard:

```
https://jetson.testingdomainzforprototypes.website/
```

## Data & retention

- SQLite DB: `./data/server.db`
- Forensic PDFs: `./data/forensics/*.pdf`
- Old rows and PDF files are purged by a background task every hour,
  keeping `RETENTION_DAYS` worth of history (default 30).

## Upgrading

```bash
git pull
docker compose build app
docker compose up -d app
```

(`cloudflared` keeps running and doesn't need to restart.)

## Tearing down

```bash
docker compose down         # keeps the ./data directory
docker compose down -v      # also removes any named volumes (there aren't any by default)
```

## Troubleshooting

| Symptom | Fix |
|---|---|
| `curl` returns 530 or 1033 | Tunnel token wrong or `cloudflared` isn't running. `docker compose logs cloudflared`. |
| `/health` returns 502 | App crashed. `docker compose logs app` and look for Python traceback. |
| WebSocket closes immediately | Confirm the Cloudflare public hostname is set to HTTP (not HTTPS) for origin, and that "Additional application settings → HTTP2 origin" is off. |
| Forensic POST fails with 413 | Cloudflare Free tier caps body at 100 MB; shouldn't be hit by our ~1 MB PDFs. |
| DB locked errors | Another process is holding the file. Only one `app` container should mount `./data`. |
