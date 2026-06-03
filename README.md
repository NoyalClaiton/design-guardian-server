# Design Guardian: Server

Backend server for the Design Guardian Figma plugin. Handles Figma library syncing and component verification.

---

## What it does

- Syncs Figma library components, styles, and variables via the Figma REST API
- Caches library data so the plugin can run fast, offline-tolerant scans
- Verifies component approval against configured design system libraries

---

## Requirements

- Node.js 20+
- A Figma Personal Access Token (PAT) with read access to your libraries

---

## Quickstart: Local

```bash
git clone https://github.com/NoyalClaiton/design-guardian-server.git
cd design-guardian-server
npm install
```

Create a `.env` file:

```env
FIGMA_PAT=your_figma_personal_access_token
```

```bash
node server.js
```

Server starts on `http://localhost:3001`. Point the Design Guardian plugin to this URL in its self-hosted mode settings.

---

## Quickstart: Docker

```bash
docker build -t design-guardian-server .
docker run -p 3001:3001 \
  -e FIGMA_PAT=your_token \
  design-guardian-server
```

---

## Deploy to Railway

1. Fork this repo
2. Create a new Railway project from your fork
3. Add `FIGMA_PAT` in the Railway dashboard under Variables
4. Railway will build and deploy automatically using the Dockerfile

---

## Environment Variables

| Variable | Required | Description |
|---|---|---|
| `FIGMA_PAT` | Yes | Figma Personal Access Token. Needs read access to all libraries you want to sync. |
| `PORT` | No | HTTP port (default: 3001). Railway sets this automatically. |

---

## API Endpoints

| Method | Path | Description |
|---|---|---|
| `GET` | `/health` | Health check. Returns `{ ok: true }`. |
| `GET` | `/library` | Fetch synced library data (components, styles, variables). |
| `GET` | `/library/status` | Current sync status for configured libraries. |
| `GET` | `/library/check` | Lightweight check. Returns whether the library has changed since `lastPublished`. |
| `GET` | `/verify-component` | Verify a single component key against approved libraries. |
| `POST` | `/verify-components` | Batch verify multiple component keys. |

---

## Getting a Figma PAT

1. Open Figma and click your avatar at the top-right
2. Go to Settings > Security > Personal access tokens
3. Click **Generate new token** and give it a name like "Design Guardian"
4. Copy the token (it won't be shown again)

Use a token from an account that has access to all team libraries you want to sync.

---

## Plugin

The Design Guardian Figma plugin communicates with this server for library syncing and component validation. In self-hosted mode, point the plugin to your server URL in the plugin settings.

---

## License

ISC
