# Design Guardian — Server

Backend server for the [Design Guardian](https://www.figma.com/community/plugin/design-guardian) Figma plugin. Handles Figma library syncing, component verification, and cloud authentication.

---

## What it does

- Syncs Figma library components, styles, and variables via the Figma REST API
- Caches library data so the plugin can run fast, offline-tolerant scans
- Verifies component approval against configured design system libraries
- Handles Figma OAuth 2.0 for cloud mode authentication
- Issues signed JWTs so the plugin can make authenticated requests

---

## Requirements

- Node.js 20+
- A Figma Personal Access Token (PAT) with read access to your libraries
- (Optional) Figma OAuth app credentials for cloud mode sign-in

---

## Quickstart — Local

```bash
git clone https://github.com/NoyalClaiton/design-guardian-server.git
cd design-guardian-server
npm install
```

Create a `.env` file:

```env
PORT=3001
FIGMA_PAT=your_figma_personal_access_token
JWT_SECRET=any_long_random_string
TOKEN_ENCRYPTION_KEY=64_char_hex_string_for_aes256

# Optional: Figma OAuth (cloud mode only)
FIGMA_CLIENT_ID=your_oauth_client_id
FIGMA_CLIENT_SECRET=your_oauth_client_secret
FIGMA_REDIRECT_URI=http://localhost:3001/auth/figma/callback
```

```bash
node server.js
```

Server starts on `http://localhost:3001`. Point the Design Guardian plugin to this URL in its self-hosted mode settings.

---

## Quickstart — Docker

```bash
docker build -t design-guardian-server .
docker run -p 3001:3001 \
  -e FIGMA_PAT=your_token \
  -e JWT_SECRET=your_secret \
  -e TOKEN_ENCRYPTION_KEY=your_hex_key \
  design-guardian-server
```

---

## Deploy to Railway

[![Deploy on Railway](https://railway.com/button.svg)](https://railway.com)

1. Fork this repo
2. Create a new Railway project from your fork
3. Set the environment variables (see table below)
4. Railway will build and deploy automatically using the Dockerfile

---

## Environment Variables

| Variable | Required | Description |
|---|---|---|
| `FIGMA_PAT` | Yes | Figma Personal Access Token. Needs read access to all libraries you want to sync. |
| `JWT_SECRET` | Yes | Secret used to sign JWTs issued to plugin clients. Use a long random string. |
| `TOKEN_ENCRYPTION_KEY` | Yes | 64-character hex string (32 bytes). Used for AES-256-GCM encryption of stored OAuth tokens. Generate with `openssl rand -hex 32`. |
| `PORT` | No | HTTP port (default: 3001). Railway sets this automatically. |
| `FIGMA_CLIENT_ID` | OAuth only | Client ID from the Figma developer portal. Required for cloud mode sign-in. |
| `FIGMA_CLIENT_SECRET` | OAuth only | Client secret from the Figma developer portal. Required for cloud mode sign-in. |
| `FIGMA_REDIRECT_URI` | OAuth only | Must match the redirect URL registered in the Figma developer portal. Example: `https://your-server.com/auth/figma/callback` |

---

## API Endpoints

| Method | Path | Description |
|---|---|---|
| `GET` | `/health` | Health check. Returns `{ ok: true }`. |
| `GET` | `/library` | Fetch synced library data (components, styles, variables). |
| `GET` | `/library/status` | Current sync status for configured libraries. |
| `GET` | `/library/check` | Lightweight check — returns whether the library has changed since `lastPublished`. |
| `GET` | `/verify-component` | Verify a single component key against approved libraries. |
| `POST` | `/verify-components` | Batch verify multiple component keys. |
| `GET` | `/auth/figma` | Start Figma OAuth flow. Redirects to Figma's authorization page. |
| `GET` | `/auth/figma/callback` | OAuth callback. Exchanges code for token and stores JWT keyed by state. |
| `GET` | `/auth/poll` | Plugin polls this to pick up the JWT after the user authorizes. |
| `GET` | `/auth/me` | Returns the authenticated user's profile (requires JWT). |

---

## Generating TOKEN_ENCRYPTION_KEY

```bash
openssl rand -hex 32
```

Paste the output as the value of `TOKEN_ENCRYPTION_KEY`.

---

## Getting a Figma PAT

1. Go to Figma → Account Settings → Security
2. Click **Generate new token**
3. Give it a name (e.g. "Design Guardian Server")
4. Copy the token — it won't be shown again

The token needs read access to any Figma files and libraries you want Design Guardian to sync.

---

## Plugin

The Design Guardian Figma plugin is a separate repository. The plugin communicates with this server for library syncing and component validation. In self-hosted mode, point the plugin to your server URL in the plugin settings.

---

## License

ISC
