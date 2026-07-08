# Design Guardian: Server

This is the backend server for the **Design Guardian** Figma plugin.

Design Guardian is a pre-handoff readiness tool for Figma. In a single scan it checks design system compliance (components, tokens, and styles against your libraries), UX fundamentals (accessibility, spacing, naming), and copy quality (text nodes reviewed against your content guidelines using AI). Issues come with suggested fixes, and many can be applied in one click.

This server enables two of those three surfaces. It syncs your Figma library data so the plugin can run design system compliance checks, and it runs AI content review when an AI provider is configured. UX fundamentals checks run client-side in the plugin and do not require this server.

---

## Deployment models

There are two ways to use the server:

**Self-hosted (run the server yourself)**
Run the server on your own machine or on a machine on your local network. The plugin connects to it over HTTPS on localhost or a custom local hostname. This keeps all your design data on your own infrastructure.

**Cloud (use the hosted server)**
Connect the plugin directly to the hosted server at `https://design-guardian-server-production.up.railway.app`. No setup required — you sign in with your Figma account through OAuth. This is the fastest way to get started.

> **Note:** The plugin's allowed network connections are fixed in the plugin manifest. It can only communicate with `localhost:3001–3010`, `design-guardian.local:3001–3010`, and the hosted cloud URL above. You cannot deploy to your own hosting provider and have the plugin reach it.

---

## Option 1: Run locally on your own machine

### What you need

- **Node.js 20 or later** ([download here](https://nodejs.org))
- **mkcert** for generating a trusted local HTTPS certificate
  - macOS: `brew install mkcert`
  - Windows: `choco install mkcert`
- A **Figma Personal Access Token** (see below)

### Setup

**Step 1.** Clone the repository and install dependencies:

```bash
git clone https://github.com/NoyalClaiton/design-guardian-server.git
cd design-guardian-server
npm install
```

**Step 2.** Create a `.env` file in the project folder:

```
FIGMA_PAT=paste_your_figma_token_here
```

**Step 3.** Start the server:

```bash
node server.js
```

The server detects whether mkcert is installed and generates a trusted HTTPS certificate automatically on first run. Once started, the terminal prints the exact URL to copy into the plugin settings (for example, `https://localhost:3001`).

### Notes

- The plugin only connects on ports **3001–3010**. If 3001 is taken the server tries the next port automatically.
- HTTPS is required. Without mkcert the server falls back to HTTP, which the Figma desktop app will refuse. Install mkcert and restart if you see a connection error.
- The generated certificate covers `localhost`, `127.0.0.1`, and `design-guardian.local`.

---

## Option 2: Run on a machine on your local network

If you want the server to run on a shared machine rather than your own laptop, the plugin connects to it using the hostname `design-guardian.local`.

**Step 1.** On the machine running the server, add this line to `/etc/hosts` (or `C:\Windows\System32\drivers\etc\hosts` on Windows):

```
127.0.0.1   design-guardian.local
```

**Step 2.** Follow the same setup steps as Option 1 (clone, `.env`, `node server.js`). The server will generate a certificate that covers `design-guardian.local` automatically.

**Step 3.** In the plugin settings, enter the URL printed by the server (for example, `https://design-guardian.local:3001`).

Devices on the same network connect through this hostname. Each device that uses the plugin must be able to reach the server machine on the network.

---

## Option 3: Use the hosted cloud server

No setup required. In the Design Guardian plugin, open Settings, go to the **Cloud** tab, and click **Set up Cloud**. You will be prompted to sign in with your Figma account. Once connected, the plugin uses the hosted server automatically.

The hosted server URL is `https://design-guardian-server-production.up.railway.app`. You do not need to enter this manually — the plugin configures it for you during setup.

---

## How to get a Figma Personal Access Token

Required for self-hosted (Options 1 and 2). Not needed for cloud (Option 3).

1. Open Figma in your browser and click your profile picture at the top right
2. Go to **Settings**, then the **Security** tab
3. Under **Personal access tokens**, click **Generate new token**
4. Give it a name like "Design Guardian" and click generate
5. Copy the token straight away — it will not be shown again

Use a Figma account that has access to all the design system libraries you want to check against.

---

## Setting up AI content review

The AI content review feature checks text in your Figma designs against a guidelines document you write (for example, a tone of voice guide, writing style checklist, or banned terms list).

**No new subscription required.** If you already use Claude, ChatGPT, or Gemini, the plugin can authenticate through your existing account via the installed CLI — no API key needed. You can also bring your own API key if you prefer pay-as-you-go, or run a local model via Ollama with no external service at all.

**Step 1.** Create a file called `content-guidelines.md` in the server folder and write your guidelines in plain Markdown. The server reads this file on startup.

**Step 2.** In the Design Guardian plugin, open Settings and go to the **AI** tab. Select a provider (Anthropic, OpenAI, or Google) and choose how to connect:
- **Use my existing subscription** (default) — the server calls the provider's CLI on your machine and routes requests through your existing account. No API key needed, but the CLI must be installed and signed in on the machine running the server:
  - Anthropic: install the [Claude CLI](https://docs.anthropic.com/claude-code), then run `claude auth login`
  - OpenAI: install [Codex CLI](https://github.com/openai/codex), then run `codex login`
  - Google: install [Gemini CLI](https://ai.google.dev/gemini-api/docs/gemini-cli), then open `gemini` and sign in
- **API Key** — enter a key from your provider account for pay-as-you-go usage. No CLI required.
- **Ollama** — runs a local model (Llama, Mistral, Phi, etc.) with no external service, account, or CLI.

**Step 3.** Run a scan. When the plugin detects text nodes, it sends them to the server for review against your guidelines. Issues include a plain-language suggestion, and many can be auto-applied in one click.

If no AI provider is configured the content review step is skipped — design system checks are unaffected.

### Referencing external sources in your guidelines

If your guidelines link to external pages — Confluence docs, Notion pages, Google Drive, or any other URL — the server fetches and inlines the content automatically so the AI sees the actual material, not just the link.

**Public pages** are fetched directly over HTTP. No CLI or connector required.

**Login-gated or internal pages** (Confluence, pages behind a VPN or SSO) can't be fetched directly. For these, the server falls back to the Claude CLI and uses whatever MCP connectors you have enabled in your Claude account. This fallback is Claude-specific because MCP connectors (Atlassian, Notion, Google Drive, etc.) are part of the Claude ecosystem — they don't exist in the Codex or Gemini CLIs. This has nothing to do with which AI provider you chose for the content scan itself; it only applies to fetching the source material.

> **Confluence** gets dedicated handling: the server extracts `cloudId` and `pageId` directly from the URL and calls the Atlassian connector with explicit parameters, rather than leaving the model to figure out the URL shape. This makes Confluence page fetches reliable where generic URL fetching would often fail.

To use this with login-gated sources:
1. Install and sign in to the `claude` CLI on the machine running the server (same steps as the "Use my existing subscription" section above)
2. In your Claude account, enable the connectors for the sources your guidelines reference — for example, the Atlassian connector for Confluence
3. Include the full page URL in your guidelines file — the server picks it up automatically on the next scan

If a page can't be fetched (connector not enabled, access not granted), the server skips that URL and the scan continues without it. Failed URLs are retried after 10 minutes.

---

## Configuration

### Required (self-hosted only)

| Setting | Description |
|---|---|
| `FIGMA_PAT` | Your Figma Personal Access Token |

### Optional

| Setting | Default | Description |
|---|---|---|
| `PORT` | `3001` | Starting port. The server tries 3001–3010 in order and uses the first available one. |
| `GUIDELINES_FILE` | `content-guidelines.md` | Path to your content guidelines Markdown file. |
| `AI_CONFIG_FILE` | `ai-config.json` | Path to the AI provider config file. Written by the plugin — do not edit manually. |
| `GUIDELINES_EXTRACT_CACHE_FILE` | `guidelines-extract-cache.json` | Cache for parsed guideline rules. Speeds up repeated scans. |
| `GUIDELINES_EVAL_CACHE_FILE` | `guidelines-eval-cache.json` | Cache for guideline quality evaluations. Survives server restarts. |

### Cloud / multi-user mode (advanced)

Only needed if you are running the server in OAuth mode where each team member signs in with their own Figma account. Single-user setups using `FIGMA_PAT` do not need these.

| Setting | Description |
|---|---|
| `FIGMA_CLIENT_ID` | OAuth app client ID from the Figma developer settings |
| `FIGMA_CLIENT_SECRET` | OAuth app client secret |
| `JWT_SECRET` | A long random string used to sign session tokens |
| `TOKEN_ENCRYPTION_KEY` | A 64-character hex string used to encrypt stored Figma tokens |

---

## License

ISC
