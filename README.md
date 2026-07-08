# Design Guardian: Server

This is the backend server for the **Design Guardian** Figma plugin.

Design Guardian checks Figma files against your design system rules — flagging unapproved components, missing text styles, wrong color values, spacing and radius violations, and more. It can also review copy against written content guidelines using AI.

This server is what powers those checks. It connects to your Figma libraries, runs AI analysis when configured, and responds to requests from the plugin.

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

The AI content review feature checks text in your Figma designs against a guidelines document you write (for example, a tone of voice guide or writing style checklist).

**Step 1.** Create a file called `content-guidelines.md` in the server folder and write your guidelines in plain Markdown. The server reads this file on startup.

**Step 2.** In the Design Guardian plugin, open Settings and go to the **AI** tab. Enter your AI provider API key and select a provider (Anthropic, OpenAI, or Google). The plugin saves this configuration to the server.

**Step 3.** Run a scan. When the plugin detects text nodes, it sends them to the server for review against your guidelines.

If no AI provider is configured the content review step is skipped — design system checks are unaffected.

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
