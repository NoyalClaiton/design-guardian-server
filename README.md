# Design Guardian: Server

This is the backend server for the **Design Guardian** Figma plugin.

Design Guardian helps design teams check whether their Figma files follow the rules of their design system. It can flag components, colors, text styles, spacing, and radius values that are not from the approved library. It can also review text content against written guidelines using AI.

This server powers all of that checking. It connects to your Figma account, pulls in your design system library data, and runs AI content analysis when configured.

---

## What the server does

- **Design system checks** — loads your Figma library components, styles, and variables so the plugin can flag rule violations (wrong components, missing text styles, unapproved color values, etc.)
- **AI content review** — scans text nodes in your designs against a Markdown guidelines file you provide, using an AI provider of your choice (Anthropic, OpenAI, or Google)
- **Library sync** — keeps the plugin's local cache of your design system up to date without requiring a full re-import every time

---

## Before you start

You will need:

- **Node.js 20 or later** installed on your machine ([download here](https://nodejs.org))
- A **Figma Personal Access Token** (see instructions below)
- An **AI provider API key** if you want to use the content review feature (Anthropic, OpenAI, or Google — your choice)

---

## Option 1: Run locally on your machine

**Step 1.** Clone the repository and install dependencies:

```bash
git clone https://github.com/NoyalClaiton/design-guardian-server.git
cd design-guardian-server
npm install
```

**Step 2.** Create a file called `.env` in the project folder with the following content:

```
FIGMA_PAT=paste_your_figma_token_here
```

**Step 3.** Start the server:

```bash
node server.js
```

The server will be running at `http://localhost:3001`. Open the Design Guardian plugin in Figma, go to settings, and enter this URL.

---

## Option 2: Run with Docker

If you have Docker installed, you can run the server without setting up Node.js:

```bash
docker build -t design-guardian-server .
docker run -p 3001:3001 \
  -e FIGMA_PAT=paste_your_figma_token_here \
  design-guardian-server
```

---

## Option 3: Deploy to Railway (hosted in the cloud)

Railway is a hosting platform that runs the server for you so you do not need to keep your own machine running.

1. Fork this repository to your own GitHub account
2. Go to [railway.com](https://railway.com) and create a new project from your forked repo
3. In the Railway dashboard, go to Variables and add `FIGMA_PAT` with your Figma token
4. Railway will build and deploy the server automatically

Once deployed, copy the public URL Railway gives you and enter it in the Design Guardian plugin settings.

---

## How to get a Figma Personal Access Token

A Personal Access Token (PAT) is a key that lets the server read your Figma library data on your behalf.

1. Open Figma in your browser and click your profile picture at the top right
2. Go to **Settings**, then the **Security** tab
3. Under **Personal access tokens**, click **Generate new token**
4. Give it a name like "Design Guardian" and click generate
5. Copy the token straight away as it will not be shown again

Use a Figma account that has access to all the design system libraries you want to check against.

---

## Setting up AI content review

The AI content review feature checks text in your Figma designs against a guidelines document you write (for example, a tone of voice guide or a content checklist).

**Step 1.** Create a file called `content-guidelines.md` in the server folder and write your guidelines in plain Markdown.

**Step 2.** In the Design Guardian plugin, open Settings and go to the **AI** tab. Enter your AI provider API key and select a provider (Anthropic, OpenAI, or Google). The plugin saves this to the server — no additional env vars are needed.

**Step 3.** Run a scan. When the plugin detects text nodes, it will send them to the server for review against your guidelines.

If you do not configure an AI provider, the content review feature is simply skipped — design system checks are unaffected.

---

## Configuration

### Required

| Setting | Description |
|---|---|
| `FIGMA_PAT` | Your Figma Personal Access Token |

### Optional

| Setting | Default | Description |
|---|---|---|
| `PORT` | `3001` | Port the server listens on. Hosting platforms like Railway set this automatically. |
| `GUIDELINES_FILE` | `content-guidelines.md` | Path to your content guidelines Markdown file. |
| `AI_CONFIG_FILE` | `ai-config.json` | Path to the AI provider config file (written by the plugin — do not edit manually). |
| `GUIDELINES_EXTRACT_CACHE_FILE` | `guidelines-extract-cache.json` | Cache for parsed guideline rules. Speeds up repeated scans. |
| `GUIDELINES_EVAL_CACHE_FILE` | `guidelines-eval-cache.json` | Cache for guideline quality evaluations. Survives server restarts. |

### Cloud / multi-user mode (advanced)

If you are deploying the server for a team where each person logs in with their own Figma account, you will also need:

| Setting | Description |
|---|---|
| `FIGMA_CLIENT_ID` | OAuth app client ID from the Figma developer settings |
| `FIGMA_CLIENT_SECRET` | OAuth app client secret |
| `JWT_SECRET` | A long random string used to sign session tokens |
| `TOKEN_ENCRYPTION_KEY` | A 64-character hex string used to encrypt stored Figma tokens |

Single-user setups (one `FIGMA_PAT` for one person or a shared team account) do not need these.

---

## License

ISC
