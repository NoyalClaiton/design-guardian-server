# Design Guardian: Server

This is the backend server for the **Design Guardian** Figma plugin.

Design Guardian helps design teams check whether their Figma files follow the rules of their design system. For example, it can flag components, colors, or text styles that are not from the approved library.

This server is what powers that checking. It connects to your Figma account, pulls in your design system library data, and makes it available to the plugin.

---

## How it works

1. You run this server (on your own machine or a hosting platform like Railway)
2. You give it a Figma token so it can access your Figma libraries
3. You point the Design Guardian plugin to your server URL
4. The plugin scans your Figma files and reports any design system violations

---

## Before you start

You will need:

- **Node.js 20 or later** installed on your machine ([download here](https://nodejs.org))
- A **Figma Personal Access Token** (see instructions below)

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

## Configuration

| Setting | Required | Description |
|---|---|---|
| `FIGMA_PAT` | Yes | Your Figma Personal Access Token |
| `PORT` | No | The port the server runs on. Defaults to 3001. Hosting platforms like Railway set this automatically. |

---

## License

ISC
