require('dotenv').config();

// Fail fast if Node is too old. fetch is built-in from Node 18; older versions throw
// "fetch is not defined" deep in library sync which is very hard to diagnose.
if (typeof fetch === 'undefined') {
  console.error('[Design Guardian] FATAL: Node.js ' + process.version + ' does not have built-in fetch.');
  console.error('[Design Guardian] Please upgrade to Node.js 18 or later. Download at: https://nodejs.org');
  process.exit(1);
}

const http = require('http');
const https = require('https');
const net = require('net');
const { AsyncLocalStorage } = require('async_hooks');

// Suppress the mDNS "already in use" error that fires when two server instances
// run on the same machine. The error originates deep inside bonjour's event chain
// and can't be caught by errorCallback alone -- a process-level handler is needed.
process.on('uncaughtException', function(err) {
  var msg = err && err.message ? err.message : String(err);
  var stack = err && err.stack ? err.stack : '';
  if (msg.indexOf('already in use') !== -1 && (stack.indexOf('bonjour') !== -1 || stack.indexOf('multicast-dns') !== -1)) {
    console.log('[Design Guardian] Note: mDNS auto-discovery is already advertised by another server instance. This is harmless -- your server is running normally and the plugin can connect using the URL shown above.');
    return;
  }
  console.error('[Design Guardian] Unexpected error:', err);
  process.exit(1);
});

let _bonjour = null;
try {
  const { Bonjour } = require('bonjour-service');
  _bonjour = new Bonjour();
  if (_bonjour.server) {
    _bonjour.server.errorCallback = function(err) {
      if (err && typeof err.message === 'string' && err.message.indexOf('already in use') !== -1) {
        console.log('[Design Guardian] Note: mDNS auto-discovery is already advertised by another server instance. This is harmless -- your server is running normally.');
        return;
      }
      throw err;
    };
  }
} catch (e) {}
const fs = require('fs');
const path = require('path');
const { URL } = require('url');
const crypto = require('crypto');
const jwt = require('jsonwebtoken');
const { execSync, spawnSync, spawn, execFile } = require('child_process');
const os = require('os');

const PORT = parseInt(process.env.PORT, 10) || 3001;
const FIGMA_PAT = process.env.FIGMA_PAT;

// ── OAuth / Cloud auth config ────────────────────────────────────────────────
const FIGMA_CLIENT_ID = process.env.FIGMA_CLIENT_ID || '';
const FIGMA_CLIENT_SECRET = process.env.FIGMA_CLIENT_SECRET || '';
const FIGMA_REDIRECT_URI = process.env.FIGMA_REDIRECT_URI || `http://localhost:${PORT}/auth/figma/callback`;
const JWT_SECRET = process.env.JWT_SECRET || '';
// 32-byte hex key for AES-256-GCM token encryption
const TOKEN_ENC_KEY = process.env.TOKEN_ENCRYPTION_KEY ? Buffer.from(process.env.TOKEN_ENCRYPTION_KEY, 'hex') : null;
// Pending auth states expire after 10 minutes
const PENDING_AUTH_TTL_MS = 10 * 60 * 1000;
const MAX_BODY_BYTES = 5 * 1024 * 1024; // 5 MB hard cap on all POST bodies that accept file content

// escHtml: escapes HTML special chars for safe interpolation into HTML page responses.
function escHtml(s) {
  return String(s).replace(/[&<>"]/g, function(c) {
    return { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c];
  });
}

// ── User store (fs + in-memory Maps, no native dependencies) ─────────────────
// users: persisted to a JSON file. Two Maps for O(1) lookup by id or figmaUserId.
// pending_auth: in-memory only (10-min TTL, no persistence needed).
// On Railway, default to /data/users.json (volume mount point).
// Locally, fall back to users.json next to server.js.
const USERS_FILE = process.env.USERS_FILE ||
  (process.env.RAILWAY_ENVIRONMENT ? '/data/users.json' : path.join(__dirname, 'users.json'));

// ── AI content review config ──────────────────────────────────────────────────
// Stored in ai-config.json alongside users.json. Holds provider, model, API key.
const AI_CONFIG_FILE = process.env.AI_CONFIG_FILE ||
  (process.env.RAILWAY_ENVIRONMENT ? '/data/ai-config.json' : path.join(__dirname, 'ai-config.json'));

// Content guidelines file — uploaded by user or pasted as text, sent to AI with each scan.
const GUIDELINES_FILE = process.env.GUIDELINES_FILE ||
  (process.env.RAILWAY_ENVIRONMENT ? '/data/content-guidelines.md' : path.join(__dirname, 'content-guidelines.md'));

// PROPOSAL: cache of the guidelines doc split into short quotable excerpts (general +
// per-component), keyed by a hash of the guidelines content so it's only regenerated when the
// guidelines actually change, not on every scan. See extractGuidelineRules().
const GUIDELINES_EXTRACT_CACHE_FILE = process.env.GUIDELINES_EXTRACT_CACHE_FILE ||
  (process.env.RAILWAY_ENVIRONMENT ? '/data/guidelines-extract-cache.json' : path.join(__dirname, 'guidelines-extract-cache.json'));

// Guidelines-quality-evaluation results cache, keyed by content hash — same idea as
// GUIDELINES_EXTRACT_CACHE_FILE above. Was in-memory only until now, so it got wiped on every
// server restart and re-paid the full AI cost even for content evaluated many times before.
const GUIDELINES_EVAL_CACHE_FILE = process.env.GUIDELINES_EVAL_CACHE_FILE ||
  (process.env.RAILWAY_ENVIRONMENT ? '/data/guidelines-eval-cache.json' : path.join(__dirname, 'guidelines-eval-cache.json'));

// Default AI persona — sent as the opening instruction in every content scan prompt.
// Users can override this via the plugin UI; an empty string in ai-config.json means "use default".
const DEFAULT_AI_PERSONA = [
  'You are a design content reviewer. Check the text content below against the provided guidelines.',
  '',
  'SKIP these, they are Figma component scaffolding with no product meaning:',
  '- Text that is literally a single generic word used as a UI element name: "Slot", "Text", "Checkbox", "Toggle"',
  '- Instructional Figma layer labels like "Swap me with your body component." or "Copy me -> detach me"',
  '- Pure numeric values like "20" used as counters or badges with no surrounding context',
  '',
  'DO evaluate these, they are real product copy regardless of where they appear:',
  '- Any text a designer clearly wrote for end users: headings, descriptions, error messages, empty states, CTAs',
  '- Button labels, even short ones, especially check capitalisation (e.g. "ACTION" should be sentence case if guidelines require it)',
  '- Any word or phrase that is not literally the name of a UI component type',
].join('\n');

// Default models per provider — used when no model is explicitly saved in ai-config.json.
const AI_DEFAULT_MODELS = {
  anthropic: 'claude-haiku-4-5-20251001',
  openai: 'gpt-4o-mini',
  google: 'gemini-1.5-flash',
  ollama: 'llama3',
};

// AI_PRICING_PER_1M: rough $ per 1M tokens, for logging cost estimates only — NOT billing-accurate.
// Verify against each provider's current pricing page before trusting these for real budgeting;
// update the numbers here if a provider changes pricing. cacheRead/cacheWrite only apply to
// Anthropic's prompt-caching tokens (cache_read_input_tokens / cache_creation_input_tokens).
const AI_PRICING_PER_1M = {
  'claude-haiku-4-5-20251001': { input: 1, output: 5, cacheRead: 0.1, cacheWrite: 1.25 },
  'gpt-4o-mini': { input: 0.15, output: 0.6 },
  'gemini-1.5-flash': { input: 0.075, output: 0.3 },
};

// estimateCostUsd: returns a $ estimate for one AI call, or null if the model isn't in the
// pricing table above (e.g. Ollama is local/free, or an unlisted model).
function estimateCostUsd(model, inputTokens, outputTokens, cacheReadTokens, cacheWriteTokens) {
  const rate = AI_PRICING_PER_1M[model];
  if (!rate) return null;
  const regularInput = Math.max(0, (inputTokens || 0) - (cacheReadTokens || 0) - (cacheWriteTokens || 0));
  const cost =
    (regularInput / 1e6) * rate.input +
    ((outputTokens || 0) / 1e6) * rate.output +
    ((cacheReadTokens || 0) / 1e6) * (rate.cacheRead || rate.input) +
    ((cacheWriteTokens || 0) / 1e6) * (rate.cacheWrite || rate.input);
  return cost;
}

// _aiScanSession: rolling accumulator across the burst of /ai/scan(-batch) calls that make up one
// "Scan" click in the plugin (many frames = many calls in quick succession). Auto-resets after
// 30s of no AI-call activity, on the assumption a new burst is a new scan rather than a continuation
// of the last one. Purely for comparing "before" vs "after" totals in the server log — not persisted.
var _aiScanSession = { startedAt: 0, lastCallAt: 0, calls: 0, inputTokens: 0, outputTokens: 0, cacheReadTokens: 0, cacheWriteTokens: 0, costUsd: 0, costUnknown: false, elapsedMs: 0 };
const AI_SCAN_SESSION_IDLE_RESET_MS = 30000;

// _requestCostStore: per-request cost tracking, isolated from _aiScanSession's 30s-idle reset.
// That reset compares against the PREVIOUS call's completion time — but a single content-scan
// call routinely takes 90-150s+ on its own, so by the time it finishes and logs, _aiScanSession
// has already "gone idle" and reset mid-request, silently zeroing out everything logged before it
// (verified directly: a request's own final total_cost came back as just its last call's cost,
// nowhere near the true sum of every AI call the request actually made). AsyncLocalStorage carries
// an accumulator through the whole async call chain of ONE HTTP request — extraction, URL/component
// fetches, the scan pass and any retry — without needing every function in that chain to accept and
// thread through an extra parameter, and without being affected by unrelated activity or resets.
const _requestCostStore = new AsyncLocalStorage();

// logAiUsage: shared logger for every provider call — logs this call's tokens/cost/time, then
// rolls it into the current scan-session accumulator and logs the running session total so far.
// preComputedCostUsd: pass the provider's own reported cost when available (e.g. the Claude Code
// CLI wrapper's `total_cost_usd`, which is real billing data) — takes priority over the estimate
// table below, which only exists for providers whose HTTP response doesn't include actual cost.
function logAiUsage(label, model, inputTokens, outputTokens, cacheReadTokens, cacheWriteTokens, elapsedMs, preComputedCostUsd) {
  const now = Date.now();
  if (now - _aiScanSession.lastCallAt > AI_SCAN_SESSION_IDLE_RESET_MS) {
    _aiScanSession = { startedAt: now, lastCallAt: now, calls: 0, inputTokens: 0, outputTokens: 0, cacheReadTokens: 0, cacheWriteTokens: 0, costUsd: 0, costUnknown: false, elapsedMs: 0 };
  }
  const cost = (preComputedCostUsd !== undefined && preComputedCostUsd !== null)
    ? preComputedCostUsd
    : estimateCostUsd(model, inputTokens, outputTokens, cacheReadTokens, cacheWriteTokens);
  const cacheInfo = (cacheReadTokens || cacheWriteTokens) ? (' cache_read=' + (cacheReadTokens || 0) + ' cache_write=' + (cacheWriteTokens || 0)) : '';
  const costInfo = cost !== null ? (' cost=$' + cost.toFixed(4) + (preComputedCostUsd !== undefined && preComputedCostUsd !== null ? ' (actual)' : ' (est)')) : ' cost=n/a';
  console.log('[Design Guardian] AI ' + (label || 'ai') + ' model=' + model + ' in=' + (inputTokens || '?') + ' out=' + (outputTokens || '?') + cacheInfo + costInfo + ' elapsed=' + elapsedMs + 'ms');

  _aiScanSession.lastCallAt = now;
  _aiScanSession.calls += 1;
  _aiScanSession.inputTokens += inputTokens || 0;
  _aiScanSession.outputTokens += outputTokens || 0;
  _aiScanSession.cacheReadTokens += cacheReadTokens || 0;
  _aiScanSession.cacheWriteTokens += cacheWriteTokens || 0;
  _aiScanSession.elapsedMs += elapsedMs || 0;
  if (cost === null) _aiScanSession.costUnknown = true;
  else _aiScanSession.costUsd += cost;
  var sessionCostInfo = _aiScanSession.costUnknown ? ('$' + _aiScanSession.costUsd.toFixed(4) + '+ (some calls unpriced)') : ('$' + _aiScanSession.costUsd.toFixed(4));
  console.log('[Design Guardian] AI session-so-far: calls=' + _aiScanSession.calls +
    ' in=' + _aiScanSession.inputTokens + ' out=' + _aiScanSession.outputTokens +
    ' cache_read=' + _aiScanSession.cacheReadTokens + ' cache_write=' + _aiScanSession.cacheWriteTokens +
    ' cost=' + sessionCostInfo + ' ai_elapsed=' + _aiScanSession.elapsedMs + 'ms' +
    ' wall_elapsed=' + (now - _aiScanSession.startedAt) + 'ms');

  // See _requestCostStore's comment above — this is the actually-reliable per-request total,
  // unaffected by _aiScanSession's idle reset above.
  var reqStore = _requestCostStore.getStore();
  if (reqStore) {
    reqStore.calls += 1;
    if (cost === null) reqStore.costUnknown = true;
    else reqStore.costUsd += cost;
  }
}

// loadAiConfig: reads AI provider config from disk; returns safe defaults if file is missing.
// Auto-generates a pairingToken if one is not already stored (used for CSRF protection on POST /ai/* endpoints).
function loadAiConfig() {
  try {
    const cfg = JSON.parse(fs.readFileSync(AI_CONFIG_FILE, 'utf8'));
    if (!cfg.pairingToken) {
      cfg.pairingToken = crypto.randomBytes(16).toString('hex');
      saveAiConfig(cfg);
    }
    return cfg;
  } catch (_) {
    const cfg = { provider: '', model: '', apiKey: '', ollamaEndpoint: 'http://localhost:11434', pairingToken: crypto.randomBytes(16).toString('hex') };
    saveAiConfig(cfg);
    return cfg;
  }
}

// saveAiConfig: writes AI provider config to disk (creates parent dirs if needed).
function saveAiConfig(cfg) {
  fs.mkdirSync(path.dirname(AI_CONFIG_FILE), { recursive: true });
  fs.writeFileSync(AI_CONFIG_FILE, JSON.stringify(cfg, null, 2));
}

// aiTokenGuard: validates the X-DG-Token header against the stored pairing token.
// Returns true if the request is authorized; returns false and sends a 401 if not.
function aiTokenGuard(req, res) {
  const cfg = loadAiConfig();
  if (cfg.pairingToken && req.headers['x-dg-token'] !== cfg.pairingToken) {
    sendJson(res, 401, { error: 'Invalid or missing plugin token. Reconnect to the server to refresh.' });
    return false;
  }
  return true;
}

let _nextUserId = 1;
const _usersByFigmaId = new Map();
const _usersById = new Map();

(function loadUsers() {
  try {
    const data = JSON.parse(fs.readFileSync(USERS_FILE, 'utf8'));
    _nextUserId = data.nextId || 1;
    (data.users || []).forEach(function(u) {
      _usersByFigmaId.set(u.figmaUserId, u);
      _usersById.set(u.id, u);
    });
  } catch (_) {}
})();

// Guidelines evaluation results cache, keyed by SHA-256 content hash — persisted to
// GUIDELINES_EVAL_CACHE_FILE so it survives server restarts, not just in-memory across one
// process lifetime. Avoids re-running the AI eval when the guidelines file has not changed.
var _evalGuidelinesCache = {};
try {
  _evalGuidelinesCache = JSON.parse(fs.readFileSync(GUIDELINES_EVAL_CACHE_FILE, 'utf8')) || {};
} catch (_) {}

function persistEvalGuidelinesCache() {
  try {
    fs.writeFileSync(GUIDELINES_EVAL_CACHE_FILE, JSON.stringify(_evalGuidelinesCache));
  } catch (err) {
    console.error('[Design Guardian] failed to persist guidelines eval cache:', err.message);
  }
}
// In-flight promises keyed by content hash — coalesces concurrent requests for
// identical content so only one Claude call is made even if N arrive simultaneously.
const _evalGuidelinesInFlight = {};
// In-memory only (not persisted) — a user clicking "Explain" twice on the exact same issue in one
// session is the only case this needs to cover; not worth a disk cache for that.
const _explainIssueCache = {};
// URL content cache: keyed by URL, value = { content, fetchedAt } for a success, or
// { failed: true, fetchedAt, consecutiveFailures } for a failure.
const _urlContentCache = {};
const _URL_CACHE_TTL = 60 * 60 * 1000; // 1 hour (successes)
const _URL_FAILURE_CACHE_TTL = 10 * 60 * 1000; // 10 minutes — base delay, see getFailureRetryDelayMs

// getFailureRetryDelayMs: escalating backoff based on how many times IN A ROW a URL has failed
// (reset to 0 by any success). We can't tell a genuine, permanent failure (no connector configured,
// page deleted, requires login we'll never have) apart from a transient one (timeout, rate limit,
// momentary outage) from a single attempt — the failure reason is free-form model text, not a
// reliable signal to key logic off of (verified directly: the same dead URL got a different
// human-readable reason on different runs). Repeated failure itself is the more reliable signal
// instead: a transient issue usually clears on the very next real attempt; a genuine one keeps
// failing attempt after attempt. So the first failure gets the original short retry (still assume
// transient, check back soon); every consecutive failure after that pushes the retry further out,
// capping at a day so a URL that structurally cannot succeed stops costing real money on every scan
// indefinitely. Any success resets the count to 0, so a fixed URL (connector added, site back up)
// is treated as fresh again rather than stuck in an escalated penalty.
function getFailureRetryDelayMs(consecutiveFailures) {
  if (consecutiveFailures <= 1) return _URL_FAILURE_CACHE_TTL; // 10 min
  if (consecutiveFailures === 2) return 60 * 60 * 1000;        // 1 hour
  return 24 * 60 * 60 * 1000;                                  // 24 hours, 3rd+ in a row
}

// _claudeCliAvailable: cached on first use so we don't spawn a failing process on every URL fetch
// when the CLI isn't installed. null = unchecked, true/false = result. Connector access (Confluence,
// Notion, Google Drive, etc.) is independent of the configured AI scan provider — any user who has
// the Claude CLI installed gets it, regardless of whether they use Anthropic, OpenAI, Gemini, or Ollama.
var _claudeCliAvailable = null;
async function checkClaudeCliAvailable() {
  if (_claudeCliAvailable !== null) return _claudeCliAvailable;
  _claudeCliAvailable = await isCliInstalled('claude');
  if (!_claudeCliAvailable) {
    console.log('[Design Guardian] claude CLI not found — connector-based URL fetching (Confluence, Notion, Google Drive, etc.) is disabled. This is separate from your AI scan provider. Install the Claude CLI to enable it: https://docs.anthropic.com/claude-code');
  }
  return _claudeCliAvailable;
}

// saveUsers: persists the in-memory user store to USERS_FILE (full replace, not append).
function saveUsers() {
  fs.mkdirSync(path.dirname(USERS_FILE), { recursive: true });
  fs.writeFileSync(USERS_FILE, JSON.stringify({
    nextId: _nextUserId,
    users: Array.from(_usersByFigmaId.values())
  }, null, 2));
}

// upsertUser: creates a new user or updates profile + tokens for an existing one; returns the user object.
function upsertUser(figmaUserId, figmaHandle, figmaEmail, accessToken, refreshToken, tokenExpiresAt) {
  let user = _usersByFigmaId.get(figmaUserId);
  if (user) {
    user.figmaHandle = figmaHandle;
    user.figmaEmail = figmaEmail;
    user.accessToken = accessToken;
    user.refreshToken = refreshToken;
    user.tokenExpiresAt = tokenExpiresAt;
  } else {
    user = { id: _nextUserId++, figmaUserId, figmaHandle, figmaEmail, accessToken, refreshToken, tokenExpiresAt, createdAt: Math.floor(Date.now() / 1000) };
    _usersByFigmaId.set(figmaUserId, user);
    _usersById.set(user.id, user);
  }
  saveUsers();
  return user;
}

function getUserById(id) {
  return _usersById.get(parseInt(id)) || null;
}

// updateUserToken: refreshes only the access token + expiry after an OAuth token refresh; skips profile fields.
function updateUserToken(id, accessToken, tokenExpiresAt) {
  const user = _usersById.get(parseInt(id));
  if (!user) return;
  user.accessToken = accessToken;
  user.tokenExpiresAt = tokenExpiresAt;
  saveUsers();
}

const _pendingAuth = new Map();

function setPendingAuth(state, jwtToken) {
  _pendingAuth.set(state, { jwt: jwtToken, createdAt: Date.now() });
}

function getPendingAuth(state) {
  return _pendingAuth.get(state) || null;
}

function deletePendingAuth(state) {
  _pendingAuth.delete(state);
}

// ── Token encryption helpers ─────────────────────────────────────────────────
// AES-256-GCM: produces iv:authTag:ciphertext (all hex, colon-separated).
function encryptToken(plaintext) {
  if (!TOKEN_ENC_KEY) throw new Error('TOKEN_ENCRYPTION_KEY not set');
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', TOKEN_ENC_KEY, iv);
  const encrypted = Buffer.concat([cipher.update(plaintext, 'utf8'), cipher.final()]);
  return iv.toString('hex') + ':' + cipher.getAuthTag().toString('hex') + ':' + encrypted.toString('hex');
}

function decryptToken(stored) {
  if (!TOKEN_ENC_KEY) throw new Error('TOKEN_ENCRYPTION_KEY not set');
  const [ivHex, tagHex, dataHex] = stored.split(':');
  const decipher = crypto.createDecipheriv('aes-256-gcm', TOKEN_ENC_KEY, Buffer.from(ivHex, 'hex'));
  decipher.setAuthTag(Buffer.from(tagHex, 'hex'));
  return decipher.update(Buffer.from(dataHex, 'hex')) + decipher.final('utf8');
}

// ── JWT helpers ───────────────────────────────────────────────────────────────
// signJwt: issues a 90-day signed JWT with the user's internal ID as the sub claim.
function signJwt(userId) {
  if (!JWT_SECRET) throw new Error('JWT_SECRET not set');
  return jwt.sign({ sub: String(userId) }, JWT_SECRET, { expiresIn: '90d' });
}

// Returns the user row for a valid Bearer token, or null.
function getUserFromRequest(req) {
  if (!JWT_SECRET) return null;
  const auth = req.headers['authorization'] || '';
  if (!auth.startsWith('Bearer ')) return null;
  try {
    const payload = jwt.verify(auth.slice(7), JWT_SECRET);
    return getUserById(payload.sub);
  } catch (_) {
    return null;
  }
}

// getFigmaAuthHeaders: returns the correct Figma API auth headers for this request.
// Cloud mode: uses the signed-in user's OAuth access token (via Bearer JWT).
// Local mode: falls back to the FIGMA_PAT environment variable.
async function getFigmaAuthHeaders(req) {
  const user = getUserFromRequest(req);
  if (user) {
    try {
      const token = await getFigmaToken(user);
      if (token) return { 'Authorization': 'Bearer ' + token };
    } catch (e) {
      console.warn('[getFigmaAuthHeaders] OAuth token error for user', user.id, ':', e.message);
    }
  }
  return { 'X-Figma-Token': FIGMA_PAT || '' };
}

// hasFigmaAuth: true if the request can authenticate Figma API calls.
// Accepts either a signed-in OAuth user (JWT) or a configured FIGMA_PAT.
function hasFigmaAuth(req) {
  return Boolean(getUserFromRequest(req)) || Boolean(FIGMA_PAT);
}

// ── Figma token refresh ───────────────────────────────────────────────────────
// Refreshes the stored access token if it expires within 10 minutes.
// Returns the current (possibly refreshed) access token as plaintext.
async function getFigmaToken(user) {
  const TEN_MIN = 10 * 60;
  const nowSec = Math.floor(Date.now() / 1000);
  if (user.tokenExpiresAt && user.tokenExpiresAt - nowSec > TEN_MIN) {
    return decryptToken(user.accessToken);
  }
  // Refresh
  const refreshToken = decryptToken(user.refreshToken);
  const body = new URLSearchParams({
    client_id: FIGMA_CLIENT_ID,
    client_secret: FIGMA_CLIENT_SECRET,
    redirect_uri: FIGMA_REDIRECT_URI,
    code: refreshToken,
    grant_type: 'refresh_token',
  });
  const resp = await fetchJson('https://api.figma.com/v1/oauth/refresh', {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: body.toString(),
  });
  const expiresAt = Math.floor(Date.now() / 1000) + (resp.expires_in || 7776000);
  updateUserToken(user.id, encryptToken(resp.access_token), expiresAt);
  return resp.access_token;
}

// ── Library cache with LRU eviction based on memory pressure ────────────────
// Stores library responses by fileKey with size tracking and LRU eviction.
// When total cache size exceeds MAX_CACHE_SIZE_MB, evicts least-recently-used entries.
// Tracks: lastAccessed (for LRU), timestamp (for freshness), size (for memory pressure)
const libraryCache = new Map(); // fileKey -> { data, timestamp, lastAccessed, sizeBytes }
let totalCacheSizeBytes = 0;
// Tracks keys with an active background getLibraryData job. Prevents parallel syncs
// for the same key when the pending cache entry expires before the job finishes.
const activeSyncs = new Set();
// Truncate file keys in logs to avoid leaking which Figma files are synced.
function shortKey(key) { return key ? String(key).slice(0, 8) + '...' : '(none)'; }
const MAX_CACHE_SIZE_MB = 50;
const MAX_CACHE_SIZE_BYTES = MAX_CACHE_SIZE_MB * 1024 * 1024;
// Cache invalidation strategy: based on library's lastModified timestamp, not TTL
// When library hasn't changed, reuse cached data indefinitely
// When library changes, re-fetch and rebuild cache
const CACHE_TTL_MS = 30 * 60 * 1000; // 30 minutes (fallback safety net only if metadata fetch fails)
// How long to skip fetchLibraryPublishedMetadata on repeated status polls for the same complete library
const VALIDATION_SKIP_MS = 5 * 60 * 1000; // 5 minutes

// ── Verification result cache ────────────────────────────────────────────────
// Caches /verify-components results to avoid re-fetching known-dead component keys
// on every scan. Keys are component keys; values include result + expiry timestamp.
// TTL by outcome: 404 (deleted component) = 24h, 200 (live) = 1h, 429 (rate-limited) = 5min
const verificationCache = new Map(); // componentKey -> { result, expiresAt }
const VERIFY_TTL_404 = 24 * 60 * 60 * 1000;
const VERIFY_TTL_200 = 60 * 60 * 1000;
const VERIFY_TTL_429 = 5 * 60 * 1000;
const VERIFY_CONCURRENCY = 4; // max parallel Figma API calls in verify-components

// ── LRU Cache Management Functions ───────────────────────────────────────
function getCacheEntrySize(data) {
  // Rough estimate: JSON.stringify length in bytes
  try {
    return JSON.stringify(data).length;
  } catch (err) {
    return 1024 * 1024; // 1MB fallback
  }
}

function evictLRUIfNeeded() {
  if (totalCacheSizeBytes <= MAX_CACHE_SIZE_BYTES) {
    return; // No eviction needed
  }


  // Find least recently used entry
  let lruKey = null;
  let lruTime = Infinity;

  for (const [key, entry] of libraryCache.entries()) {
    if (entry.lastAccessed < lruTime) {
      lruTime = entry.lastAccessed;
      lruKey = key;
    }
  }

  if (lruKey) {
    const removed = libraryCache.get(lruKey);
    totalCacheSizeBytes -= removed.sizeBytes;
    libraryCache.delete(lruKey);

    // Recursively evict more if still over limit
    if (totalCacheSizeBytes > MAX_CACHE_SIZE_BYTES) {
      evictLRUIfNeeded();
    }
  }
}

function cacheGet(key) {
  const entry = libraryCache.get(key);
  if (entry) {
    entry.lastAccessed = Date.now(); // Update access time
    return entry;
  }
  return null;
}

function cacheSet(key, data) {
  const sizeBytes = getCacheEntrySize(data);
  const now = Date.now();
  const entry = {
    data,
    timestamp: now,
    lastAccessed: now,
    lastValidatedAt: now,
    sizeBytes
  };

  // If entry exists, subtract old size
  if (libraryCache.has(key)) {
    totalCacheSizeBytes -= libraryCache.get(key).sizeBytes;
  }

  libraryCache.set(key, entry);
  totalCacheSizeBytes += sizeBytes;


  // Trigger LRU eviction if needed
  evictLRUIfNeeded();
}

// ── HTTP helpers ─────────────────────────────────────────────────────────────
// sendJson: serializes data as JSON and writes it with CORS + no-cache headers.
function sendJson(res, status, data) {
  const jsonString = JSON.stringify(data);
  res.writeHead(status, {
    'Content-Type': 'application/json',
    'Cache-Control': 'no-store',
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Methods': 'GET,POST,DELETE,OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type,X-DG-Token',
    'Access-Control-Allow-Private-Network': 'true'
  });
  res.end(jsonString);
}

// fetchJson: makes an HTTP request and parses JSON; throws on non-2xx or JSON parse failure.
// label is used in error messages — pass a provider name for non-Figma calls (e.g. 'Anthropic API').
async function fetchJson(url, options = {}, label = 'Figma API') {

  // Timeout covers both headers AND body download. Cleared only after response.text()
  // completes -- clearing at header arrival left large body reads with no timeout.
  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), 240000);

  try {
    const response = await fetch(url, { ...options, signal: controller.signal });
    const text = await response.text();
    clearTimeout(timeoutId);

    let json;
    try {
      json = JSON.parse(text);
    } catch (e) {
      throw new Error(`Invalid JSON from ${label}: ${text}`);
    }

    if (!response.ok) {
      const detail = json?.err || json?.message || json?.error || JSON.stringify(json);
      throw new Error(`${label} ${response.status}: ${detail}`);
    }

    return json;
  } catch (error) {
    clearTimeout(timeoutId);
    if (error.name === 'AbortError') {
      throw new Error(`${label} timeout (240s)`);
    }
    throw error;
  }
}

// fetchJsonOptional: like fetchJson but returns { ok, data } / { ok: false, error } instead of throwing.
async function fetchJsonOptional(url, options = {}) {

  try {
    // Timeout covers headers AND body. Cleared only after response.text() completes.
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 120000);

    let response;
    try {
      response = await fetch(url, { ...options, signal: controller.signal });
    } catch (fetchError) {
      clearTimeout(timeoutId);
      if (fetchError.name === 'AbortError') {
        return { ok: false, error: 'Figma API timeout (120s)' };
      }
      throw fetchError;
    }

    let text;
    try {
      text = await response.text();
    } catch (bodyError) {
      clearTimeout(timeoutId);
      if (bodyError.name === 'AbortError') {
        return { ok: false, error: 'Figma API timeout (120s)' };
      }
      throw bodyError;
    }
    clearTimeout(timeoutId);

    let json;
    try {
      json = JSON.parse(text);
    } catch (e) {
      return { ok: false, error: `Invalid JSON: ${text}` };
    }

    if (!response.ok) {
      return {
        ok: false,
        error: json?.err || json?.message || `HTTP ${response.status}`,
        status: response.status
      };
    }

    return { ok: true, data: json };
  } catch (error) {
    return { ok: false, error: error.message || 'Unknown optional fetch error' };
  }
}

// normalizeFileKey: extracts a bare file key from a full Figma URL, or returns the input as-is.
function normalizeFileKey(input) {
  if (!input) return '';
  const value = String(input).trim();

  const fileMatch = value.match(/figma\.com\/(?:file|design)\/([a-zA-Z0-9]+)/);
  if (fileMatch) return fileMatch[1];

  return value;
}

// Fetch published components and styles to compute library's latest update timestamp
// Based on individual component/style updated_at values, not file-level lastModified
// Returns { ok: true, lastPublished: '...' } or { ok: false, error: '...' }
async function fetchLibraryPublishedMetadata(fileKey, headers) {
  const [componentsResult, stylesResult] = await Promise.all([
    fetchJsonOptional(`https://api.figma.com/v1/files/${fileKey}/components`, { headers }),
    fetchJsonOptional(`https://api.figma.com/v1/files/${fileKey}/styles`, { headers })
  ]);

  if (!componentsResult.ok && !stylesResult.ok) {
    return { ok: false, error: 'Could not fetch components or styles metadata' };
  }

  const allUpdatedAts = [];
  if (componentsResult.ok && componentsResult.data?.meta?.components) {
    componentsResult.data.meta.components.forEach(c => {
      if (c.updated_at) allUpdatedAts.push(c.updated_at);
    });
  }
  if (stylesResult.ok && stylesResult.data?.meta?.styles) {
    stylesResult.data.meta.styles.forEach(s => {
      if (s.updated_at) allUpdatedAts.push(s.updated_at);
    });
  }

  const lastPublished = allUpdatedAts.length > 0
    ? allUpdatedAts.slice().sort().pop()
    : null;

  return {
    ok: true,
    lastPublished: lastPublished
  };
}

// uniqueBy: deduplicates items by a key function; first occurrence wins.
function uniqueBy(items, getKey) {
  const map = new Map();
  for (const item of items) {
    const key = getKey(item);
    if (!key) continue;
    if (!map.has(key)) {
      map.set(key, item);
    }
  }
  return Array.from(map.values());
}

// normalizeComponentsFromFile: maps raw file API component entries to the shared normalized shape.
function normalizeComponentsFromFile(fileData) {
  const raw = Object.entries(fileData.components || {});
  return raw.map(([nodeId, item]) => ({
    key: item.key || '',
    nodeId: nodeId || '',
    name: item.name || '',
    description: item.description || '',
    pageName: item.containing_frame?.pageName || '',
    containingFrame: item.containing_frame?.name || '',
    type: item.type || 'unknown',
    source: 'file'
  }));
}

// normalizePublishedComponents: maps raw published components API response to the shared normalized shape.
function normalizePublishedComponents(componentsData) {
  return (componentsData.meta?.components || []).map((item) => ({
    key: item.key || '',
    nodeId: item.node_id || '',
    name: item.name || '',
    description: item.description || '',
    pageName: item.containing_frame?.pageName || '',
    containingFrame: item.containing_frame?.name || '',
    source: 'published',
    updatedAt: item.updated_at || ''
  }));
}

// normalizeStylesFromFile: maps raw file API style entries to the shared normalized shape.
function normalizeStylesFromFile(fileData) {
  const raw = Object.values(fileData.styles || {});
  return raw.map((item) => {
    const normalized = {
      key: item.key || '',
      nodeId: item.node_id || '',
      name: item.name || '',
      styleType: item.style_type || '',
      source: 'file'
    };
    // For effect styles, include the effects array if available
    if (item.style_type === 'EFFECT' && Array.isArray(item.effects)) {
      normalized.effects = item.effects;
    }
    return normalized;
  });
}

// normalizePublishedStyles: maps raw published styles API response to the shared normalized shape.
function normalizePublishedStyles(stylesData) {
  return (stylesData.meta?.styles || []).map((item) => {
    const normalized = {
      key: item.key || '',
      nodeId: item.node_id || '',
      name: item.name || '',
      styleType: item.style_type || '',
      source: 'published',
      updatedAt: item.updated_at || ''
    };
    // For effect styles, include the effects array if available
    if (item.style_type === 'EFFECT' && Array.isArray(item.effects)) {
      normalized.effects = item.effects;
    }
    return normalized;
  });
}

// extractAllComponentsFromDocument: walks the full document tree; returns all COMPONENT nodes that have a key.
function extractAllComponentsFromDocument(document) {
  const components = [];

  function traverse(node) {
    if (!node) return;
    if (node.type === 'COMPONENT' && node.key) {
      components.push({
        key: node.key || '',
        nodeId: node.id || '',
        name: node.name || '',
        source: 'document-tree'
      });
    }
    if (Array.isArray(node.children)) {
      node.children.forEach(traverse);
    }
  }

  traverse(document);
  return components;
}

// extractComponentSignaturesFromDocument: walks the document tree to extract child-structure signatures for the given node IDs.
function extractComponentSignaturesFromDocument(document, componentNodeIds) {
  const nodeIdSet = new Set(componentNodeIds);
  const signatures = {};

  function traverse(node) {
    if (!node) return;
    if (nodeIdSet.has(node.id) && Array.isArray(node.children)) {
      const children = node.children;
      const childNames = children.map(c => c.name || '').filter(Boolean);
      const childTypes = children.map(c => c.type || '').filter(Boolean);
      const childStructure = children.map(c => ({
        type: c.type || '',
        childCount: Array.isArray(c.children) ? c.children.length : 0
      }));
      const textChildCount = children.filter(c => c.type === 'TEXT').length;
      const instanceChildCount = children.filter(c => c.type === 'INSTANCE').length;
      const frameChildCount = children.filter(c => c.type === 'FRAME').length;
      const layoutMode = node.layoutMode || 'NONE';
      signatures[node.id] = {
        childNames,
        childTypes,
        childStructure,
        childCount: children.length,
        textChildCount,
        instanceChildCount,
        frameChildCount,
        layoutMode
      };
    }
    if (Array.isArray(node.children)) {
      node.children.forEach(traverse);
    }
  }

  traverse(document);
  return signatures;
}

// normalizeVariables: normalizes the raw Figma variables API response into collections + variable lists.
function normalizeVariables(variablesData) {
  const meta = variablesData?.meta || {};
  const variableCollections = meta.variableCollections || {};
  const variables = meta.variables || {};

  const collectionList = Object.values(variableCollections).map((collection) => ({
    id: collection.id || '',
    key: collection.key || '',
    name: collection.name || '',
    modes: Array.isArray(collection.modes)
      ? collection.modes.map((mode) => ({
          modeId: mode.modeId || '',
          name: mode.name || ''
        }))
      : []
  }));

  const variableList = Object.values(variables)
    .filter((variable) => {
      // Skip variables with missing required fields that would cause errors
      if (!variable.id || !variable.name) {
        console.warn('[Backend] Skipping variable with missing id or name:', variable);
        return false;
      }
      return true;
    })
    .map((variable) => ({
      id: variable.id || '',
      key: variable.key || '',
      name: variable.name || '',
      resolvedType: variable.resolvedType || '',
      variableCollectionId: variable.variableCollectionId || '',
      scopes: Array.isArray(variable.scopes) ? variable.scopes : [],
      valuesByMode: variable.valuesByMode || {}
    }));

  return {
    collections: collectionList,
    variables: variableList
  };
}

// Helper: classify library into size bucket based on component count
function classifyLibraryBucket(componentCount) {
  if (componentCount < 100) return 'small';      // < 100 components
  if (componentCount < 500) return 'medium';     // 100-499 components
  return 'large';                                 // 500+ components
}

// Helper: get estimated total time for library sync based on bucket
function getEstimatedSyncTime(bucket) {
  const estimates = {
    small: 10,      // 10 seconds
    medium: 40,     // 40 seconds
    large: 90       // 90 seconds
  };
  return estimates[bucket] || 40;
}


// Extract component signatures from a /nodes endpoint response.
// /nodes shape: { nodes: { nodeId: { document: { children: [...], layoutMode } } } }
function extractSignaturesFromNodesResponse(nodesData, batchNodeIds) {
  const signatures = {};
  for (const nodeId of batchNodeIds) {
    const nodeEntry = nodesData.nodes && nodesData.nodes[nodeId];
    if (!nodeEntry || !nodeEntry.document) continue;
    const doc = nodeEntry.document;
    const children = Array.isArray(doc.children) ? doc.children : [];
    signatures[nodeId] = {
      childNames: children.map(c => c.name || '').filter(Boolean),
      childTypes: children.map(c => c.type || '').filter(Boolean),
      childStructure: children.map(c => ({
        type: c.type || '',
        childCount: Array.isArray(c.children) ? c.children.length : 0
      })),
      childCount: children.length,
      textChildCount: children.filter(c => c.type === 'TEXT').length,
      instanceChildCount: children.filter(c => c.type === 'INSTANCE').length,
      frameChildCount: children.filter(c => c.type === 'FRAME').length,
      layoutMode: doc.layoutMode || 'NONE'
    };
  }
  return signatures;
}

// Fetch component signatures for all given node IDs using parallel /nodes batches.
// Batches nodeIds into chunks of BATCH_SIZE to stay within URL length limits.
// Returns array of componentSignature objects ready to store in the cache.
async function fetchComponentSignatures(fileKey, componentNodeIds, headers, components) {
  const BATCH_SIZE = 180;
  const batches = [];
  for (let i = 0; i < componentNodeIds.length; i += BATCH_SIZE) {
    batches.push(componentNodeIds.slice(i, i + BATCH_SIZE));
  }

  const batchResults = await Promise.all(
    batches.map((batchIds, batchIndex) => {
      // Node IDs contain ':' which must be URL-encoded in query params
      const idsParam = batchIds.map(id => encodeURIComponent(id)).join(',');
      const url = `https://api.figma.com/v1/files/${fileKey}/nodes?ids=${idsParam}`;
      return fetchJsonOptional(url, { headers }).then(result => ({ result, batchIds, batchIndex }));
    })
  );

  const allRawSignatures = {};
  let successBatches = 0;
  let failedBatches = 0;
  const failedBatchErrors = [];

  for (const { result, batchIds, batchIndex } of batchResults) {
    if (!result.ok) {
      failedBatches++;
      if (failedBatchErrors.length < 3 && result.error) failedBatchErrors.push(result.error);
      continue;
    }
    const batchSigs = extractSignaturesFromNodesResponse(result.data, batchIds);
    Object.assign(allRawSignatures, batchSigs);
    successBatches++;
  }

  // Build final signature objects using component metadata already fetched in Phase 1
  const componentByNodeId = {};
  for (const c of components) {
    if (c.nodeId) componentByNodeId[c.nodeId] = c;
  }

  const signatures = componentNodeIds
    .filter(nodeId => allRawSignatures[nodeId])
    .map(nodeId => {
      const c = componentByNodeId[nodeId] || {};
      const sig = allRawSignatures[nodeId];
      return {
        nodeId,
        key: c.key || '',
        name: c.name || '',
        containingFrame: c.containingFrame || '',
        childNames: sig.childNames,
        childTypes: sig.childTypes,
        childStructure: sig.childStructure,
        childCount: sig.childCount,
        textChildCount: sig.textChildCount,
        instanceChildCount: sig.instanceChildCount,
        frameChildCount: sig.frameChildCount,
        layoutMode: sig.layoutMode
      };
    });

  // Return structured shape so caller can detect total Phase 2 failure ("all N batches
  // failed") and transition the cache to status='error' instead of silently writing
  // status='complete' with an empty signatures array. Empty-signatures-complete used to
  // degrade every signature-dependent rule (I05/I07/etc.) with no user-visible warning.
  return {
    signatures,
    successBatches,
    failedBatches,
    totalBatches: batches.length,
    allFailed: batches.length > 0 && successBatches === 0,
    sampleErrors: failedBatchErrors
  };
}

// getLibraryData: fetches all component/style/variable data for a library file from the Figma API.
// Returns normalized library object; Phase 2 (signatures) runs in the background after Phase 1 returns.
async function getLibraryData(fileKeyRaw, normalizedKey, previousData, figmaHeaders) {
  const fileKey = normalizeFileKey(fileKeyRaw);
  if (!fileKey) throw new Error('Missing file key');

  const headers = figmaHeaders || { 'X-Figma-Token': FIGMA_PAT || '' };

  // Phase 1: 5 parallel calls — file metadata (depth=1 for info, depth=2 for document tree) + components + styles + variables
  // depth=1: metadata-only (name, lastModified, thumbnailUrl, version)
  // depth=2: includes document tree to extract all components (both published and unpublished)
  // Published components and styles come from the REST endpoints, which are faster.
  const startShallowTime = Date.now();

  const [fileData, fileDataDeep, publishedComponentsResult, publishedStylesResult, variablesResult] = await Promise.all([
    fetchJson(`https://api.figma.com/v1/files/${fileKey}`, { headers }),
    fetchJsonOptional(`https://api.figma.com/v1/files/${fileKey}?depth=2`, { headers }),
    fetchJsonOptional(`https://api.figma.com/v1/files/${fileKey}/components`, { headers }),
    fetchJsonOptional(`https://api.figma.com/v1/files/${fileKey}/styles`, { headers }),
    fetchJsonOptional(`https://api.figma.com/v1/files/${fileKey}/variables/local`, { headers })
  ]);


  const publishedComponents = publishedComponentsResult.ok
    ? normalizePublishedComponents(publishedComponentsResult.data)
    : [];

  // Extract all components from file (includes both published and unpublished)
  let allComponents = publishedComponents;
  let unpublishedComponents = [];

  // Extract all components from fileData.components (includes both published and unpublished)
  let allComponentsFromFile = [];
  // ── Component extraction: published + unpublished base components ─────────────
  // Fetches full file data to get all components (2000+), then filters to:
  // - Published: from /components endpoint (identified by non-empty key in published list)
  // - Unpublished base: from fileData.components where name starts with . or _
  // This 50% data reduction skips variant/feature components, keeping only components
  // needed for library key verification. See: Design Guardian issue on unpublished components.
  // Component set tracking
  var componentSetsFromFile = [];
  var unpublishedComponentSets = [];

  if (fileData && fileData.components && typeof fileData.components === 'object') {
    allComponentsFromFile = normalizeComponentsFromFile(fileData);

    // Build set of published component keys for comparison
    var publishedKeySet = new Set();
    publishedComponents.forEach(function(c) {
      if (c.key) publishedKeySet.add(c.key);
    });

    // Identify unpublished base components: in file but NOT in published list AND start with . or _
    // (. and _ prefixes indicate draft/internal/base components in Figma)
    unpublishedComponents = allComponentsFromFile.filter(function(comp) {
      return comp.key && !publishedKeySet.has(comp.key) && comp.name &&
             (comp.name.charAt(0) === '.' || comp.name.charAt(0) === '_');
    });

  } else {
  }

  // Check for component sets in fileData
  if (fileData && fileData.componentSets && typeof fileData.componentSets === 'object') {
    componentSetsFromFile = Object.values(fileData.componentSets);

    // Identify unpublished component sets (same logic: not in published list, starts with . or _)
    var publishedSetKeySet = new Set();
    publishedComponents.forEach(function(c) {
      if (c.componentSetKey) publishedSetKeySet.add(c.componentSetKey);
    });

    unpublishedComponentSets = componentSetsFromFile.filter(function(set) {
      return set.key && !publishedSetKeySet.has(set.key) && set.name &&
             (set.name.charAt(0) === '.' || set.name.charAt(0) === '_');
    });

  } else {
  }

  // Mark published status and combine components
  publishedComponents.forEach(function(c) { c.published = true; });
  unpublishedComponents.forEach(function(c) { c.published = false; });
  allComponents = publishedComponents.concat(unpublishedComponents);

  const components = allComponents;

  // Mark published status and combine component sets
  // Separate published from unpublished - unpublished are those starting with . or _
  var allComponentSets = [];
  var publishedComponentSets = componentSetsFromFile.filter(function(set) {
    // Published if does NOT start with . or _
    return set.name && set.name.charAt(0) !== '.' && set.name.charAt(0) !== '_';
  });
  publishedComponentSets.forEach(function(set) { set.published = true; });
  unpublishedComponentSets.forEach(function(set) { set.published = false; });
  allComponentSets = publishedComponentSets.concat(unpublishedComponentSets);

  if (allComponentSets.length > 0) {
  }

  const styles = publishedStylesResult.ok
    ? normalizePublishedStyles(publishedStylesResult.data)
    : [];

  let normalizedVariables = { collections: [], variables: [] };
  if (variablesResult.ok) {
    try {
      normalizedVariables = normalizeVariables(variablesResult.data);
    } catch (err) {
      console.error('[Backend] Error normalizing variables:', err.message);
    }
  }

  // Compute lastPublished = max(updated_at) across all components and styles
  const allUpdatedAts = [];
  components.forEach(function(c) { if (c.updatedAt) allUpdatedAts.push(c.updatedAt); });
  styles.forEach(function(s) { if (s.updatedAt) allUpdatedAts.push(s.updatedAt); });
  const lastPublished = allUpdatedAts.length > 0
    ? allUpdatedAts.slice().sort().pop()  // ISO strings sort lexicographically
    : null;

  // Map of component key -> updatedAt for delta sync on re-sync
  const componentUpdatedAt = {};
  components.forEach(function(c) { if (c.key && c.updatedAt) componentUpdatedAt[c.key] = c.updatedAt; });

  const actualComponentCount = components.length;
  const reclassifiedBucket = classifyLibraryBucket(actualComponentCount);
  const reclassifiedEstimatedSyncTime = getEstimatedSyncTime(reclassifiedBucket);

  // Signatures populated by Phase 2 background /nodes batches
  const componentSignatures = [];

  const warnings = [];
  if (!publishedComponentsResult.ok) {
    warnings.push(`Published components unavailable: ${publishedComponentsResult.error}`);
  }
  if (!fileDataDeep.ok) {
    warnings.push(`Document tree unavailable (unpublished components may be missed): ${fileDataDeep.error}`);
  }
  if (!publishedStylesResult.ok) {
    warnings.push(`Published styles unavailable: ${publishedStylesResult.error}`);
  }
  if (!variablesResult.ok) {
    warnings.push(`Variables unavailable: ${variablesResult.error}`);
  }

  // Extract spacing and radius tokens from numeric variables with appropriate scopes/names
  var spacingTokens = [];
  var radiusTokens = [];
  var SPACING_SCOPES = ['GAP', 'WIDTH_HEIGHT', 'HORIZONTAL_PADDING', 'VERTICAL_PADDING', 'ALL_SCOPES'];
  var RADIUS_SCOPES = ['CORNER_RADIUS', 'ALL_SCOPES'];
  for (var _tvIdx = 0, _tvList = normalizedVariables.variables; _tvIdx < _tvList.length; _tvIdx++) {
    var v = _tvList[_tvIdx];
    var numValue = v.resolvedType === 'NUMBER' || v.resolvedType === 'FLOAT' ? Number(v.valuesByMode[Object.keys(v.valuesByMode)[0]]) : NaN;
    if (!Number.isFinite(numValue)) continue;
    var vScopes = v.scopes || [];
    var hasSpacingScope = vScopes.some(function (s) { return SPACING_SCOPES.indexOf(s) !== -1; });
    var hasRadiusScope = vScopes.some(function (s) { return RADIUS_SCOPES.indexOf(s) !== -1; });
    var hasSpacingName = vScopes.length === 0 && /spacing|space|gap|padding|size|width|height/i.test(v.name);
    var hasRadiusName = vScopes.length === 0 && /radius|corner|round/i.test(v.name);
    if (hasSpacingScope || hasSpacingName) spacingTokens.push(numValue);
    if (hasRadiusScope || hasRadiusName) radiusTokens.push(numValue);
  }
  spacingTokens = Array.from(new Set(spacingTokens)).sort(function (a, b) { return a - b; });
  radiusTokens = Array.from(new Set(radiusTokens)).sort(function (a, b) { return a - b; });

  const shallowTime = Date.now() - startShallowTime;

  // ✓ PHASE 1 COMPLETE: UPDATE CACHE WITH STATUS='SHALLOW'
  // Build shallow data object with components and styles (signatures will be empty at this point)
  // createdAt is REQUIRED so the /library/status cache-hit branch (line ~1127) can detect
  // when a shallow entry has been stuck for >30s and invalidate it. Without this field the
  // shallow entry lingers indefinitely, polling clients see status=shallow forever, and the
  // 4-minute client backstop is the only escape.
  const shallowData = {
    ok: true,
    status: 'shallow',
    createdAt: Date.now(),
    message: 'Library loaded (shallow). You can scan now. Full depth loading in background...',
    bucket: reclassifiedBucket,
    estimatedSyncTime: reclassifiedEstimatedSyncTime,
    totalComponentsCount: actualComponentCount,
    lastPublished: lastPublished,
    componentUpdatedAt: componentUpdatedAt,
    library: {
      fileKey,
      name: fileData.name || 'Untitled library',
      lastModified: fileData.lastModified || null,
      thumbnailUrl: fileData.thumbnailUrl || '',
      version: fileData.version || '',
      components,
      componentSets: allComponentSets,
      componentSignatures: [],  // empty for shallow phase
      styles,
      variables: normalizedVariables.variables,
      variableCollections: normalizedVariables.collections,
      spacingTokens: spacingTokens,
      radiusTokens: radiusTokens
    },
    counts: {
      components: components.length,
      componentsLoading: components.length,
      componentsProgress: null,  // null until Phase 2 signatures complete
      styles: styles.length,
      stylesLoading: styles.length,
      stylesProgress: null,
      variables: normalizedVariables.variables.length,
      variableCollections: normalizedVariables.collections.length
    },
    diagnostics: {
      publishedComponents: publishedComponents.length,
      unpublishedComponents: unpublishedComponents.length,
      totalComponents: components.length,
      componentSetsFromFile: componentSetsFromFile.length,
      unpublishedComponentSets: unpublishedComponentSets.length,
      publishedStyles: styles.length,
      variablesEndpointAvailable: variablesResult.ok,
      documentTreeAvailable: fileDataDeep.ok,
      extractedTokens: {
        spacingTokens: spacingTokens.length,
        radiusTokens: radiusTokens.length
      }
    },
    warnings: warnings
  };

  if (normalizedKey) {
    cacheSet(normalizedKey, shallowData);
  }

  // Delta sync: reuse signatures from previous cache for unchanged components
  const previousComponentUpdatedAt = (previousData && previousData.componentUpdatedAt) || null;
  const previousSignatures = (previousData && previousData.library && previousData.library.componentSignatures) || null;

  const reusedSignaturesByNodeId = {};
  let componentNodeIdsToFetch;

  if (previousComponentUpdatedAt && previousSignatures && previousSignatures.length > 0) {
    // Build lookup of previous signatures by nodeId
    previousSignatures.forEach(function(sig) {
      if (sig.nodeId) reusedSignaturesByNodeId[sig.nodeId] = sig;
    });

    // Find changed/new components (updatedAt differs from stored)
    const changedNodeIds = [];
    components.forEach(function(c) {
      const prevUpdatedAt = previousComponentUpdatedAt[c.key];
      if (!prevUpdatedAt || prevUpdatedAt !== c.updatedAt) {
        changedNodeIds.push(c.nodeId);
        delete reusedSignaturesByNodeId[c.nodeId]; // don't reuse potentially stale signature
      }
    });

    componentNodeIdsToFetch = changedNodeIds.filter(Boolean);
    const reusedCount = Object.keys(reusedSignaturesByNodeId).length;
  } else {
    // No previous cache — full fetch
    componentNodeIdsToFetch = components.map(function(c) { return c.nodeId; }).filter(Boolean);
  }

  // Phase 2: Background /nodes batches — only for changed/new components (non-blocking)
  const phase2StartTime = Date.now();

  function updateCacheWithSignatures(finalSignatures) {
    const normalizedKeyForUpdate = normalizeFileKey(fileKey);
    if (libraryCache.has(normalizedKeyForUpdate)) {
      const cached = cacheGet(normalizedKeyForUpdate);
      if (cached) {
        cached.data.library.componentSignatures = finalSignatures;
        cached.data.status = 'complete';
        cached.data.counts.componentsProgress = 100;
        cached.data.counts.stylesProgress = 100;
        totalCacheSizeBytes -= cached.sizeBytes;
        cached.sizeBytes = getCacheEntrySize(cached.data);
        totalCacheSizeBytes += cached.sizeBytes;
        cached.timestamp = Date.now();
        cached.lastAccessed = Date.now();
      }
    } else {
    }
  }

  // markCacheAsError: transitions a shallow cache entry to status='error' so the polling
  // client surfaces the failure immediately instead of waiting out the 4-minute backstop.
  // Called when Phase 2 (component signatures) throws, or when every signature batch
  // fails (total Figma outage / rate-limit storm).
  function markCacheAsError(errMessage) {
    const normalizedKeyForError = normalizeFileKey(fileKey);
    if (libraryCache.has(normalizedKeyForError)) {
      const cached = cacheGet(normalizedKeyForError);
      if (cached) {
        cached.data.status = 'error';
        cached.data.error = errMessage;
        cached.data.message = 'Library sync failed during Phase 2: ' + errMessage;
        totalCacheSizeBytes -= cached.sizeBytes;
        cached.sizeBytes = getCacheEntrySize(cached.data);
        totalCacheSizeBytes += cached.sizeBytes;
        cached.timestamp = Date.now();
        cached.lastAccessed = Date.now();
      }
    }
  }

  if (componentNodeIdsToFetch.length === 0) {
    // All components unchanged — immediately mark complete
    const reusedSignatures = Object.values(reusedSignaturesByNodeId);
    updateCacheWithSignatures(reusedSignatures);
  } else {
    fetchComponentSignatures(fileKey, componentNodeIdsToFetch, headers, components)
      .then(function(result) {
        // Total Phase 2 failure: every Figma /nodes batch returned an error. Writing
        // status='complete' here would set componentSignatures=[] and silently degrade
        // every signature-dependent rule (I05/I07 shallow-sync guard, etc.) with no
        // user-visible warning. Surface as an error so the client retries explicitly.
        if (result.allFailed) {
          const sample = result.sampleErrors.length > 0 ? ': ' + result.sampleErrors.join('; ') : '';
          const msg = 'All ' + result.totalBatches + ' Figma /nodes batches failed' + sample;
          console.error('[Sync] Phase 2 total failure for key=' + shortKey(fileKey) + ': ' + msg);
          markCacheAsError(msg);
          return;
        }
        const mergedSignatures = Object.values(reusedSignaturesByNodeId).concat(result.signatures);
        updateCacheWithSignatures(mergedSignatures);
      })
      .catch(function(err) {
        // Phase 2 threw (network failure, rejected promise from inside fetchComponentSignatures).
        // Previously this catch was empty: the error vanished, the cache stayed at 'shallow'
        // forever, and polling clients waited the full 4-minute backstop. Now the error is
        // logged AND written to the cache so the next /library/status poll surfaces it.
        const errMsg = (err && err.message) || 'Phase 2 component signature fetch threw';
        console.error('[Sync] Phase 2 exception for key=' + shortKey(fileKey) + ': ' + errMsg);
        markCacheAsError(errMsg);
      });
  }

  return {
    ok: true,
    status: 'shallow',  // Signal that this is shallow data
    message: 'Library loaded (shallow). You can scan now. Full depth loading in background...',
    bucket: reclassifiedBucket,                      // 'small' | 'medium' | 'large' (reclassified based on actual count)
    estimatedSyncTime: reclassifiedEstimatedSyncTime, // seconds (reclassified)
    totalComponentsCount: actualComponentCount,      // for UI progress calculation (actual shallow load count)
    lastPublished: lastPublished,
    library: {
      fileKey,
      name: fileData.name || 'Untitled library',
      lastModified: fileData.lastModified || null,
      thumbnailUrl: fileData.thumbnailUrl || '',
      version: fileData.version || '',
      components,
      componentSets: allComponentSets,
      componentSignatures,
      styles,
      variables: normalizedVariables.variables,
      variableCollections: normalizedVariables.collections,
      spacingTokens: spacingTokens,
      radiusTokens: radiusTokens
    },
    counts: {
      components: components.length,
      componentsLoading: components.length,
      componentsProgress: null,  // null until Phase 2 signatures complete
      styles: styles.length,
      stylesLoading: styles.length,
      stylesProgress: null,
      variables: normalizedVariables.variables.length,
      variableCollections: normalizedVariables.collections.length
    },
    diagnostics: {
      publishedComponents: publishedComponents.length,
      unpublishedComponents: unpublishedComponents.length,
      totalComponents: components.length,
      componentSetsFromFile: componentSetsFromFile.length,
      unpublishedComponentSets: unpublishedComponentSets.length,
      publishedStyles: styles.length,
      variablesEndpointAvailable: variablesResult.ok,
      documentTreeAvailable: fileDataDeep.ok,
      extractedTokens: {
        spacingTokens: spacingTokens.length,
        radiusTokens: radiusTokens.length
      },
      extractedStyles: {
        effectStyles: styles.filter(s => s.styleType === 'EFFECT').length
      }
    },
    warnings
  };
}

// requestHandler: main HTTP router — handles CORS preflight, all API endpoints, and the 404 fallback.
async function requestHandler(req, res) {
  if (req.method === 'OPTIONS') {
    res.writeHead(204, {
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Methods': 'GET,POST,DELETE,OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type,Authorization,X-DG-Token',
      'Access-Control-Allow-Private-Network': 'true'
    });
    res.end();
    return;
  }

  try {
    const url = new URL(req.url, `http://localhost:${PORT}`);

    if (req.method === 'GET' && url.pathname === '/health') {
      sendJson(res, 200, {
        ok: true,
        patConfigured: Boolean(FIGMA_PAT)
      });
      return;
    }

    if (req.method === 'GET' && url.pathname === '/library/status') {
      const requestReceivedTime = Date.now();
      const fileKey = url.searchParams.get('fileKey');
      const normalizedKey = normalizeFileKey(fileKey);
      if (!normalizedKey) {
        sendJson(res, 400, { ok: false, error: 'Missing fileKey parameter' });
        return;
      }
      if (!hasFigmaAuth(req)) {
        sendJson(res, 401, { ok: false, error: 'No Figma authentication available. Sign in via OAuth or configure FIGMA_PAT.' });
        return;
      }

      const figmaHeaders = await getFigmaAuthHeaders(req);
      const headers = figmaHeaders;

      // Check cache for library status using publish-date validation
      const cacheHit = libraryCache.has(normalizedKey);
      let useCache = false;

      if (cacheHit) {
        const cached = cacheGet(normalizedKey);  // Updates lastAccessed for LRU
        const cachedLastPublished = cached.data?.lastPublished;
        const cachedStatus = cached.data?.status;

        // Only validate cache if it's complete (avoid redundant API calls on pending/shallow)
        if (cachedStatus !== 'complete') {
          // 'pending' = placeholder written before Phase 1 finishes. Treat as valid while
          // an active sync job is running OR for up to 270s (just past the 240s fetchJson
          // timeout). Previously 30s caused new syncs to start every 30s while the body
          // download of a large Figma file was still in progress.
          //
          // 'shallow' = Phase 1 done, Phase 2 in progress. Do NOT invalidate here. Phase 2
          // is bounded by fetchJsonOptional's timeout and has explicit terminal transitions:
          // updateCacheWithSignatures on success, markCacheAsError on failure. Invalidating
          // shallow would race the still-running Phase 2 promise and corrupt the cache.
          if (cachedStatus === 'shallow') {
            useCache = true;
          } else {
            const pendingAge = Date.now() - (cached.data?.createdAt || Date.now());
            if (activeSyncs.has(normalizedKey) || pendingAge <= 270000) {
              useCache = true;
            } else {
              totalCacheSizeBytes -= cached.sizeBytes;
              libraryCache.delete(normalizedKey);
            }
          }
        } else {
          // Skip Figma metadata call if we validated recently (polling every few seconds)
          const timeSinceValidation = Date.now() - (cached.lastValidatedAt || 0);
          if (timeSinceValidation < VALIDATION_SKIP_MS) {
            useCache = true;
          } else {
            // Fetch current published component/style metadata to check if library has changed
            const metadataResult = await fetchLibraryPublishedMetadata(fileKey, headers);

            if (metadataResult.ok && metadataResult.lastPublished === cachedLastPublished) {
              // Library has NOT changed — return cached status, refresh validation timestamp
              cached.lastValidatedAt = Date.now();
              useCache = true;
            } else if (metadataResult.ok) {
              // Library HAS changed — invalidate cache
              totalCacheSizeBytes -= cached.sizeBytes;
              libraryCache.delete(normalizedKey);
            } else {
              // Metadata fetch failed — fall back to TTL check
              const age = Date.now() - cached.timestamp;
              if (age < CACHE_TTL_MS) {
                useCache = true;
              } else {
                totalCacheSizeBytes -= cached.sizeBytes;
                libraryCache.delete(normalizedKey);
              }
            }
          }
        }
      }

      if (useCache) {
        // Return current cached status
        const cached = cacheGet(normalizedKey);
        const cachedStatusForResponse = cached.data.status || 'unknown';
        const response = {
          ok: cachedStatusForResponse !== 'error',
          fileKey: normalizedKey,
          status: cachedStatusForResponse,
          bucket: cached.data.bucket || 'unknown',
          estimatedSyncTime: cached.data.estimatedSyncTime || 0,
          totalComponentsCount: cached.data.totalComponentsCount || 0,
          message: cachedStatusForResponse === 'complete'
            ? 'Library data is complete and ready to scan'
            : cachedStatusForResponse === 'error'
              ? (cached.data.message || 'Library sync failed')
              : 'Library data is loading, full-depth fetch in progress...',
          error: cached.data.error || undefined
        };

        const responseTime = Date.now() - requestReceivedTime;
        sendJson(res, 200, response);
      } else {
        // Cache MISS: Set placeholder and start background fetch WITHOUT BLOCKING

        // Set initial placeholder so concurrent requests find it in cache
        const placeholderData = {
          ok: true,
          status: 'pending',
          bucket: 'large',
          estimatedSyncTime: 90,
          message: 'Starting library fetch...',
          createdAt: Date.now()
        };
        cacheSet(normalizedKey, placeholderData);

        // Start background fetch WITHOUT WAITING. Guard with activeSyncs to prevent
        // parallel jobs for the same key when the pending TTL expires mid-download.
        if (activeSyncs.has(normalizedKey)) {
          // job already running, skip
        } else {
          activeSyncs.add(normalizedKey);
          const _syncStart = Date.now();
          console.log('[Sync] Started  key=' + shortKey(normalizedKey));
          getLibraryData(fileKey, normalizedKey, undefined, figmaHeaders)
            .then(data => {
              cacheSet(normalizedKey, data);
              console.log('[Sync] Complete key=' + shortKey(normalizedKey) + ' (' + ((Date.now() - _syncStart) / 1000).toFixed(1) + 's)');
            })
            .catch(err => {
              console.error('[Background] getLibraryData failed for key=' + shortKey(normalizedKey) + ':', err.message);
              cacheSet(normalizedKey, {
                ok: false,
                status: 'error',
                error: err.message,
                fileKey: normalizedKey,
                message: 'Library fetch failed: ' + err.message
              });
            })
            .finally(() => {
              activeSyncs.delete(normalizedKey);
            });
        }

        // Respond IMMEDIATELY with pending status (do not wait for fetch to complete)
        const response = {
          ok: true,
          fileKey: normalizedKey,
          status: 'pending',
          bucket: 'large',
          estimatedSyncTime: 90,
          message: 'Starting library fetch...'
        };

        const responseTime = Date.now() - requestReceivedTime;
        sendJson(res, 200, response);
      }
      return;
    }

    if (req.method === 'GET' && url.pathname === '/library') {
      const requestReceivedTime = Date.now();
      if (!hasFigmaAuth(req)) {
        sendJson(res, 500, { error: 'No Figma authentication available. Sign in via OAuth or configure FIGMA_PAT.' });
        return;
      }

      const fileKey = url.searchParams.get('fileKey');
      const fresh = url.searchParams.get('fresh') === 'true';

      const figmaHeaders = await getFigmaAuthHeaders(req);
      const headers = figmaHeaders;

      try {
        const normalizedKey = normalizeFileKey(fileKey);

        // Check cache if not forcing fresh
        if (!fresh && libraryCache.has(normalizedKey)) {
          const cached = cacheGet(normalizedKey);  // Updates lastAccessed for LRU
          const cachedLastPublished = cached.data?.lastPublished;
          const cachedStatus = cached.data?.status;

          // Only validate cache if it's complete (avoid redundant API calls on pending/shallow)
          if (cachedStatus === 'complete') {
            // Skip Figma metadata call if we validated recently
            const timeSinceValidation = Date.now() - (cached.lastValidatedAt || 0);
            if (timeSinceValidation < VALIDATION_SKIP_MS) {
              const responseTime = Date.now() - requestReceivedTime;
              sendJson(res, 200, cached.data);
              return;
            }

            // Fetch current published component/style metadata to check if library has changed
            const metadataResult = await fetchLibraryPublishedMetadata(fileKey, headers);

            if (metadataResult.ok && metadataResult.lastPublished === cachedLastPublished) {
              // Library has NOT changed since last cache — return cached entry
              cached.lastValidatedAt = Date.now();
              const responseTime = Date.now() - requestReceivedTime;
              sendJson(res, 200, cached.data);
              return;
            } else if (metadataResult.ok) {
              // Library HAS changed — invalidate cache and fetch fresh
              totalCacheSizeBytes -= cached.sizeBytes;
              libraryCache.delete(normalizedKey);
            } else {
              // Metadata fetch failed — fall back to TTL check (safety net)
              const age = Date.now() - cached.timestamp;
              if (age < CACHE_TTL_MS) {
                const responseTime = Date.now() - requestReceivedTime;
                sendJson(res, 200, cached.data);
                return;
              } else {
                totalCacheSizeBytes -= cached.sizeBytes;
                libraryCache.delete(normalizedKey);
              }
            }
          } else {
            // Cache is incomplete (status=pending or shallow), skip validation and fetch fresh
            totalCacheSizeBytes -= cached.sizeBytes;
            libraryCache.delete(normalizedKey);
          }
        }

        // Capture previous cache entry for delta sync before clearing/skipping
        let previousData = null;
        if (fresh) {
          if (libraryCache.has(normalizedKey)) {
            const prevEntry = libraryCache.get(normalizedKey);
            previousData = prevEntry ? prevEntry.data : null;
            totalCacheSizeBytes -= prevEntry.sizeBytes;
          }
          libraryCache.delete(normalizedKey);
        }

        const data = await getLibraryData(fileKey, normalizedKey, previousData, figmaHeaders);

        // Store in cache (uses LRU eviction if needed)
        cacheSet(normalizedKey, data);

        const responseTime = Date.now() - requestReceivedTime;
        sendJson(res, 200, data);
      } catch (err) {
        console.error('[Backend Error] getLibraryData failed:', err.message);
        console.error('[Backend Error] Stack:', err.stack);
        sendJson(res, 500, { error: 'Library data unavailable. Try again or check your Figma connection.' });
      }
      return;
    }

    if (req.method === 'GET' && url.pathname === '/verify-component') {
      if (!hasFigmaAuth(req)) {
        sendJson(res, 500, { error: 'No Figma authentication available. Sign in via OAuth or configure FIGMA_PAT.' });
        return;
      }

      const componentKey = url.searchParams.get('key');
      if (!componentKey) {
        sendJson(res, 400, { error: 'Missing key parameter' });
        return;
      }

      const figmaHeaders = await getFigmaAuthHeaders(req);
      const result = await fetchJsonOptional(
        `https://api.figma.com/v1/components/${componentKey}`,
        { headers: figmaHeaders }
      );

      if (!result.ok) {
        sendJson(res, 200, { ok: false, error: result.error });
        return;
      }

      const fileKey = result.data?.meta?.file_key || null;
      const componentSetName = result.data?.meta?.containing_frame?.containingComponentSet?.name || '';
      const description = result.data?.meta?.description || '';
      sendJson(res, 200, { ok: true, fileKey, componentSetName, description });
      return;
    }

    // Batch verification: verify multiple component keys in parallel.
    // Reduces 147 individual requests to ~5-10 batch requests on large files.
    if (req.method === 'POST' && url.pathname === '/verify-components') {
      if (!hasFigmaAuth(req)) {
        sendJson(res, 500, { error: 'No Figma authentication available. Sign in via OAuth or configure FIGMA_PAT.' });
        return;
      }

      let body = '';
      req.on('data', chunk => { body += chunk.toString(); });
      req.on('end', async () => {
        const figmaHeaders = await getFigmaAuthHeaders(req);
        try {
          const { keys } = JSON.parse(body);
          if (!Array.isArray(keys) || keys.length === 0) {
            sendJson(res, 400, { error: 'Missing or empty keys array' });
            return;
          }

          // Deduplicate keys on backend to reduce Figma API calls
          const uniqueKeys = Array.from(new Set(keys));

          // Cap batch size at 500 to prevent endpoint overload (Figma API limits + memory)
          const MAX_BATCH_SIZE = 500;
          if (uniqueKeys.length > MAX_BATCH_SIZE) {
            sendJson(res, 400, { error: `Batch size ${uniqueKeys.length} exceeds limit of ${MAX_BATCH_SIZE}` });
            return;
          }

          const now = Date.now();
          const verified = {};
          const keysToFetch = [];

          // Serve cached results without hitting Figma API
          for (const key of uniqueKeys) {
            const cached = verificationCache.get(key);
            if (cached && cached.expiresAt > now) {
              verified[key] = cached.result;
            } else {
              keysToFetch.push(key);
            }
          }

          // Concurrency-limited fetch: process in groups of VERIFY_CONCURRENCY to avoid 429s
          const fetchStart = Date.now();
          for (let i = 0; i < keysToFetch.length; i += VERIFY_CONCURRENCY) {
            if (Date.now() - fetchStart > 28000) {
              // Approaching 30s timeout — stop early and return what we have
              for (let j = i; j < keysToFetch.length; j++) {
                verified[keysToFetch[j]] = { ok: false, error: 'timeout' };
              }
              break;
            }
            const batch = keysToFetch.slice(i, i + VERIFY_CONCURRENCY);
            const results = await Promise.all(batch.map(key =>
              fetchJsonOptional(
                `https://api.figma.com/v1/components/${key}`,
                { headers: figmaHeaders }
              )
            ));

            for (let j = 0; j < batch.length; j++) {
              const key = batch[j];
              const result = results[j];
              let entry;

              if (!result || !result.ok) {
                entry = { ok: false, error: result?.error || 'Unknown error' };
                const ttl = result?.status === 429 ? VERIFY_TTL_429 : VERIFY_TTL_404;
                verificationCache.set(key, { result: entry, expiresAt: Date.now() + ttl });
              } else {
                const fileKey = result.data?.meta?.file_key || null;
                const componentSetName = result.data?.meta?.containing_frame?.containingComponentSet?.name || '';
                const description = result.data?.meta?.description || '';
                entry = { ok: true, fileKey, componentSetName, description };
                verificationCache.set(key, { result: entry, expiresAt: Date.now() + VERIFY_TTL_200 });
              }

              verified[key] = entry;
            }
          }

          sendJson(res, 200, { verified });
        } catch (err) {
          console.error('[verify-components] Error:', err.message);
          sendJson(res, 400, { error: err.message });
        }
      });
      return;
    }

    if (req.method === 'GET' && url.pathname === '/library/check') {
      const fileKey = url.searchParams.get('fileKey');
      const normalizedKey = normalizeFileKey(fileKey);
      const pluginLastPublished = url.searchParams.get('lastPublished') || null;

      if (!normalizedKey) {
        sendJson(res, 400, { ok: false, error: 'Missing fileKey parameter' });
        return;
      }

      const cached = cacheGet(normalizedKey);
      if (!cached) {
        sendJson(res, 200, { ok: true, lastPublished: null, changed: true, reason: 'no-cache' });
        return;
      }

      const age = Date.now() - cached.timestamp;
      if (age >= CACHE_TTL_MS) {
        sendJson(res, 200, { ok: true, lastPublished: null, changed: true, reason: 'cache-expired' });
        return;
      }

      const cachedLastPublished = cached.data.lastPublished || null;
      const changed = !pluginLastPublished || !cachedLastPublished || pluginLastPublished !== cachedLastPublished;
      sendJson(res, 200, { ok: true, lastPublished: cachedLastPublished, changed: changed, reason: changed ? 'lastPublished-differs' : 'up-to-date' });
      return;
    }

    // ── GET /validate-file?fileKey=xxx ────────────────────────────────────────
    // Lightweight upfront check: can the server access this Figma file?
    // Returns { ok, name } on success or { ok: false, error } on failure.
    // Uses a 10s timeout so the modal stays responsive.
    if (req.method === 'GET' && url.pathname === '/validate-file') {
      const fileKey = url.searchParams.get('fileKey');
      const normalizedKey = normalizeFileKey(fileKey);
      if (!normalizedKey) {
        sendJson(res, 400, { ok: false, error: 'Missing or invalid file key' });
        return;
      }
      if (!hasFigmaAuth(req)) {
        sendJson(res, 200, { ok: false, error: 'No Figma authentication available. Sign in via OAuth or configure FIGMA_PAT.' });
        return;
      }
      const figmaHeaders = await getFigmaAuthHeaders(req);
      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(), 10000);
      try {
        const response = await fetch(
          `https://api.figma.com/v1/files/${normalizedKey}?depth=1`,
          { headers: figmaHeaders, signal: controller.signal }
        );
        clearTimeout(timer);
        const data = await response.json().catch(() => ({}));
        if (!response.ok) {
          const errDetail = data?.err || data?.message || data?.error || `HTTP ${response.status}`;
          sendJson(res, 200, { ok: false, error: `Cannot access file: ${errDetail}` });
          return;
        }
        sendJson(res, 200, { ok: true, name: data.name || 'Untitled' });
      } catch (e) {
        clearTimeout(timer);
        const msg = e.name === 'AbortError' ? 'Timed out checking file' : 'Could not reach Figma API';
        sendJson(res, 200, { ok: false, error: msg });
      }
      return;
    }

    // ── GET /auth/figma ───────────────────────────────────────────────────────
    // Step 1: plugin opens browser to this URL with ?state=<random>.
    // Redirects to Figma's OAuth authorization page.
    if (FIGMA_CLIENT_ID && req.method === 'GET' && url.pathname === '/auth/figma') {
      const state = url.searchParams.get('state');
      if (!state) { sendJson(res, 400, { error: 'Missing state param' }); return; }
      const authUrl = new URL('https://www.figma.com/oauth');
      authUrl.searchParams.set('client_id', FIGMA_CLIENT_ID);
      authUrl.searchParams.set('redirect_uri', FIGMA_REDIRECT_URI);
      authUrl.searchParams.set('scope', 'current_user:read file_content:read file_metadata:read library_assets:read library_content:read team_library_content:read');
      authUrl.searchParams.set('state', state);
      authUrl.searchParams.set('response_type', 'code');
      res.writeHead(302, { Location: authUrl.toString() });
      res.end();
      return;
    }

    // ── GET /auth/figma/callback ──────────────────────────────────────────────
    // Step 2: Figma redirects here after user authorizes.
    // Exchanges code for tokens, upserts user, stores JWT keyed by state.
    if (FIGMA_CLIENT_ID && req.method === 'GET' && url.pathname === '/auth/figma/callback') {
      const code = url.searchParams.get('code');
      const state = url.searchParams.get('state');
      const oauthError = url.searchParams.get('error');
      const oauthErrorDesc = url.searchParams.get('error_description');
      if (oauthError) {
        console.error('[OAuth callback] Figma returned error:', oauthError, oauthErrorDesc);
        res.writeHead(400, { 'Content-Type': 'text/html' });
        res.end('<p>Authorization failed: ' + escHtml(oauthError) + (oauthErrorDesc ? ' - ' + escHtml(oauthErrorDesc) : '') + '. You can close this tab.</p>');
        return;
      }
      if (!code || !state) {
        res.writeHead(400, { 'Content-Type': 'text/html' });
        res.end('<p>Authorization failed. Missing code or state. You can close this tab.</p>');
        return;
      }
      try {
        // Exchange code for tokens
        const tokenBody = new URLSearchParams({
          client_id: FIGMA_CLIENT_ID,
          client_secret: FIGMA_CLIENT_SECRET,
          redirect_uri: FIGMA_REDIRECT_URI,
          code: code,
          grant_type: 'authorization_code',
        });
        const tokenResp = await fetchJson('https://api.figma.com/v1/oauth/token', {
          method: 'POST',
          headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
          body: tokenBody.toString(),
        });
        // Fetch Figma user info
        const meResp = await fetchJson('https://api.figma.com/v1/me', {
          headers: { 'Authorization': 'Bearer ' + tokenResp.access_token },
        });
        const figmaUserId = String(meResp.id);
        const figmaHandle = meResp.handle || meResp.email || figmaUserId;
        const figmaEmail = meResp.email || null;
        const expiresAt = Math.floor(Date.now() / 1000) + (tokenResp.expires_in || 7776000);
        // Upsert user and store JWT so the plugin can pick it up via polling
        const user = upsertUser(figmaUserId, figmaHandle, figmaEmail, encryptToken(tokenResp.access_token), encryptToken(tokenResp.refresh_token), expiresAt);
        const token = signJwt(user.id);
        setPendingAuth(state, token);
        res.writeHead(200, { 'Content-Type': 'text/html' });
        res.end(`<!DOCTYPE html><html><head><meta charset="utf-8"><title>Design Guardian</title>
          <style>body{font-family:system-ui,sans-serif;display:flex;align-items:center;justify-content:center;height:100vh;margin:0;background:#0d0d0d;color:#e5e5e5;}
          .card{text-align:center;padding:40px;border-radius:12px;background:#1a1a1a;border:1px solid #2a2a2a;}
          h2{margin:0 0 8px;font-size:18px;}p{margin:0;color:#888;font-size:14px;}</style>
          </head><body><div class="card"><h2>Connected to Design Guardian</h2>
          <p>You can close this tab and return to Figma.</p></div></body></html>`);
      } catch (err) {
        console.error('[OAuth callback error]', err.message, err.stack);
        res.writeHead(200, { 'Content-Type': 'text/html' });
        res.end('<!DOCTYPE html><html><head><meta charset="utf-8"><title>Design Guardian</title>' +
          '<style>body{font-family:system-ui,sans-serif;display:flex;align-items:center;justify-content:center;height:100vh;margin:0;background:#0d0d0d;color:#e5e5e5;}' +
          '.card{text-align:center;padding:40px;border-radius:12px;background:#1a1a1a;border:1px solid #2a2a2a;}' +
          'h2{margin:0 0 8px;font-size:18px;}p{margin:0;color:#888;font-size:14px;}</style>' +
          '</head><body><div class="card"><h2>Connection failed</h2>' +
          '<p>' + escHtml(err.message) + '</p></div></body></html>');
      }
      return;
    }

    // ── GET /auth/poll ────────────────────────────────────────────────────────
    // Plugin polls this every 2s after opening the browser auth window.
    // Returns { token } when ready, 202 while pending, 410 when state expired.
    if (FIGMA_CLIENT_ID && req.method === 'GET' && url.pathname === '/auth/poll') {
      const state = url.searchParams.get('state');
      if (!state) { sendJson(res, 400, { error: 'Missing state' }); return; }
      const row = getPendingAuth(state);
      if (!row) {
        sendJson(res, 410, { error: 'State expired or not found' });
        return;
      }
      const age = Date.now() - row.createdAt;
      if (age > PENDING_AUTH_TTL_MS) {
        deletePendingAuth(state);
        sendJson(res, 410, { error: 'State expired' });
        return;
      }
      if (!row.jwt) {
        sendJson(res, 202, { pending: true });
        return;
      }
      // JWT ready - return it and clean up
      deletePendingAuth(state);
      sendJson(res, 200, { token: row.jwt });
      return;
    }

    // ── GET /auth/me ──────────────────────────────────────────────────────────
    // Returns the signed-in user's display info. Requires Bearer token.
    if (FIGMA_CLIENT_ID && req.method === 'GET' && url.pathname === '/auth/me') {
      const user = getUserFromRequest(req);
      if (!user) { sendJson(res, 401, { error: 'Unauthorized' }); return; }
      sendJson(res, 200, {
        figmaUserId: user.figmaUserId,
        handle: user.figmaHandle,
        email: user.figmaEmail,
      });
      return;
    }

    // ── GET /ai/config ───────────────────────────────────────────────────────
    // Returns current AI provider config (API key masked).
    // NOTE: pairingToken is returned here without authentication — the plugin needs it on
    // first load for its CSRF bootstrap before it has any token to send. Acceptable for
    // single-desk local use (server bound to 0.0.0.0 on a trusted LAN). For shared/team
    // deployment, consider restricting the bind address to 127.0.0.1.
    if (req.method === 'GET' && url.pathname === '/ai/config') {
      const cfg = loadAiConfig();
      sendJson(res, 200, {
        ok: true,
        provider: cfg.provider || '',
        model: cfg.model || '',
        ollamaEndpoint: cfg.ollamaEndpoint || 'http://localhost:11434',
        hasApiKey: !!(cfg.apiKey),
        defaultModels: AI_DEFAULT_MODELS,
        persona: cfg.persona || '',
        defaultPersona: DEFAULT_AI_PERSONA,
        pairingToken: cfg.pairingToken || '',
      });
      return;
    }

    // ── POST /ai/config ──────────────────────────────────────────────────────
    // Saves AI provider config. Protected by pairing token (X-DG-Token header).
    if (req.method === 'POST' && url.pathname === '/ai/config') {
      if (!aiTokenGuard(req, res)) return;
      const chunks = [];
      req.on('data', function(chunk) { chunks.push(chunk); });
      req.on('end', function() {
        const body = Buffer.concat(chunks).toString('utf8');
        try {
          const incoming = JSON.parse(body);
          const existing = loadAiConfig();
          const updated = {
            provider: incoming.provider || existing.provider || '',
            model: incoming.model || existing.model || '',
            authMethod: incoming.authMethod || existing.authMethod || 'cli',
            ollamaEndpoint: incoming.ollamaEndpoint || existing.ollamaEndpoint || 'http://localhost:11434',
            // Only update apiKey if a new one was sent; empty string means "keep existing"
            apiKey: incoming.apiKey !== undefined && incoming.apiKey !== ''
              ? incoming.apiKey
              : (existing.apiKey || ''),
            // Empty string means "use default persona" — preserve that intent explicitly
            persona: typeof incoming.persona === 'string' ? incoming.persona : (existing.persona || ''),
            // Must carry the existing pairingToken — omitting it causes loadAiConfig to
            // generate a new one on the next read, invalidating in-flight plugin requests.
            pairingToken: existing.pairingToken || '',
          };
          saveAiConfig(updated);
          sendJson(res, 200, { ok: true });
        } catch (e) {
          sendJson(res, 400, { error: 'Invalid request body' });
        }
      });
      return;
    }

    // ── GET /ai/cli-status ───────────────────────────────────────────────────
    // Returns which provider CLIs are installed and authenticated on this machine.
    if (req.method === 'GET' && url.pathname === '/ai/cli-status') {
      const providers = ['anthropic', 'openai', 'google'];
      const cliNames = { anthropic: 'claude', openai: 'codex', google: 'gemini' };
      const results = {};
      await Promise.all(providers.map(async function(p) {
        const installed = await isCliInstalled(cliNames[p]);
        const loggedIn = installed ? await checkCliAuth(p) : false;
        results[p] = { installed: installed, loggedIn: loggedIn };
      }));
      sendJson(res, 200, results);
      return;
    }

    // ── POST /ai/cli-login ───────────────────────────────────────────────────
    // Spawns the provider's CLI login process detached so it opens a browser
    // OAuth flow on the user's machine. Returns immediately — login is async.
    if (req.method === 'POST' && url.pathname === '/ai/cli-login') {
      const chunks = [];
      req.on('data', function(chunk) { chunks.push(chunk); });
      req.on('end', async function() {
        const body = Buffer.concat(chunks).toString('utf8');
        try {
          const { provider } = JSON.parse(body);
          // Login command per provider:
          // - claude auth login: opens browser for Claude.ai / SSO auth (correct subcommand).
          // - gemini: no standalone login; open gemini REPL and user types /auth inside.
          // - codex login: explicit subcommand that opens a browser OAuth flow.
          const loginCmds = {
            anthropic: ['claude', 'auth', 'login'],
            google:    ['gemini'],
            openai:    ['codex', 'login'],
          };
          const installUrls = {
            anthropic: 'https://docs.anthropic.com/claude-code',
            google:    'https://ai.google.dev/gemini-api/docs/gemini-cli',
            openai:    'https://github.com/openai/codex',
          };
          const cmd = loginCmds[provider];
          if (!cmd) { sendJson(res, 400, { error: 'No login command for provider: ' + provider }); return; }
          // Check the binary is actually installed before trying to spawn
          const installed = await isCliInstalled(cmd[0]);
          if (!installed) {
            sendJson(res, 400, {
              error: '"' + cmd[0] + '" CLI is not installed. Install it first: ' + (installUrls[provider] || 'check provider docs'),
            });
            return;
          }
          // Spawn detached and inherit server stdio so the child process can open a browser.
          const child = spawn(cmd[0], cmd.slice(1), { detached: true, stdio: 'inherit' });
          child.on('error', function(err) {
            console.error('[cli-login] spawn error for "' + cmd.join(' ') + '":', err.message);
          });
          child.unref();
          sendJson(res, 200, { ok: true });
        } catch (e) {
          sendJson(res, 400, { error: 'Invalid request body' });
        }
      });
      return;
    }

    // ── GET /ai/guidelines ───────────────────────────────────────────────────
    // Returns { content, files, manual } so the UI can restore uploaded file cards.
    if (req.method === 'GET' && url.pathname === '/ai/guidelines') {
      try {
        const raw = fs.readFileSync(GUIDELINES_FILE, 'utf8');
        let data;
        try { data = JSON.parse(raw); } catch (_) { data = null; }
        if (!data || typeof data !== 'object') {
          // Legacy plain-text format: surface as a synthetic file card so the UI shows it
          // as an uploaded file (not manual text). Avoids the loop where plain-text content
          // fills the manual textarea and gets re-saved as manual on every interaction.
          const lines = raw.split('\n').length;
          const legacyFile = { name: 'content-guidelines.md', content: raw, lines: lines, enabled: true };
          sendJson(res, 200, { ok: true, content: raw, files: [legacyFile], manual: '', evaluateGuidelines: false });
        } else {
          sendJson(res, 200, { ok: true, content: data.content || '', files: data.files || [], manual: data.manual || '', evaluateGuidelines: data.evaluateGuidelines === true });
        }
      } catch (_) {
        sendJson(res, 200, { ok: true, content: '', files: [], manual: '', evaluateGuidelines: false });
      }
      return;
    }

    // ── POST /ai/guidelines ──────────────────────────────────────────────────
    // Accepts { files: [{name,content,lines,enabled}], manual: string, evaluateGuidelines: boolean }.
    // Merges into a single content string for AI scans and stores all fields.
    if (req.method === 'POST' && url.pathname === '/ai/guidelines') {
      if (!aiTokenGuard(req, res)) return;
      const chunks = [];
      let glBodySize = 0, glBodyTooBig = false;
      req.on('data', function(chunk) { glBodySize += chunk.length; if (glBodySize > MAX_BODY_BYTES) { glBodyTooBig = true; return; } chunks.push(chunk); });
      req.on('end', function() {
        if (glBodyTooBig) { sendJson(res, 413, { error: 'Guidelines payload exceeds 5 MB limit' }); return; }
        const body = Buffer.concat(chunks).toString('utf8');
        try {
          const payload = JSON.parse(body);
          const files = Array.isArray(payload.files) ? payload.files : [];
          const manual = typeof payload.manual === 'string' ? payload.manual.trim() : '';
          // Default OFF — an uploaded/pasted guidelines doc isn't necessarily unreviewed; only run
          // the (real cost) quality-evaluation AI call when the user explicitly opts in.
          const evaluateGuidelines = payload.evaluateGuidelines === true;
          const fileContent = files.filter(function(f) { return f.enabled !== false; })
            .map(function(f) { return '--- ' + f.name + ' ---\n' + stripYamlFrontmatter(f.content || ''); }).join('\n\n');
          const content = fileContent && manual ? fileContent + '\n\n--- Manual ---\n' + manual
            : fileContent || manual;
          fs.mkdirSync(path.dirname(GUIDELINES_FILE), { recursive: true });
          fs.writeFileSync(GUIDELINES_FILE, JSON.stringify({ content, files, manual, evaluateGuidelines }), 'utf8');
          sendJson(res, 200, { ok: true });
        } catch (e) {
          console.error('[Design Guardian] POST /ai/guidelines error:', e.message);
          sendJson(res, 500, { error: e.message || 'Failed to save guidelines' });
        }
      });
      return;
    }

    // ── POST /ai/evaluate-guidelines ─────────────────────────────────────────
    // Evaluates uploaded guidelines for quality before they are used in scans.
    // Body: { content: string }
    // Returns: { ok: true, issues: [{ severity, category, message, suggestion }] }
    if (req.method === 'POST' && url.pathname === '/ai/evaluate-guidelines') {
      if (!aiTokenGuard(req, res)) return;
      const evalChunks = [];
      let evalBodySize = 0, evalBodyTooBig = false;
      req.on('data', function(chunk) { evalBodySize += chunk.length; if (evalBodySize > MAX_BODY_BYTES) { evalBodyTooBig = true; return; } evalChunks.push(chunk); });
      req.on('end', async function() {
        if (evalBodyTooBig) { sendJson(res, 413, { error: 'Content exceeds 5 MB limit' }); return; }
        const body = Buffer.concat(evalChunks).toString('utf8');
        try {
          const { content } = JSON.parse(body);
          if (!content || !content.trim()) {
            sendJson(res, 400, { error: 'content is required' });
            return;
          }
          const contentHash = require('crypto').createHash('sha256').update(content).digest('hex').slice(0, 16);
          if (_evalGuidelinesCache[contentHash]) {
            sendJson(res, 200, { ok: true, issues: _evalGuidelinesCache[contentHash], cached: true });
            return;
          }
          // Coalesce concurrent requests for the same content — only one Claude call fires.
          if (_evalGuidelinesInFlight[contentHash]) {
            const issues = await _evalGuidelinesInFlight[contentHash];
            sendJson(res, 200, { ok: true, issues, cached: true });
            return;
          }
          const cfg = loadAiConfig();
          if (!cfg.provider) {
            sendJson(res, 400, { error: 'AI provider not configured. Set it in plugin settings.' });
            return;
          }
          const model = cfg.model || AI_DEFAULT_MODELS[cfg.provider] || '';
          const evalPromise = runAiGuidelinesEvaluation(cfg, model, content);
          _evalGuidelinesInFlight[contentHash] = evalPromise;
          let issues;
          try {
            issues = await evalPromise;
          } finally {
            delete _evalGuidelinesInFlight[contentHash];
          }
          // Only cache non-empty results — empty arrays are indistinguishable from a parse
          // failure and locking in [] would hide a failed call on the next request.
          if (issues && issues.length > 0) { _evalGuidelinesCache[contentHash] = issues; persistEvalGuidelinesCache(); }
          sendJson(res, 200, { ok: true, issues: issues || [] });
        } catch (e) {
          sendJson(res, 500, { error: e.message || 'Guidelines evaluation failed' });
        }
      });
      return;
    }

    // ── POST /ai/evaluate-guidelines-batch ───────────────────────────────────
    // Evaluates multiple guidelines files in a single AI call. Saves one CLI spawn per file
    // vs. the per-file /ai/evaluate-guidelines endpoint. Cache is still keyed per-file so
    // changing one file does not force re-evaluation of the others.
    // Body: { files: [{ name: string, content: string }] }
    // Returns: { ok: true, results: { [name]: { issues: [], cached: bool } } }
    if (req.method === 'POST' && url.pathname === '/ai/evaluate-guidelines-batch') {
      if (!aiTokenGuard(req, res)) return;
      const batchEvalChunks = [];
      let batchEvalSize = 0, batchEvalTooBig = false;
      req.on('data', function(chunk) { batchEvalSize += chunk.length; if (batchEvalSize > MAX_BODY_BYTES) { batchEvalTooBig = true; return; } batchEvalChunks.push(chunk); });
      req.on('end', async function() {
        if (batchEvalTooBig) { sendJson(res, 413, { error: 'Content exceeds 5 MB limit' }); return; }
        const body = Buffer.concat(batchEvalChunks).toString('utf8');
        try {
          const { files } = JSON.parse(body);
          if (!Array.isArray(files) || files.length === 0) {
            sendJson(res, 400, { error: 'files array is required' }); return;
          }
          const cfg = loadAiConfig();
          if (!cfg.provider) {
            sendJson(res, 400, { error: 'AI provider not configured. Set it in plugin settings.' }); return;
          }
          const model = cfg.model || AI_DEFAULT_MODELS[cfg.provider] || '';

          // Check the per-file cache first — only changed files need a new AI call.
          const results = {};
          const uncached = [];
          files.forEach(function(f) {
            if (!f.content || !f.content.trim()) return;
            const hash = require('crypto').createHash('sha256').update(f.content).digest('hex').slice(0, 16);
            if (_evalGuidelinesCache[hash]) {
              results[f.name] = { issues: _evalGuidelinesCache[hash], cached: true };
            } else {
              uncached.push({ name: f.name, content: f.content, hash: hash });
            }
          });

          if (uncached.length === 0) {
            sendJson(res, 200, { ok: true, results }); return;
          }

          const rawBatch = await runAiGuidelinesEvaluationBatch(cfg, model, uncached);
          if (Array.isArray(rawBatch)) {
            var cacheDirty = false;
            rawBatch.forEach(function(entry) {
              if (!entry || !entry.name) return;
              const file = uncached.find(function(f) { return f.name === entry.name; });
              if (!file) return;
              const issues = Array.isArray(entry.issues) ? entry.issues : [];
              if (issues.length > 0) { _evalGuidelinesCache[file.hash] = issues; cacheDirty = true; }
              results[entry.name] = { issues: issues, cached: false };
            });
            if (cacheDirty) persistEvalGuidelinesCache();
          }
          // Fill any files the AI didn't return (parse failure, etc.) with empty results.
          uncached.forEach(function(f) {
            if (!results[f.name]) results[f.name] = { issues: [], cached: false };
          });

          sendJson(res, 200, { ok: true, results });
        } catch (e) {
          sendJson(res, 500, { error: e.message || 'Guidelines batch evaluation failed' });
        }
      });
      return;
    }

    // ── POST /ai/test-connection ─────────────────────────────────────────────
    // Tests the configured AI provider by sending a minimal 1-token prompt.
    // Body: { provider, apiKey, model, authMethod }
    // Returns: { ok: true } or { ok: false, error: string }
    if (req.method === 'POST' && url.pathname === '/ai/test-connection') {
      const chunks = [];
      req.on('data', function(chunk) { chunks.push(chunk); });
      req.on('end', async function() {
        try {
          const body = JSON.parse(Buffer.concat(chunks).toString('utf8'));
          const { provider, apiKey, model, authMethod } = body;
          if (authMethod === 'cli') {
            const cliCmd = provider === 'anthropic' ? 'claude' : provider === 'google' ? 'gemini' : 'codex';
            const installed = await isCliInstalled(cliCmd);
            if (!installed) { sendJson(res, 200, { ok: false, error: cliCmd + ' CLI not found on PATH' }); return; }
            const authed = await checkCliAuth(provider);
            if (!authed) { sendJson(res, 200, { ok: false, error: 'CLI is not logged in. Run the login command first.' }); return; }
            sendJson(res, 200, { ok: true });
            return;
          }
          if (!apiKey) { sendJson(res, 200, { ok: false, error: 'API key is required' }); return; }
          if (!model)  { sendJson(res, 200, { ok: false, error: 'Model is required' }); return; }
          const testPrompt = 'Reply with the single word: ok';
          // A real, billed call, just a tiny one (max_tokens: 5) — verified directly this wasn't
          // logged at all, same gap as runCliToolFetch. Log it too so "every AI call" actually means
          // every one, not just the ones inside a content scan.
          const _testStart = Date.now();
          if (provider === 'anthropic') {
            const _testRes = await fetchJson('https://api.anthropic.com/v1/messages', {
              method: 'POST',
              headers: { 'Content-Type': 'application/json', 'x-api-key': apiKey, 'anthropic-version': '2023-06-01' },
              body: JSON.stringify({ model, max_tokens: 5, messages: [{ role: 'user', content: testPrompt }] }),
            }, 'Anthropic API');
            const _testUsage = _testRes && _testRes.usage;
            logAiUsage('test-connection', model, _testUsage && _testUsage.input_tokens, _testUsage && _testUsage.output_tokens,
              (_testUsage && _testUsage.cache_read_input_tokens) || 0, (_testUsage && _testUsage.cache_creation_input_tokens) || 0, Date.now() - _testStart);
          } else if (provider === 'openai') {
            const _testRes = await fetchJson('https://api.openai.com/v1/chat/completions', {
              method: 'POST',
              headers: { 'Content-Type': 'application/json', 'Authorization': 'Bearer ' + apiKey },
              body: JSON.stringify({ model, max_tokens: 5, messages: [{ role: 'user', content: testPrompt }] }),
            }, 'OpenAI API');
            const _testUsage = _testRes && _testRes.usage;
            logAiUsage('test-connection', model, _testUsage && _testUsage.prompt_tokens, _testUsage && _testUsage.completion_tokens, 0, 0, Date.now() - _testStart);
          } else if (provider === 'google') {
            const endpoint = 'https://generativelanguage.googleapis.com/v1beta/models/' + model + ':generateContent?key=' + apiKey;
            const _testRes = await fetchJson(endpoint, {
              method: 'POST',
              headers: { 'Content-Type': 'application/json' },
              body: JSON.stringify({ contents: [{ parts: [{ text: testPrompt }] }] }),
            }, 'Google AI API');
            const _testUsage = _testRes && _testRes.usageMetadata;
            logAiUsage('test-connection', model, _testUsage && _testUsage.promptTokenCount, _testUsage && _testUsage.candidatesTokenCount, 0, 0, Date.now() - _testStart);
          } else {
            sendJson(res, 200, { ok: false, error: 'Unknown provider: ' + provider }); return;
          }
          sendJson(res, 200, { ok: true });
        } catch (e) {
          sendJson(res, 200, { ok: false, error: e.message || 'Connection failed' });
        }
      });
      return;
    }

    // ── GET /ai/test-endpoint ────────────────────────────────────────────────
    // Tests an Ollama endpoint by calling /api/tags and checking for a model list.
    // Query param: url (the Ollama base URL)
    // Returns: { ok: true, models: [...] } or { ok: false, error: string }
    if (req.method === 'GET' && url.pathname === '/ai/test-endpoint') {
      const ollamaUrl = (url.searchParams.get('url') || '').replace(/\/$/, '');
      if (!ollamaUrl) { sendJson(res, 200, { ok: false, error: 'url parameter is required' }); return; }
      try {
        const result = await fetchJson(ollamaUrl + '/api/tags', {}, 'Ollama');
        const models = (result && Array.isArray(result.models) ? result.models : []).map(function(m) { return m.name || m; });
        sendJson(res, 200, { ok: true, models });
      } catch (e) {
        sendJson(res, 200, { ok: false, error: e.message || 'Could not reach Ollama endpoint' });
      }
      return;
    }

    // ── POST /ai/scan ────────────────────────────────────────────────────────
    // Accepts text nodes from a frame, checks against guidelines via configured AI provider.
    // Protected by pairing token (X-DG-Token header).
    // Body: { textNodes: [{ id, name, characters, path }] }
    if (req.method === 'POST' && url.pathname === '/ai/scan') {
      if (!aiTokenGuard(req, res)) return;
      const chunks = [];
      req.on('data', function(chunk) { chunks.push(chunk); });
      req.on('end', function() {
      _requestCostStore.run({ costUsd: 0, costUnknown: false, calls: 0 }, async function() {
        const body = Buffer.concat(chunks).toString('utf8');
        try {
          const { textNodes } = JSON.parse(body);
          if (!Array.isArray(textNodes) || textNodes.length === 0) {
            sendJson(res, 400, { error: 'textNodes array is required' });
            return;
          }

          const cfg = loadAiConfig();
          if (!cfg.provider) {
            sendJson(res, 400, { error: 'AI provider not configured. Set it in plugin settings.' });
            return;
          }

          let guidelines = '';
          let guidelinesFiles = [];
          let guidelinesManual = '';
          try {
            const raw = fs.readFileSync(GUIDELINES_FILE, 'utf8');
            let parsed;
            try { parsed = JSON.parse(raw); } catch (_) { parsed = null; }
            guidelines = (parsed && typeof parsed.content === 'string') ? parsed.content : raw;
            guidelinesFiles = (parsed && Array.isArray(parsed.files)) ? parsed.files : [];
            guidelinesManual = (parsed && typeof parsed.manual === 'string') ? parsed.manual : '';
          } catch (_) {}
          if (!guidelines.trim()) {
            sendJson(res, 400, { error: 'No content guidelines found. Upload guidelines in plugin settings.' });
            return;
          }

          const model = cfg.model || AI_DEFAULT_MODELS[cfg.provider] || '';
          const detectedComponentNames = detectComponentNames(textNodes);

          // Step 1: extract component-page map + URL scopes (cached by guidelines content hash).
          const extracted = await extractGuidelineRules(cfg, model, guidelines);

          // Step 2: resolve inline URLs and fetch component Confluence pages — independent of each
          // other, both depend only on `extracted`, so they run in parallel.
          const [urlResult, pagesResult] = await Promise.all([
            resolveGuidelinesUrls(guidelines, extracted && extracted.urlScopes, detectedComponentNames),
            fetchComponentPagesAppendix(extracted, textNodes),
          ]);
          const { content: resolvedGuidelines } = urlResult;
          const augmentedGuidelines = pagesResult.text ? resolvedGuidelines + '\n\n## Additional component-specific guideline pages\n' + pagesResult.text : resolvedGuidelines;
          // Report generic-resolver URLs AND component-page fetches together, so the plugin's
          // "External sources" card shows every source it tried — passed and failed.
          const fetchedUrls = urlResult.fetchedUrls.concat(pagesResult.fetchedUrls);
          const failedUrls = urlResult.failedUrls.concat(pagesResult.failedUrls);

          // Step 3: AI scan with fully-assembled guidelines.
          const issues = await runAiContentScan(cfg, model, augmentedGuidelines, textNodes, guidelinesFiles, guidelinesManual);
          const _reqCost = _requestCostStore.getStore() || { costUsd: 0, costUnknown: false, calls: 0 };
          const _scanCostLabel = _reqCost.costUnknown ? ('$' + _reqCost.costUsd.toFixed(4) + '+') : ('$' + _reqCost.costUsd.toFixed(4));
          console.log('[Design Guardian] /ai/scan request nodeCount=' + textNodes.length + ' guidelines_bytes=' + guidelines.length + ' ai_calls=' + _reqCost.calls + ' total_cost=' + _scanCostLabel);
          sendJson(res, 200, { ok: true, issues, urlWarnings: failedUrls.length > 0 ? failedUrls : undefined, fetchedUrls: fetchedUrls.length > 0 ? fetchedUrls : undefined, meta: { provider: cfg.provider, model, nodeCount: textNodes.length, totalCostUsd: _reqCost.costUsd, aiCalls: _reqCost.calls } });
        } catch (e) {
          console.error('[Design Guardian] /ai/scan request FAILED: ' + e.message);
          sendJson(res, 500, { error: e.message || 'AI scan failed' });
        }
      });
      });
      return;
    }

    // ── POST /ai/scan-batch ──────────────────────────────────────────────────
    // Evaluates 2-3 frames in a single Claude call to amortise the guidelines
    // cache_miss across all frames. Used when totalChunks <= 3.
    // Body: { frames: [{ frameName: string, textNodes: [...] }] }
    if (req.method === 'POST' && url.pathname === '/ai/scan-batch') {
      if (!aiTokenGuard(req, res)) return;
      const batchChunks = [];
      req.on('data', function(chunk) { batchChunks.push(chunk); });
      req.on('end', function() {
      _requestCostStore.run({ costUsd: 0, costUnknown: false, calls: 0 }, async function() {
        const body = Buffer.concat(batchChunks).toString('utf8');
        try {
          const { frames } = JSON.parse(body);
          if (!Array.isArray(frames) || frames.length === 0) {
            sendJson(res, 400, { error: 'frames array is required' }); return;
          }
          const cfg = loadAiConfig();
          if (!cfg.provider) {
            sendJson(res, 400, { error: 'AI provider not configured. Set it in plugin settings.' }); return;
          }
          let guidelines = '';
          let guidelinesFiles = [];
          let guidelinesManual = '';
          try {
            const raw = fs.readFileSync(GUIDELINES_FILE, 'utf8');
            let parsed;
            try { parsed = JSON.parse(raw); } catch (_) { parsed = null; }
            guidelines = (parsed && typeof parsed.content === 'string') ? parsed.content : raw;
            guidelinesFiles = (parsed && Array.isArray(parsed.files)) ? parsed.files : [];
            guidelinesManual = (parsed && typeof parsed.manual === 'string') ? parsed.manual : '';
          } catch (_) {}
          if (!guidelines.trim()) {
            sendJson(res, 400, { error: 'No content guidelines found. Upload guidelines in plugin settings.' }); return;
          }
          const model = cfg.model || AI_DEFAULT_MODELS[cfg.provider] || '';
          var _allNodes = frames.reduce(function(acc, f) { return acc.concat(f.textNodes || []); }, []);
          const detectedComponentNames = detectComponentNames(_allNodes);

          // Step 1: extract component-page map + URL scopes (cached by guidelines content hash).
          const extracted = await extractGuidelineRules(cfg, model, guidelines);

          // Step 2: resolve inline URLs and fetch component Confluence pages in parallel.
          const [urlResult, pagesResult] = await Promise.all([
            resolveGuidelinesUrls(guidelines, extracted && extracted.urlScopes, detectedComponentNames),
            fetchComponentPagesAppendix(extracted, _allNodes),
          ]);
          const { content: resolvedGuidelines } = urlResult;
          const augmentedGuidelines = pagesResult.text ? resolvedGuidelines + '\n\n## Additional component-specific guideline pages\n' + pagesResult.text : resolvedGuidelines;
          const fetchedUrls = urlResult.fetchedUrls.concat(pagesResult.fetchedUrls);
          const failedUrls = urlResult.failedUrls.concat(pagesResult.failedUrls);

          // Step 3: AI scan with fully-assembled guidelines.
          const issues = await runAiContentScanBatch(cfg, model, augmentedGuidelines, frames, guidelinesFiles, guidelinesManual);
          var _totalNodes = frames.reduce(function(sum, f) { return sum + ((f.textNodes && f.textNodes.length) || 0); }, 0);
          const _reqCost = _requestCostStore.getStore() || { costUsd: 0, costUnknown: false, calls: 0 };
          const _scanCostLabel = _reqCost.costUnknown ? ('$' + _reqCost.costUsd.toFixed(4) + '+') : ('$' + _reqCost.costUsd.toFixed(4));
          console.log('[Design Guardian] /ai/scan-batch request frameCount=' + frames.length + ' nodeCount=' + _totalNodes + ' guidelines_bytes=' + guidelines.length + ' ai_calls=' + _reqCost.calls + ' total_cost=' + _scanCostLabel);
          sendJson(res, 200, { ok: true, issues, urlWarnings: failedUrls.length > 0 ? failedUrls : undefined, fetchedUrls: fetchedUrls.length > 0 ? fetchedUrls : undefined, meta: { provider: cfg.provider, model, frameCount: frames.length, totalCostUsd: _reqCost.costUsd, aiCalls: _reqCost.calls } });
        } catch (e) {
          console.error('[Design Guardian] /ai/scan-batch request FAILED: ' + e.message);
          sendJson(res, 500, { error: e.message || 'Batch scan failed' });
        }
      });
      });
      return;
    }

    // ── POST /ai/normalize ───────────────────────────────────────────────────
    // Normalizes rule names and severity levels across issues found in parallel
    // frame scans. Accepts raw AI issues and returns a consistent set.
    // Body: { issues: [...rawAiIssues] }
    if (req.method === 'POST' && url.pathname === '/ai/normalize') {
      if (!aiTokenGuard(req, res)) return;
      const normChunks = [];
      req.on('data', function(chunk) { normChunks.push(chunk); });
      req.on('end', function() {
      // Wrapped in the per-request cost store (like /ai/scan) so this call's cost is captured and
      // returned in meta — normalize is a real AI call the scan triggers, so the plugin's "AI cost"
      // stat must include it rather than silently omitting it.
      _requestCostStore.run({ costUsd: 0, costUnknown: false, calls: 0 }, async function() {
        try {
          const body = JSON.parse(Buffer.concat(normChunks).toString('utf8'));
          const issues = Array.isArray(body.issues) ? body.issues : [];
          if (issues.length === 0) { sendJson(res, 200, { ok: true, issues: [], meta: { totalCostUsd: 0, aiCalls: 0 } }); return; }
          const cfg = loadAiConfig();
          if (!cfg.provider) { sendJson(res, 400, { error: 'AI provider not configured' }); return; }
          const model = cfg.model || AI_DEFAULT_MODELS[cfg.provider] || '';
          const normalized = await runAiNormalizationPass(cfg, model, issues);
          const _reqCost = _requestCostStore.getStore() || { costUsd: 0, calls: 0 };
          sendJson(res, 200, { ok: true, issues: normalized, meta: { totalCostUsd: _reqCost.costUsd, aiCalls: _reqCost.calls } });
        } catch (e) {
          sendJson(res, 500, { error: e.message || 'Normalization failed' });
        }
      });
      });
      return;
    }

    // ── POST /ai/explain-issue ────────────────────────────────────────────────
    // On-demand reasoning for ONE content issue — not baked into the main scan, so most issues
    // (self-evident from their citation + suggestion alone) never pay this cost. Only the specific
    // issue a user clicks "Explain" on triggers this, and only that one. Small, focused prompt —
    // no guidelines document, no tool-use — so this should be quicker than the per-component
    // Confluence fetches, though unverified against a real timing measurement.
    // Body: { characters, issue, guidelineQuote, suggestion, suggestionOptions, rule }
    if (req.method === 'POST' && url.pathname === '/ai/explain-issue') {
      if (!aiTokenGuard(req, res)) return;
      const explainChunks = [];
      req.on('data', function(chunk) { explainChunks.push(chunk); });
      req.on('end', function() {
      // Per-request cost store (like /ai/scan and /ai/normalize) so this on-demand call's cost is
      // captured and returned in meta. A cache hit returns before any callAiProvider call, so the
      // store stays 0 — the plugin then correctly adds $0 for a repeat click on the same issue.
      _requestCostStore.run({ costUsd: 0, costUnknown: false, calls: 0 }, async function() {
        try {
          const body = JSON.parse(Buffer.concat(explainChunks).toString('utf8'));
          const characters = String(body.characters || '').slice(0, 2000);
          const issueText = String(body.issue || '').slice(0, 500);
          const guidelineQuote = String(body.guidelineQuote || '').slice(0, 2000);
          const suggestion = String(body.suggestion || '').slice(0, 500);
          const rule = String(body.rule || '').slice(0, 200);
          // suggestionOptions: the judgment-call case from runAiContentScan — 2 candidate fixes
          // instead of one. When present, "suggestion" is empty (see toContentIssue in ui.html) and
          // the explanation should address why it's ambiguous enough to need 2 options, not restate
          // a single fix's rationale.
          const suggestionOptions = Array.isArray(body.suggestionOptions)
            ? body.suggestionOptions.slice(0, 2).map(function(o) {
                return { label: String((o && o.label) || '').slice(0, 50), text: String((o && o.text) || '').slice(0, 500) };
              }).filter(function(o) { return o.text; })
            : [];
          if (!issueText || (!suggestion && suggestionOptions.length === 0)) {
            sendJson(res, 400, { error: 'issue and a suggestion (or suggestionOptions) are required' });
            return;
          }

          const cfg = loadAiConfig();
          if (!cfg.provider) { sendJson(res, 400, { error: 'AI provider not configured' }); return; }
          const model = cfg.model || AI_DEFAULT_MODELS[cfg.provider] || '';

          const optionsKeyPart = suggestionOptions.map(function(o) { return o.label + ':' + o.text; }).join('|');
          const cacheKey = crypto.createHash('sha256').update(characters + '|' + issueText + '|' + guidelineQuote + '|' + suggestion + '|' + optionsKeyPart).digest('hex');
          const cached = _explainIssueCache[cacheKey];
          if (cached) { sendJson(res, 200, { ok: true, reasoning: cached, cached: true, meta: { totalCostUsd: 0, aiCalls: 0 } }); return; }

          const prompt = suggestionOptions.length > 0
            ? [
                'A content review flagged this text and offered 2 alternative fixes instead of one,',
                'because it judged this a genuine judgment call. Explain briefly why the cited guideline',
                'makes this ambiguous, and what meaningfully differs between the two options.',
                '',
                'Flagged text: ' + JSON.stringify(characters),
                'Issue: ' + issueText,
                'Rule: ' + (rule || '(unspecified)'),
                'Cited guideline: ' + JSON.stringify(guidelineQuote || '(no citation available)'),
                suggestionOptions.map(function(o) { return o.label + ': ' + o.text; }).join('\n'),
                '',
                'Return ONLY a JSON array containing exactly one object: [{ "reasoning": "..." }]',
                '"reasoning" must be 1-2 sentences, plain text, no markdown. Explain why the guideline',
                'permits either option (what they have in common that satisfies it) and what actually',
                'differs between them (tone, formality, length) — not a restatement of the issue.',
                'Return only valid JSON, no explanation outside it.',
              ].join('\n')
            : [
                'A content review flagged this text and suggested a fix. Explain briefly why the cited',
                'guideline supports this specific fix.',
                '',
                'Flagged text: ' + JSON.stringify(characters),
                'Issue: ' + issueText,
                'Rule: ' + (rule || '(unspecified)'),
                'Cited guideline: ' + JSON.stringify(guidelineQuote || '(no citation available)'),
                'Suggested fix: ' + suggestion,
                '',
                'Return ONLY a JSON array containing exactly one object: [{ "reasoning": "..." }]',
                '"reasoning" must be 1-2 sentences, plain text, no markdown. Explain the connection between',
                'the cited guideline and the suggested fix — not a restatement of the issue. If there is a',
                'genuinely reasonable alternative fix, mention it briefly in the same field.',
                'Return only valid JSON, no explanation outside it.',
              ].join('\n');

          const result = await callAiProvider(cfg, model, prompt, null, 'explain-issue');
          const obj = unwrapAiObject(result);
          const reasoning = (obj && typeof obj.reasoning === 'string') ? obj.reasoning.trim() : '';
          if (!reasoning) { sendJson(res, 500, { error: 'Could not generate an explanation' }); return; }
          _explainIssueCache[cacheKey] = reasoning;
          var _reqCost = _requestCostStore.getStore() || { costUsd: 0, calls: 0 };
          sendJson(res, 200, { ok: true, reasoning: reasoning, cached: false, meta: { totalCostUsd: _reqCost.costUsd, aiCalls: _reqCost.calls } });
        } catch (e) {
          sendJson(res, 500, { error: e.message || 'Explain failed' });
        }
      });
      });
      return;
    }

    // ── POST /add-comment ────────────────────────────────────────────────────
    // Posts a Figma comment on a specific node using the user's PAT.
    // Body: { fileKey, nodeId, message, x, y }
    if (req.method === 'POST' && url.pathname === '/add-comment') {
      if (!hasFigmaAuth(req)) {
        sendJson(res, 500, { error: 'No Figma authentication available. Sign in via OAuth or configure FIGMA_PAT.' });
        return;
      }
      const chunks = [];
      req.on('data', function(chunk) { chunks.push(chunk); });
      req.on('end', async function() {
        const figmaHeaders = await getFigmaAuthHeaders(req);
        const body = Buffer.concat(chunks).toString('utf8');
        try {
          const { fileKey, nodeId, x, y, offsetX, offsetY, message } = JSON.parse(body);
          if (!fileKey) { sendJson(res, 400, { error: 'fileKey is required' }); return; }
          if (!message) { sendJson(res, 400, { error: 'message is required' }); return; }

          // Plugin API node IDs for instance override children use the format "I123:456;789:012;..."
          // where "I" is a prefix and ";" separates the ancestor chain. Figma REST API only
          // accepts a simple "123:456" node ID — strip the prefix and take the first segment.
          let cleanNodeId = nodeId || '';
          if (cleanNodeId.startsWith('I')) cleanNodeId = cleanNodeId.slice(1);
          if (cleanNodeId.includes(';')) cleanNodeId = cleanNodeId.split(';')[0];
          // The REST API uses colon form ("123:456"). Normalizing hyphens to colons repairs any
          // mangled IDs before they reach Figma.
          cleanNodeId = cleanNodeId.replace(/-/g, ':');
          const restNodeId = cleanNodeId || null;
          const figmaUrl = `https://api.figma.com/v1/files/${fileKey}/comments`;
          // Anchor to the node when we have one — this is page-aware (Figma knows which page the
          // node lives on). An absolute {x,y} pin has no page context and Figma drops it on the
          // default page, which is why pinning put comments on the wrong page.
          const pinMeta = { x: Math.round(x || 0), y: Math.round(y || 0) };
          // node_offset positions the comment within the anchored node. For instance sublayers the
          // plugin computes the text's offset from the instance root so the comment lands on the text.
          const nodeOffset = { x: Math.round(offsetX || 0), y: Math.round(offsetY || 0) };
          const client_meta = restNodeId
            ? { node_id: restNodeId, node_offset: nodeOffset }
            : pinMeta;

          let result;
          try {
            result = await fetchJson(figmaUrl, {
              method: 'POST',
              headers: Object.assign({}, figmaHeaders, { 'Content-Type': 'application/json' }),
              body: JSON.stringify({ message, client_meta }),
            });
          } catch (anchorErr) {
            // Node-anchored post failed (e.g. the node isn't addressable via REST). Rather than
            // lose the comment, retry as an absolute canvas pin using the coords the plugin captured.
            if (restNodeId) {
              console.warn('[Design Guardian] add-comment node-anchor failed; retrying as canvas pin:', anchorErr.message);
              result = await fetchJson(figmaUrl, {
                method: 'POST',
                headers: Object.assign({}, figmaHeaders, { 'Content-Type': 'application/json' }),
                body: JSON.stringify({ message, client_meta: pinMeta }),
              });
            } else {
              throw anchorErr;
            }
          }
          sendJson(res, 200, { ok: true, commentId: result.id });
        } catch (e) {
          console.error('[Design Guardian] add-comment error:', e.message);
          sendJson(res, 500, { error: e.message || 'Failed to post comment' });
        }
      });
      return;
    }

    // ── DELETE /remove-comment ───────────────────────────────────────────────
    // Deletes a Figma comment previously posted by /add-comment.
    // Body: { fileKey, commentId }
    if (req.method === 'DELETE' && url.pathname === '/remove-comment') {
      if (!hasFigmaAuth(req)) {
        sendJson(res, 500, { error: 'No Figma authentication available. Sign in via OAuth or configure FIGMA_PAT.' });
        return;
      }
      const chunks = [];
      req.on('data', function(chunk) { chunks.push(chunk); });
      req.on('end', async function() {
        const figmaHeaders = await getFigmaAuthHeaders(req);
        const body = Buffer.concat(chunks).toString('utf8');
        try {
          const { fileKey, commentId } = JSON.parse(body);
          if (!fileKey)   { sendJson(res, 400, { error: 'fileKey is required' }); return; }
          if (!commentId) { sendJson(res, 400, { error: 'commentId is required' }); return; }

          const controller = new AbortController();
          const timeoutId = setTimeout(() => controller.abort(), 30000);
          const response = await fetch(
            `https://api.figma.com/v1/files/${fileKey}/comments/${commentId}`,
            { method: 'DELETE', headers: figmaHeaders, signal: controller.signal }
          );
          clearTimeout(timeoutId);

          if (!response.ok) {
            const text = await response.text();
            let detail = `HTTP ${response.status}`;
            try { const j = JSON.parse(text); detail = j.err || j.message || j.error || detail; } catch (_) {}
            throw new Error(`Figma API ${response.status}: ${detail}`);
          }

          sendJson(res, 200, { ok: true });
        } catch (e) {
          console.error('[Design Guardian] remove-comment error:', e.message);
          sendJson(res, 500, { error: e.message || 'Failed to delete comment' });
        }
      });
      return;
    }

    sendJson(res, 404, { error: 'Not found' });
  } catch (error) {
    sendJson(res, 500, { error: error.message || 'Unknown error' });
  }
}

// stripYamlFrontmatter: removes --- ... --- block from the start of a SKILL.md file so only the body is used as guidelines.
function stripYamlFrontmatter(text) {
  if (!text || !text.startsWith('---')) return text;
  var end = text.indexOf('\n---', 3);
  if (end === -1) return text;
  return text.slice(end + 4).replace(/^\n/, '');
}

// ── URL resolution for guidelines ────────────────────────────────────────────
// Detects URLs in guidelines content, fetches them, and inlines the content so
// Claude sees the actual referenced material. Direct HTTP is tried first; if it
// fails (auth required, VPN, 4xx) the request falls back to the Claude CLI which
// has access to any MCP connectors the user has configured (Notion, Confluence,
// Google Drive, etc.) and can reach resources behind VPN/auth.

// Shared by resolveGuidelinesUrls (skips these entirely — handled by the scan-scoped
// fetchComponentPagesAppendix -> fetchConfluencePage path instead) and extractGuidelineRules
// (excludes these from the generic urlScopes classification, since they're not "generic" links).
const CONFLUENCE_URL_RE = /\/wiki\/spaces\/[^/]+\/pages\//i;

function extractUrls(text) {
  const seen = new Set();
  const results = [];
  // '<' excluded alongside the existing '>' — not a legal URL character, so this only ever
  // truncates a match early (e.g. a doc's own "pattern: url/<placeholder>" example prose getting
  // scraped as if the placeholder were a real path segment), never drops a well-formed URL.
  // em dash / en dash / '*' excluded too — verified directly: prose like "...pages/12345—**verified**"
  // with no space before the dash was getting captured as part of the URL, producing a second,
  // garbled cache key for the same link and doubling failed-fetch cost for one dead URL.
  const re = /https?:\/\/[^\s)>"'\]\\,<—–*]+/g;
  let m;
  while ((m = re.exec(text)) !== null) {
    const url = m[0].replace(/[.,;:!?]+$/, ''); // strip trailing punctuation
    if (!seen.has(url)) { seen.add(url); results.push(url); }
  }
  return results;
}

function stripHtmlTags(html) {
  return html
    .replace(/<script[\s\S]*?<\/script>/gi, '')
    .replace(/<style[\s\S]*?<\/style>/gi, '')
    .replace(/<[^>]+>/g, ' ')
    .replace(/&nbsp;/g, ' ').replace(/&amp;/g, '&')
    .replace(/&lt;/g, '<').replace(/&gt;/g, '>').replace(/&quot;/g, '"')
    .replace(/\s{2,}/g, ' ')
    .trim();
}

async function fetchUrlDirect(url) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), 8000);
  try {
    const res = await fetch(url, { signal: controller.signal, headers: { 'User-Agent': 'DesignGuardian/1.0' } });
    clearTimeout(timer);
    if (!res.ok) {
      console.warn('[Design Guardian] fetch-url direct HTTP ' + res.status + ' for ' + url);
      return null;
    }
    const text = await res.text();
    const ct = res.headers.get('content-type') || '';
    const content = ct.includes('html') ? stripHtmlTags(text) : text;
    return content.slice(0, 20000) || null;
  } catch (err) {
    clearTimeout(timer);
    const reason = err.name === 'AbortError' ? 'timeout (8s)' : err.message;
    console.warn('[Design Guardian] fetch-url direct failed (' + reason + ') for ' + url);
    return null;
  }
}

// buildCliFetchPrompt: generic "use any connector" instruction, EXCEPT for a recognized Confluence
// page URL, where it gives an explicit tool-call instruction instead (cloudId + pageId). The
// generic phrasing leaves the model to reverse-engineer the URL shape into the right connector
// call on its own, which it doesn't reliably do — verified directly: the same Atlassian connector
// fetches the same page fine when given cloudId/pageId explicitly. Other URL shapes (or connectors
// that don't exist at all, e.g. a Salesforce-gated community article) keep the generic fallback —
// this only helps the case that was actually reachable but mis-instructed.
function buildCliFetchPrompt(url) {
  var confluenceMatch = url.match(/^https?:\/\/([^/]+)\/wiki\/spaces\/[^/]+\/pages\/(\d+)/i);
  if (confluenceMatch) {
    var hostname = confluenceMatch[1];
    var pageId = confluenceMatch[2];
    return [
      'This is a Confluence page. Use your Confluence/Atlassian connector\'s page-fetch tool directly',
      '(e.g. getConfluencePage) with cloudId="' + hostname + '" and pageId="' + pageId + '".',
      'Do NOT try to fetch the raw URL as a generic web page.',
      '',
      'Rules:',
      '- Return ONLY the page body content as plain text — no markdown formatting, no explanation, no extra commentary.',
      '- Do NOT make up or summarise the content.',
      '- If the tool call fails or the page cannot be found, your response MUST BEGIN with the literal text FETCH_FAILED. You may then add a colon and a SHORT reason for our diagnostic logs — e.g. "FETCH_FAILED: page not found", "FETCH_FAILED: permission denied", "FETCH_FAILED: page has no body content", "FETCH_FAILED: tool returned an error". The FETCH_FAILED marker MUST come first and MUST be present on any failure. On SUCCESS (you got real page content) do NOT include the word FETCH_FAILED anywhere — return only the page body.',
    ].join('\n');
  }
  return [
    'Use any available tools or connectors to fetch the full text content of this URL:',
    url,
    '',
    'Rules:',
    '- Use a connector/tool to retrieve it. Do NOT make up or summarise the content.',
    '- Return ONLY the raw text content — no markdown, no explanation, no extra commentary.',
    '- If you cannot retrieve it for any reason, your response MUST BEGIN with the literal text FETCH_FAILED. You may then add a colon and a SHORT reason for our diagnostic logs — e.g. "FETCH_FAILED: page not found", "FETCH_FAILED: permission denied", "FETCH_FAILED: empty content". The FETCH_FAILED marker MUST come first and MUST be present on any failure. On SUCCESS do NOT include the word FETCH_FAILED anywhere — return only the fetched content.',
  ].join('\n');
}

// looksLikePermissionDenial: a headless CLI tool call that gets denied should output exactly
// FETCH_FAILED per the prompt's own instruction, but verified directly that not every model
// follows that reliably — a smaller model can narrate the denial as prose ("I need your permission
// to access...") instead of the literal fallback string. Catch that prose too, so it can't get
// spliced into the guidelines as if it were real fetched content — silently wrong is worse than
// cleanly absent.
function looksLikePermissionDenial(text) {
  return /need(s)? (your )?permission|permission (hasn't|has not) been granted|please approve|not authorized to (access|use)|don'?t have (access|permission)/i.test(text.slice(0, 300));
}

// URL_FETCH_MODEL: model used specifically for the CLI-based guideline-URL fetch, independent of
// whatever model the plugin has configured for the actual content scan (runAiScanCLI). Verified
// directly: once the tool call is actually allowed (see --allowedTools below), a smaller model
// (Haiku, the typical content-scan default) can still fail to reliably use it — it may just
// output the FETCH_FAILED fallback without attempting the tool at all — while a larger model used
// it correctly on the first try. This one fetch is comparatively rare (cached on both success and
// failure — see _URL_CACHE_TTL/_URL_FAILURE_CACHE_TTL), so paying for a more capable model here is
// a narrow, low-volume trade; the high-volume content-scan calls are unaffected and keep using
// whatever model the plugin is configured for.
const URL_FETCH_MODEL = process.env.URL_FETCH_MODEL || 'sonnet';

// runCliToolFetch: spawns `claude -p` with exactly one pre-approved read-only tool and parses the
// result, treating a FETCH_FAILED marker (anywhere in the response — see comment below) or a
// permission-denial narration as failure. Shared by fetchUrlViaCli (arbitrary guideline URLs) and
// fetchConfluencePage (direct component→page lookups) so the model-selection, permission-scoping,
// and failure-detection logic lives in exactly one place instead of being copy-pasted per caller.
// label is only used in log lines to tell the two callers apart.
async function runCliToolFetch(prompt, allowedTool, label) {
  const _cliStart = Date.now();
  try {
    // _cliModelState here only answers "is --model allowed at all" (an enterprise-policy fact
    // shared with runAiScanCLI) — the alias requested is always URL_FETCH_MODEL, never whatever
    // alias runAiScanCLI locked in for the content scan.
    var useFlag = _cliModelState === null || _cliModelState.useFlag;
    var modelAlias = useFlag ? URL_FETCH_MODEL : 'default';
    var args = useFlag
      ? ['-p', '--output-format', 'json', '--allowedTools', allowedTool, '--model', URL_FETCH_MODEL]
      : ['-p', '--output-format', 'json', '--allowedTools', allowedTool];
    var stdout = await spawnCli('claude', args, prompt);
    var wrapper = JSON.parse(stdout);
    // First CLI call in the process to discover whether --model is blocked by enterprise policy —
    // mirrors runAiScanCLI's own detection so whichever call happens first decides it for both.
    if (wrapper.is_error && _cliModelState === null) {
      var errText = (typeof wrapper.result === 'string' ? wrapper.result : '').toLowerCase();
      if (errText.includes('model') || errText.includes('not found') || errText.includes('not available')) {
        console.log('[Design Guardian] --model ' + URL_FETCH_MODEL + ' blocked by policy, retrying ' + label + ' without it');
        _cliModelState = { alias: 'default', useFlag: false };
        modelAlias = 'default';
        stdout = await spawnCli('claude', ['-p', '--output-format', 'json', '--allowedTools', allowedTool], prompt);
        wrapper = JSON.parse(stdout);
      }
    } else if (!wrapper.is_error && _cliModelState === null) {
      _cliModelState = { alias: URL_FETCH_MODEL, useFlag: true };
    }
    // This CLI call is a real, billed Claude invocation (tool-use fetch of a URL/Confluence page),
    // same as the main content-scan/extraction calls — verified directly that it was NOT being
    // logged at all, so its cost was silently missing from _aiScanSession and every total built on
    // top of it (the /ai/scan summary line and the plugin's "AI cost" stat). Log it regardless of
    // whether the fetch succeeded or hit FETCH_FAILED below — a failed fetch still consumed tokens.
    var u = wrapper.usage || {};
    logAiUsage(label, modelAlias + ' (CLI/anthropic)', u.input_tokens, u.output_tokens,
      u.cache_read_input_tokens || 0, u.cache_creation_input_tokens || 0,
      Date.now() - _cliStart, wrapper.total_cost_usd != null ? wrapper.total_cost_usd : null);
    const result = (wrapper.result || '').trim();
    // Verified directly: a model asked to "output exactly FETCH_FAILED" on failure will often
    // still explain itself first and put the literal marker at the END instead of outputting it
    // bare — an anchored ^FETCH_FAILED check misses that entirely and lets the explanation get
    // spliced into the guidelines as if it were real content. Check for the marker ANYWHERE in
    // the response, not just at the start.
    if (!result || /FETCH_FAILED/i.test(result) || looksLikePermissionDenial(result)) {
      console.warn('[Design Guardian] ' + label + ' returned FETCH_FAILED — model said: "' + result.slice(0, 200) + '"' + (wrapper.permission_denials && wrapper.permission_denials.length ? ' (permission denied for: ' + wrapper.permission_denials.map(function(d) { return d.tool_name; }).join(', ') + ')' : ''));
      return null;
    }
    return result.slice(0, 20000);
  } catch (err) {
    console.error('[Design Guardian] ' + label + ' CLI error: ' + err.message);
    return null;
  }
}

async function fetchUrlViaCli(url) {
  if (!await checkClaudeCliAvailable()) return null;
  const prompt = buildCliFetchPrompt(url);
  // Pre-approve ONLY the one specific read-only tool this call needs — never a blanket
  // --dangerously-skip-permissions. The URL being fetched originates from user-uploaded guidelines
  // content, so a full bypass would hand an attacker-influenceable prompt unrestricted tool access
  // (write-capable tools included, e.g. Gmail/Slack), not just this one read. Verified directly:
  // without any allowlist the tool call is silently denied; with a scoped --allowedTools naming
  // exactly the tool needed, the same call succeeds and returns real content.
  const confluenceMatch = url.match(/^https?:\/\/([^/]+)\/wiki\/spaces\/[^/]+\/pages\/(\d+)/i);
  const allowedTool = confluenceMatch ? 'mcp__claude_ai_Atlassian__getConfluencePage' : 'WebFetch';
  return await runCliToolFetch(prompt, allowedTool, 'fetch-url CLI for ' + url);
}

// fetchConfluencePage: direct component -> Confluence page lookup, bypassing extractUrls entirely.
// Most component-guideline pages in a table like components.md are listed as bare page IDs
// ("| Button | 3687940934 |"), never as full https:// links — extractUrls only ever finds a literal
// URL already spelled out in prose, so it structurally can't see these. This fetches by cloudId +
// pageId directly, using the same Confluence prompt/permission/failure handling as fetchUrlViaCli,
// and caches success (1hr) / failure (10min) the same way, keyed by a synthetic "url" so a
// component whose page keeps failing doesn't get re-attempted on every scan.
async function fetchConfluencePage(cloudId, pageId) {
  const cacheKey = 'confluence://' + cloudId + '/' + pageId;
  const now = Date.now();
  const cached = _urlContentCache[cacheKey];
  if (cached && !cached.failed && now - cached.fetchedAt < _URL_CACHE_TTL) {
    console.log('[Design Guardian] component-page fetch cache hit (' + cloudId + '/' + pageId + '), ' + cached.content.length + ' chars');
    return cached.content;
  }
  if (cached && cached.failed && now - cached.fetchedAt < getFailureRetryDelayMs(cached.consecutiveFailures)) {
    console.log('[Design Guardian] component-page fetch skipping known-failed (' + cloudId + '/' + pageId + '), fail streak=' + cached.consecutiveFailures +
      ', retry in ' + Math.ceil((getFailureRetryDelayMs(cached.consecutiveFailures) - (now - cached.fetchedAt)) / 1000) + 's');
    return null;
  }

  if (!await checkClaudeCliAvailable()) return null;

  const prompt = [
    'This is a Confluence page. Use your Confluence/Atlassian connector\'s page-fetch tool directly',
    '(e.g. getConfluencePage) with cloudId="' + cloudId + '" and pageId="' + pageId + '".',
    'Do NOT try to fetch the raw URL as a generic web page.',
    '',
    'Rules:',
    '- Return ONLY the page body content as plain text — no markdown formatting, no explanation, no extra commentary.',
    '- Do NOT make up or summarise the content.',
    '- If the tool call fails or the page cannot be found, your ENTIRE response must be exactly the literal text FETCH_FAILED and nothing else — no explanation of why, even briefly. Any other text in your response, even one extra sentence, is treated as a successful fetch and gets spliced into a real document, so partial compliance is worse than none.',
  ].join('\n');
  const _fetchStart = Date.now();
  const result = await runCliToolFetch(prompt, 'mcp__claude_ai_Atlassian__getConfluencePage', 'component-page fetch (' + cloudId + '/' + pageId + ')');
  const elapsedMs = Date.now() - _fetchStart;
  if (result) {
    console.log('[Design Guardian] component-page fetch SUCCESS (' + cloudId + '/' + pageId + '), ' + result.length + ' chars, elapsed=' + elapsedMs + 'ms');
    _urlContentCache[cacheKey] = { content: result, fetchedAt: now };
    return result;
  }
  var priorFailures = (cached && cached.failed) ? (cached.consecutiveFailures || 1) : 0;
  console.log('[Design Guardian] component-page fetch FAILED (' + cloudId + '/' + pageId + '), elapsed=' + elapsedMs + 'ms, fail streak=' + (priorFailures + 1));
  _urlContentCache[cacheKey] = { failed: true, fetchedAt: now, consecutiveFailures: priorFailures + 1 };
  return null;
}

// resolveGuidelinesUrls: replaces URLs found in guidelines with their fetched content,
// so Claude sees the referenced material inline. Successes cached 1 hour, failures cached
// 10 minutes (see _URL_CACHE_TTL / _URL_FAILURE_CACHE_TTL above).
// urlScopes (from extractGuidelineRules — same cached, hash-checked pass that finds the
// componentPages table) maps a generic URL to the single named component its surrounding text is
// actually about, if any; a URL with no entry is general guidance and always resolved. detectedComponentNames
// is which components are actually present in THIS scan (from the caller's textNodes). A URL scoped
// to a component NOT in this scan is skipped entirely — same principle as the Confluence-page skip
// below, just for links the extraction pass identified as component-specific by reading the doc.
// Returns { content: string, failedUrls: string[], fetchedUrls: string[] }.
async function resolveGuidelinesUrls(content, urlScopes, detectedComponentNames) {
  urlScopes = urlScopes || {};
  detectedComponentNames = detectedComponentNames || [];
  const allUrls = extractUrls(content);

  // Confluence-shaped links (anything under /wiki/spaces/.../pages/...) are never fetched here,
  // whether or not they have a valid numeric page ID. Verified directly: a component's Confluence
  // page can appear as a literal URL in the guidelines doc's own prose (e.g. a worked example of
  // "the pattern is always https://host/wiki/spaces/SPACE/pages/<id>"), and this function used to
  // fetch it unconditionally on every scan — including scans of components that page has nothing
  // to do with (a "Bubble"-only scan still paid for Button's page). Component Confluence pages are
  // already fetched correctly and scan-scoped by fetchComponentPagesAppendix -> fetchConfluencePage,
  // which only fires for components actually detected in that scan. Skipping them here entirely
  // (rather than trying to fetch-and-cache) also kills the malformed/incomplete link case for free —
  // a truncated ".../pages/" with no ID was still being sent to fetchUrlViaCli's generic WebFetch
  // path before, wasting a full CLI round-trip on a link that could never resolve either way.
  const urls = allUrls.filter(function(url) {
    if (CONFLUENCE_URL_RE.test(url)) {
      console.log('[Design Guardian] fetch-url skipping Confluence link (handled by scan-scoped per-component fetch, not the generic resolver): ' + url);
      return false;
    }
    var scopedTo = urlScopes[url];
    if (scopedTo && detectedComponentNames.indexOf(scopedTo) === -1) {
      console.log('[Design Guardian] fetch-url skipping "' + url + '" — scoped to component "' + scopedTo + '", not present in this scan');
      return false;
    }
    return true;
  });
  if (urls.length === 0) return { content, failedUrls: [], fetchedUrls: [] };

  const now = Date.now();

  // logFetchedContent: diagnostic for a "successful" fetch — success just means HTTP 2xx, it
  // doesn't mean the content is actually useful (e.g. an unauthenticated fetch of a login-gated
  // page can return 200 with a login form's HTML). Flags a few common login/auth-wall markers as
  // a hint, not a hard gate, so a silent "success" can still be sanity-checked from the log.
  function logFetchedContent(url, text, fromCache) {
    var preview = text.replace(/\s+/g, ' ').trim().slice(0, 150);
    var looksLikeLogin = /sign in|log in|authentication required|please log in|atlassian account|salesforce/i.test(text.slice(0, 2000));
    console.log('[Design Guardian] fetch-url ' + (fromCache ? 'cache hit' : 'fetched') + ' (' + text.length + ' chars' + (looksLikeLogin ? ', LOOKS LIKE LOGIN/AUTH PAGE' : '') + ') for ' + url + ': "' + preview + '..."');
  }

  // Fetch all URLs in parallel — each is independent.
  const fetchResults = await Promise.all(urls.map(async function(url) {
    const cached = _urlContentCache[url];
    if (cached && !cached.failed && now - cached.fetchedAt < _URL_CACHE_TTL) {
      logFetchedContent(url, cached.content, true);
      return { url, text: cached.content, failed: false };
    }
    if (cached && cached.failed && now - cached.fetchedAt < getFailureRetryDelayMs(cached.consecutiveFailures)) {
      console.log('[Design Guardian] fetch-url skipping known-failed URL (fail streak=' + cached.consecutiveFailures +
        ', retry in ' + Math.ceil((getFailureRetryDelayMs(cached.consecutiveFailures) - (now - cached.fetchedAt)) / 1000) + 's): ' + url);
      return { url, text: null, failed: true };
    }
    let fetched = await fetchUrlDirect(url);
    if (!fetched) fetched = await fetchUrlViaCli(url);
    if (fetched) {
      logFetchedContent(url, fetched, false);
      _urlContentCache[url] = { content: fetched, fetchedAt: now };
      return { url, text: fetched, failed: false };
    }
    var priorFailures = (cached && cached.failed) ? (cached.consecutiveFailures || 1) : 0;
    console.error('[Design Guardian] fetch-url all methods failed for: ' + url + ', fail streak=' + (priorFailures + 1));
    _urlContentCache[url] = { failed: true, fetchedAt: now, consecutiveFailures: priorFailures + 1 };
    return { url, text: null, failed: true };
  }));

  let result = content;
  const failedUrls = [];
  const fetchedUrls = [];
  for (var i = 0; i < fetchResults.length; i++) {
    var r = fetchResults[i];
    if (r.failed) {
      failedUrls.push(r.url);
    } else {
      fetchedUrls.push(r.url);
      result = result.replace(r.url, r.url + '\n[Content from ' + r.url + ']:\n---\n' + r.text + '\n---');
    }
  }
  return { content: result, failedUrls, fetchedUrls };
}

// ── AI provider router ────────────────────────────────────────────────────────
// Sends text content + guidelines to the configured AI provider.
// Returns array of { layerName, path, issue, suggestion } objects.
// callAiProvider: routes a prepared prompt to the configured AI provider (CLI subscription or
// direct API key). Shared by extraction, content-scan, and batch-scan so provider branching lives
// in exactly one place instead of being copy-pasted at every call site.
async function callAiProvider(cfg, model, userPart, systemPart, label, timeoutMs) {
  const fullPrompt = systemPart ? (systemPart + '\n\n' + userPart) : userPart;
  if (cfg.authMethod === 'cli') {
    return await runAiScanCLI(cfg.provider, model, fullPrompt, label, timeoutMs);
  }
  if (cfg.provider === 'anthropic') {
    return await runAiScanAnthropic(cfg.apiKey, model, userPart, systemPart, label);
  } else if (cfg.provider === 'openai') {
    return await runAiScanOpenAI(cfg.apiKey, model, fullPrompt, label);
  } else if (cfg.provider === 'google') {
    return await runAiScanGoogle(cfg.apiKey, model, fullPrompt, label);
  } else if (cfg.provider === 'ollama') {
    return await runAiScanOllama(cfg.ollamaEndpoint || 'http://localhost:11434', model, fullPrompt, label);
  }
  throw new Error('Unknown AI provider: ' + cfg.provider);
}

// extractGuidelineRules: reads the full guidelines doc ONCE per content version (sha256-hash-
// checked, cached to disk at GUIDELINES_EXTRACT_CACHE_FILE) to find two things a client can't get
// via regex alone: the component-name -> Confluence-page-ID table, and — for every OTHER (non-
// Confluence) link found in the doc's prose — which single named component that link's surrounding
// text is specifically about, if any (urlScopes). This used to ALSO ask the model to condense every
// rule into short verbatim excerpts ("general"/"byComponent") for the scan prompt — dropped that: it
// was a lossy summarization step (an LLM condensing the source document loses the surrounding
// reasoning, worked examples, and cross-references between rules that the full document has), it
// was also the single largest time cost in the whole pipeline, and Anthropic prompt caching already
// lets the full document be reused cheaply across calls without needing a separate AI call to
// shrink it. The two structures extracted here still need a model, though — a componentPages row is
// usually just a bare number next to a name, not a full URL, and "which component is this random
// link about" is a reading-comprehension question, neither is regex-matchable.
// Returns null (not throws) on any failure — callers fall back to no component-page lookups and no
// URL scoping (resolveGuidelinesUrls treats every unscoped URL as general, i.e. always fetched).
async function extractGuidelineRules(cfg, model, guidelines) {
  const hash = crypto.createHash('sha256').update(guidelines).digest('hex');
  try {
    const cached = JSON.parse(fs.readFileSync(GUIDELINES_EXTRACT_CACHE_FILE, 'utf8'));
    // urlScopes !== undefined guards against a cache file written before this field existed —
    // without it, a doc cached under the old shape would silently return with no urlScopes forever
    // (same hash, so it'd never naturally miss), and every generic URL would look "unscoped" (i.e.
    // general/always-fetch) even for links that are genuinely component-specific.
    if (cached && cached.hash === hash && cached.rules && cached.rules.urlScopes !== undefined) {
      console.log('[Design Guardian] guideline extraction cache hit (hash=' + hash.slice(0, 8) + ')');
      return cached.rules;
    }
  } catch (_) {}

  console.log('[Design Guardian] guideline extraction cache miss (hash=' + hash.slice(0, 8) + ') — running extraction pass');
  const genericUrls = extractUrls(guidelines).filter(function(u) { return !CONFLUENCE_URL_RE.test(u); });
  const prompt = [
    'You are indexing a UI content-guidelines document to find two specific pieces of structure in it.',
    '',
    '## Guidelines document',
    guidelines,
    '',
    '## Task 1: component -> Confluence page table',
    'Check whether the document contains a table or list mapping named UI components to Confluence page IDs or URLs (e.g. a "Component | Page ID" table, or a sentence like "the pattern is always https://host/wiki/spaces/SPACE/pages/<Page ID>"). Most rows in such a table are usually just a bare number, not a full URL — that is expected. If you find one:',
    '- Identify the hostname (e.g. "example.atlassian.net") from any full URL example shown anywhere in the document.',
    '- For EVERY component row in the table, however it is written (a full URL, or just a bare numeric ID next to a component name), record it as componentPages["ComponentName"] = { "cloudId": "<hostname>", "pageId": "<numeric id, digits only>" }.',
    '- Do not skip rows just because they are bare numbers rather than full links — that is the normal case, not the exception.',
    '- If the document has no such table, "componentPages" can be an empty object — do not invent structure that is not there.',
    '',
    '## Task 2: scope of other links',
    genericUrls.length
      ? [
          'Here are other (non-Confluence) URLs found in this document: ' + JSON.stringify(genericUrls),
          'For each one, look at the text around it. If that text is clearly and specifically about ONE named UI component (e.g. it only makes sense in a "Button" section, or says something like "for Card wording, see this article"), record urlScopes["<the exact URL as given above>"] = "<component name>".',
          'If a URL gives general guidance that is not tied to one specific component (e.g. overall voice/tone, a general writing-style reference, something referenced from multiple sections), do NOT add it to urlScopes at all — just omit it. Omitting a URL means "always relevant", so only add an entry when you are confident it is component-specific; guess "general" (omit) over guessing a component.',
        ].join('\n')
      : 'No non-Confluence URLs were found in this document, so urlScopes should be an empty object.',
    '',
    'Return ONLY a JSON array containing exactly one object: [{ "componentPages": { "Button": { "cloudId": "...", "pageId": "..." } }, "urlScopes": { "https://example.com/some-article": "Button" } }]',
    'Return only valid JSON, no explanation.',
  ].join('\n');

  try {
    const result = await callAiProvider(cfg, model, prompt, null, 'extract-guideline-rules', 480000);
    const obj = unwrapAiObject(result);
    const rules = (obj && typeof obj === 'object')
      ? {
          componentPages: (obj.componentPages && typeof obj.componentPages === 'object') ? obj.componentPages : {},
          urlScopes: (obj.urlScopes && typeof obj.urlScopes === 'object') ? obj.urlScopes : {},
        }
      : null;
    if (!rules) { console.error('[Design Guardian] guideline extraction returned unexpected shape'); return null; }
    try {
      fs.writeFileSync(GUIDELINES_EXTRACT_CACHE_FILE, JSON.stringify({ hash, extractedAt: Date.now(), rules }));
    } catch (writeErr) {
      console.error('[Design Guardian] failed to persist guideline extraction cache:', writeErr.message);
    }
    console.log('[Design Guardian] guideline extraction done: componentPages=' + Object.keys(rules.componentPages).length + ' urlScopes=' + Object.keys(rules.urlScopes).length);
    return rules;
  } catch (err) {
    console.error('[Design Guardian] guideline extraction failed:', err.message);
    return null;
  }
}

// detectComponentNames: every distinct component name present on any of these text nodes,
// confirmed or unconfirmed — used both for the Confluence-page fetch (fetchComponentPagesAppendix,
// confirmed-only) and for URL scoping (resolveGuidelinesUrls, via urlScopes) so a link tagged as
// belonging to a component that isn't part of THIS scan gets skipped.
function detectComponentNames(textNodes) {
  return Array.from(new Set(textNodes.filter(function(n) { return n.component; }).map(function(n) { return n.component; })));
}

// fetchComponentPagesAppendix: fetches each CONFIRMED component's real Confluence page and returns
// the text to append after the full guidelines document ('' if there's nothing to add). Deliberately
// takes no `fullGuidelines` param — it's a pure function of `extracted` + `textNodes`, which is what
// lets the caller run this in parallel with resolveGuidelinesUrls (generic URL resolution): the two
// fetch entirely different things (component pages vs. prose-embedded links) and neither result
// depends on the other, they just both depend on `extracted` (from extractGuidelineRules) being
// ready first. The full document alone never has these pages' actual content — components are just
// bare page-ID numbers in a table, not something the source text itself contains — so this ADDS to
// the full document rather than replacing any part of it with a distilled subset.
async function fetchComponentPagesAppendix(extracted, textNodes) {
  const componentNames = detectComponentNames(textNodes);
  console.log('[Design Guardian] components detected in this scan: ' + (componentNames.length ? componentNames.join(', ') : '(none)'));

  // Only a 'confirmed' match (component key found in the synced/approved library) gets its own
  // Confluence page fetched. 'unconfirmed' means a real Figma instance was found, but it isn't
  // verified against that library — it could be a lookalike, an old/local copy, or a genuinely
  // different component that happens to share a name. Fetching a specific page for it risks
  // splicing in guidance for the WRONG component; it still gets the general guidelines (already
  // tagged "(component: X, unconfirmed match)" in the scan prompt via componentTagFor), just no
  // page-specific appendix.
  const confirmedComponentNames = Array.from(new Set(
    textNodes.filter(function(n) { return n.component && n.componentConfidence === 'confirmed'; }).map(function(n) { return n.component; })
  ));
  const unconfirmedNames = componentNames.filter(function(n) { return confirmedComponentNames.indexOf(n) === -1; });
  if (unconfirmedNames.length) {
    console.log('[Design Guardian] skipping component-page fetch for unconfirmed match(es): ' + unconfirmedNames.join(', '));
  }
  if (!extracted || confirmedComponentNames.length === 0) return { text: '', fetchedUrls: [], failedUrls: [] };

  // Fire all per-component Confluence fetches in parallel — they're fully independent (different
  // pages, nothing shared but the cache object, which is a safe plain-object write under Node's
  // single-threaded event loop). Verified directly: awaiting them one at a time inside a for-loop
  // multiplied wait time by the number of distinct components in a scan (3 components ~30s each
  // sequentially = ~94s) instead of just waiting for the slowest one (~35s).
  const pageFetches = confirmedComponentNames.map(function(name) {
    var pageRef = extracted.componentPages && extracted.componentPages[name];
    if (pageRef && pageRef.cloudId && pageRef.pageId) {
      console.log('[Design Guardian] "' + name + '" matched componentPages -> ' + pageRef.cloudId + '/' + pageRef.pageId + ', fetching...');
      return fetchConfluencePage(pageRef.cloudId, pageRef.pageId).then(function(content) {
        return { name: name, content: content };
      });
    }
    console.log('[Design Guardian] "' + name + '" has no entry in componentPages — no page to fetch');
    return Promise.resolve({ name: name, content: null });
  });
  const pageResults = await Promise.all(pageFetches);

  const appendix = [];
  // Report the component pages this scan actually fetched (and the ones that failed) so the
  // plugin's "External sources in guidelines" card can show them alongside the generic URLs.
  // Before, only resolveGuidelinesUrls's generic links were reported — so a scan whose only
  // successful fetches were Confluence component pages showed nothing under "passed," and a failed
  // component page (e.g. Card) never surfaced at all. Reconstruct a Confluence page URL per entry
  // so it renders consistently with the generic ones. A pageRef-less entry ("no page to fetch")
  // isn't a fetch at all, so it counts as neither passed nor failed.
  const fetchedUrls = [];
  const failedUrls = [];
  pageResults.forEach(function(r) {
    var pageRef = extracted.componentPages[r.name];
    if (!pageRef || !pageRef.cloudId || !pageRef.pageId) return;
    var pageUrl = 'https://' + pageRef.cloudId + '/wiki/pages/' + pageRef.pageId;
    if (r.content) {
      appendix.push('', 'Full guideline page for "' + r.name + '" (' + pageRef.cloudId + '/' + pageRef.pageId + '):', r.content);
      fetchedUrls.push(pageUrl);
    } else {
      failedUrls.push(pageUrl);
    }
  });
  return { text: appendix.length ? appendix.join('\n') : '', fetchedUrls: fetchedUrls, failedUrls: failedUrls };
}

// componentTagFor: builds the "(component: X)"/"(component: X, unconfirmed match)" suffix for one
// text line — 'unconfirmed' means the plugin found a real component instance but it isn't in the
// user's synced/approved library, so its rules should be applied a bit more cautiously.
function componentTagFor(n) {
  if (!n.component) return '';
  return ' (component: ' + n.component + (n.componentConfidence === 'unconfirmed' ? ', unconfirmed match' : '') + ')';
}

// checkCompletenessAndRetry: a node with zero issues and a silently-skipped node look identical
// unless the model also reports which refs it actually examined (reviewedRefs). This diffs the
// full ref list against what came back, retries EXACTLY ONCE with just the missing nodes (a retry
// is not a guarantee — it's the same non-deterministic model, just given another chance — so this
// is capped, not looped), and for anything still missing after that, synthesizes a normal,
// low-severity "review incomplete" issue scoped to that one node instead of silently dropping it
// or showing a separate banner that would cast doubt on the rest of the scan.
// retryPass(missingNodes) must return { issues, reviewedRefs } for just those nodes.
// collectReviewedRefs: a ref explicitly listed in "reviewedRefs" is one signal that it was
// examined, but not the only one — a ref that has an issue reported against it is DIRECT proof
// it was examined, independent of whether the model also remembered to list it in reviewedRefs.
// Verified directly this matters: in production, "issues" has come back fully populated while
// "reviewedRefs" came back completely empty in the same response — treating that as "252 of 252
// skipped" was wrong when most of those 252 clearly WERE looked at (they have issues to prove it).
// Only a ref with neither an issue NOR a reviewedRefs entry is genuinely ambiguous (reviewed-and-
// clean vs. silently-skipped look identical) — this narrows retries/synthetic issues to only that
// truly ambiguous set instead of everything the model forgot to enumerate.
// unwrapAiObject: every single-object prompt asks for "a JSON array containing exactly one
// object" ([{...}]), but models intermittently drop the array wrapper and return the bare
// object ({...}) — same data, one missing bracket. Verified directly (July 7 2026 log): a
// content scan of 48 nodes returned a complete, valid bare object TWICE (first pass and
// retry), and the old inline `Array.isArray(result) ? result[0] : null` discarded both paid
// responses, tagging all 48 layers "manual review". The retry can never save this case — it
// resends the identical prompt to the identical model, which repeats the identical format
// quirk. Accept both shapes instead: the content is what matters, not the wrapper.
function unwrapAiObject(result) {
  if (Array.isArray(result)) return (result[0] && typeof result[0] === 'object') ? result[0] : null;
  return (result && typeof result === 'object') ? result : null;
}

function collectReviewedRefs(pass) {
  var reviewed = new Set();
  // Coerce to Number here too, symmetric with the issues loop below — allRefs (from the client) are
  // always plain numbers, so a model that returns reviewedRefs as numeric strings (e.g. ["0","1"])
  // would otherwise silently fail every Set.has() lookup, producing a false "100% missing" that
  // looks identical to the exact failure mode this whole mechanism exists to catch.
  (Array.isArray(pass.reviewedRefs) ? pass.reviewedRefs : []).forEach(function(ref) {
    var r = Number(ref);
    if (Number.isFinite(r)) reviewed.add(r);
  });
  (pass.issues || []).forEach(function(iss) {
    var r = iss && Number(iss.ref);
    if (Number.isFinite(r)) reviewed.add(r);
  });
  return reviewed;
}

async function checkCompletenessAndRetry(allNodesWithRef, firstPass, retryPass, label) {
  var allRefs = allNodesWithRef.map(function(n) { return n.ref; });
  var reviewed = collectReviewedRefs(firstPass);
  var missingRefs = allRefs.filter(function(ref) { return !reviewed.has(ref); });
  if (missingRefs.length === 0) return firstPass.issues;

  console.warn('[Design Guardian] ' + label + ': ' + missingRefs.length + ' of ' + allRefs.length + ' refs missing from reviewedRefs, retrying just those: ' + missingRefs.join(','));
  var missingNodes = allNodesWithRef.filter(function(n) { return missingRefs.indexOf(n.ref) !== -1; });
  var retryResult = await retryPass(missingNodes);
  var reviewedAfterRetry = collectReviewedRefs(retryResult);
  var stillMissing = missingRefs.filter(function(ref) { return !reviewedAfterRetry.has(ref); });
  var combined = firstPass.issues.concat(retryResult.issues);
  if (stillMissing.length > 0) {
    console.warn('[Design Guardian] ' + label + ': ' + stillMissing.length + ' refs still missing after retry, adding manual-review issues: ' + stillMissing.join(','));
    stillMissing.forEach(function(ref) {
      var node = allNodesWithRef.filter(function(n) { return n.ref === ref; })[0];
      combined.push({
        ref: ref,
        frameName: node ? node.frameName : undefined,
        layerPath: node ? node.path : '',
        characters: node ? node.characters : '',
        issue: 'Automated content review could not process this layer after 2 attempts.',
        suggestion: 'Review this layer\'s copy manually against the content guidelines.',
        rule: 'Review incomplete',
        severity: 'suggestion',
      });
    });
  }
  return combined;
}

// verifyGuidelineQuotes: mechanically checks whether each issue's "guidelineQuote" is a real,
// verbatim excerpt from the guidelines text actually sent to the model — a plain substring check,
// no AI call needed. The prompt already tells the model never to invent or paraphrase a citation,
// but that's a request, not a guarantee. Doesn't drop a failing issue — the underlying finding may
// still be real, just mis-cited — it marks it (citationVerified) so that's visible instead of the
// citation being trusted blindly. Whitespace is normalized on both sides so a quote that merely
// spans a line break in the source document doesn't fail on a technicality.
// normalizeForCitationCheck: folds away the COSMETIC differences that make a genuine citation fail
// an exact-substring check, so verification tracks meaning, not punctuation. Applied to both sides.
// Verified directly, twice, on the same rule:
//   1. Source had "**Ampersands:**", model quoted "Ampersands:" — markdown asterisks. (fixed first)
//   2. Source had  Use "and" instead.  (double quotes), model quoted  Use 'and' instead.  (single) —
//      the model re-punctuated the quote, so a straight substring miss flagged a real citation as
//      "unverified" (the persistent "ampersand hallucination"). So we now also fold ALL quote
//      characters (straight/curly, single/double, backtick) to nothing and normalize dash variants
//      (en/em → hyphen), which is the same class of cosmetic drift.
// This only ever makes matching MORE lenient about punctuation — it can't turn a genuinely different
// quote into a false match, because the words themselves still have to line up.
function normalizeForCitationCheck(text) {
  return String(text)
    .replace(/\*+/g, '')                 // markdown emphasis
    .replace(/[‘’“”"'`]/g, '') // all quote chars (curly + straight, single + double, backtick)
    .replace(/[–—]/g, '-')      // en/em dash → hyphen
    .replace(/\s+/g, ' ')                 // collapse whitespace (incl. line breaks)
    .trim();
}

// resolveActualSourceFile: deterministically finds which individual guidelines file (or the
// manually-pasted text) a verified quote really came from, instead of trusting the model's own
// "source_file" guess. Verified directly: the model attributed an Ampersand rule to
// "content-rules.md" when it actually lives in "style-guide.md" — content-rules.md's own text
// explicitly tells the reader to check style-guide.md's glossary for exactly this kind of rule, so
// the model likely picked the file that introduces the CONCEPT rather than the file the exact
// quoted text is really in. This is a plain substring search per file — same normalization as the
// citation check itself — so it's exact, not another guess.
function resolveActualSourceFile(normalizedQuote, guidelinesFiles, guidelinesManual) {
  for (var i = 0; i < (guidelinesFiles || []).length; i++) {
    var f = guidelinesFiles[i];
    if (f && f.enabled !== false && f.content && normalizeForCitationCheck(f.content).indexOf(normalizedQuote) !== -1) {
      return f.name;
    }
  }
  if (guidelinesManual && normalizeForCitationCheck(guidelinesManual).indexOf(normalizedQuote) !== -1) {
    return 'Manual';
  }
  return null;
}

function verifyGuidelineQuotes(issues, guidelinesText, label, guidelinesFiles, guidelinesManual) {
  var normalizedGuidelines = normalizeForCitationCheck(guidelinesText);
  var flaggedCount = 0;
  var correctedCount = 0;
  issues.forEach(function(issue) {
    // Skip checkCompletenessAndRetry's own synthesized "could not process this layer" issues —
    // they never had a real citation to begin with (that's the point of them), so this isn't a
    // trust signal to compute or show for them.
    if (issue.rule === 'Review incomplete') return;
    var quote = issue.guidelineQuote ? normalizeForCitationCheck(issue.guidelineQuote) : '';
    issue.citationVerified = !!quote && normalizedGuidelines.indexOf(quote) !== -1;
    if (!issue.citationVerified) {
      flaggedCount++;
      console.warn('[Design Guardian] ' + label + ': unverified citation on issue (ref ' + issue.ref + '): "' + String(issue.guidelineQuote || '(none)').slice(0, 120) + '"');
      return;
    }
    // Only correct source_file for a citation we've actually verified exists — no point guessing
    // a "real" file for a quote that isn't real to begin with.
    var actualFile = resolveActualSourceFile(quote, guidelinesFiles, guidelinesManual);
    if (actualFile && actualFile !== issue.source_file) {
      if (issue.source_file) {
        correctedCount++;
        console.warn('[Design Guardian] ' + label + ': source_file corrected on issue (ref ' + issue.ref + '): model said "' + issue.source_file + '", actually in "' + actualFile + '"');
      }
      issue.source_file = actualFile;
    }
  });
  if (flaggedCount > 0) {
    console.warn('[Design Guardian] ' + label + ': ' + flaggedCount + ' of ' + issues.length + ' issues had an unverifiable guideline citation');
  }
  if (correctedCount > 0) {
    console.warn('[Design Guardian] ' + label + ': ' + correctedCount + ' issue(s) had their source_file corrected to the file the citation actually appears in');
  }
  return issues;
}

// `guidelines` here is already the fully-assembled document — resolved URLs spliced in AND
// component-page appendix attached — built by the caller (see /ai/scan) so that those two fetches
// can run in parallel with each other instead of one waiting on the other's output.
async function runAiContentScan(cfg, model, guidelines, textNodes, guidelinesFiles, guidelinesManual) {
  const relevantGuidelines = guidelines;
  // Each node gets a short integer ref so Claude echoes a trivially-copyable handle instead of
  // transcribing a 60-char instance-sublayer ID. Plugin maps ref -> real node. Normally already
  // set by ui.html before this ever reaches the server; only defaulted here as a safety net.
  // Then remap every node to a LOCAL 0-based ref for the model. Verified directly from logs: a
  // sub-batch whose refs were offset (50-97) had the model silently renumber them from 0 in its
  // reviewedRefs/issues — so every ref came back "missing" — while the sibling sub-batch with refs
  // 0-49 in the SAME scan parsed fine and matched. This is a DIFFERENT failure from the JSON-parse
  // one (no parse error occurred): a small model reliably echoes [ref:0..N] but not an offset base.
  // Local 0-based refs put every call in the regime that works; localToOriginal translates the
  // model's answers back to the client-facing ref before returning, so ui.html's ref->nodeId map
  // (which is keyed on the original global refs) is unaffected.
  var localToOriginal = {};
  textNodes.forEach(function(n, i) {
    var clientRef = (n.ref === 0 || n.ref) ? n.ref : i;
    localToOriginal[i] = clientRef;
    n.ref = i;
  });

  const persona = (cfg.persona || '').trim() || DEFAULT_AI_PERSONA;

  function buildPrompt(nodes) {
    const textSummary = nodes
      .map(function(n) { return '- [ref:' + n.ref + ']' + componentTagFor(n) + ' [' + n.path + '] ' + JSON.stringify(n.characters); })
      .join('\n');

    // systemPart: persona + full guidelines document, with any matched component pages appended
    // (cacheable; identical across all parallel frame scans)
    const systemPart = [
      persona,
      '',
      '## Content Guidelines',
      relevantGuidelines,
    ].join('\n');

    // userPart: per-frame content + output instructions (changes each call)
    const userPart = [
      '## Text Content from Design (format: [ref:N] (component: Name, if any) [layer path] "text")',
      'When a layer is tagged with a component name, check it against both the general rules and that component\'s specific rules above, if any exist. "unconfirmed match" means the component is not from your synced/approved library — still apply its rules, just weigh a genuinely ambiguous case toward not flagging it.',
      textSummary,
      '',
      'Return ONLY a JSON array containing exactly one object: [{ "reviewedRefs": [...], "issues": [...] }]',
      'Write "reviewedRefs" FIRST, before "issues" — commit to the full list up front rather than getting to it last, after already spending your output on every issue. It is a flat array of integers: every single [ref:N] number from the list above that you examined, WHETHER OR NOT it had an issue. Every ref must appear exactly once, in any order — this costs nothing extra for a clean layer (just the number) and is the only way we can tell "reviewed, no issues" apart from "silently skipped". With ' + nodes.length + ' layers in this batch, "reviewedRefs" must have exactly ' + nodes.length + ' entries — do not stop partway through the list.',
      '"issues" is an array where each issue must have:',
      '- "ref": copy the exact integer from [ref:N] for the layer with the issue (e.g. 7). Just the number.',
      '- "layerPath": the layer path from the list above',
      '- "characters": copy the full text string for that layer exactly as it appears in the input above, character for character',
      '- "issue": ONE sentence, max 24 words. State only the violation. No conjunctions, no "also", no extra context.',
      '- "suggestion": ONE sentence, max 24 words. Give the fix or an example replacement. REQUIRED for every issue except when you are using "suggestionOptions" instead (see below) — even if "context"/"find"/"replace" already show the mechanical fix, still write "suggestion" in plain words; do not skip it just because the fix is obvious or already implied elsewhere. Never provide both "suggestion" and "suggestionOptions" on the same issue.',
      '- "suggestionOptions": ONLY use this instead of "suggestion" when there are 2 genuinely reasonable, meaningfully different fixes and you cannot confidently pick one over the other (e.g. a more formal rewrite vs. a more conversational one that both equally satisfy the rule). This is the exception, not the default — most issues have one clear fix, so use "suggestion" unless you are genuinely torn. When you do use it, provide exactly 2 objects: [{ "label": "Option A", "text": "..." }, { "label": "Option B", "text": "..." }]. Omit "context"/"find"/"replace" entirely in this case — there is no single unambiguous string to auto-apply when 2 different answers are both valid.',
      '- "rule": 2-4 words naming the specific guideline violated. Examples: "Sentence case", "Banned term", "CTA specificity", "Second person", "Oxford comma".',
      '- "guidelineQuote": the EXACT excerpt from the Content Guidelines section above (character-for-character, copy-paste, not summarized) that this specific issue violates. If you cannot quote a real excerpt that actually supports this issue, do NOT report the issue at all — do not invent or paraphrase a citation.',
      '- "source_file": the name from the "--- Name ---" section header where this guideline is defined (e.g. "Brand Voice Guide.md"). Omit if the rule comes from multiple files or the source is unclear.',
      '- "severity": "error" (clear rule violation) | "warning" (judgment call) | "suggestion" (optional improvement).',
      '- "context": a short snippet (roughly 5-10 words) copied verbatim from "characters" that surrounds the flagged word or phrase. Must be an exact substring of "characters". If this same problem occurs more than once in this layer, create a SEPARATE issue object per occurrence, and give each one a "context" snippet with enough surrounding words that it uniquely identifies that one occurrence (it must not also match the other occurrence).',
      '- "find": the exact word or phrase inside "context" that is wrong. Must be an exact substring of "context".',
      '- "replace": the corrected replacement for "find" ONLY, not the rest of the sentence. Omit "context"/"find"/"replace" entirely if there is no clean, isolated fix (e.g. the whole sentence needs rewriting, or you used "suggestionOptions").',
      '',
      'Bad example: "All-caps violates sentence case. \'Action\' is flagged in the glossary and the accessibility guideline warns against generic copy."',
      'Good example issue: "All-caps violates sentence case requirement."',
      'Good example suggestion: "Use sentence case: \'Get started\'."',
      'Good example rule: "Sentence case"',
      'Good example, single occurrence: characters is "Please ACTION this request." -> context: "Please ACTION this request", find: "ACTION", replace: "action".',
      'Good example, repeated occurrence: characters is "Click here to continue. Click here for details." and both "Click here" instances violate the same rule -> return two issues: issue A has context "Click here to continue", find "Click here", replace "Continue"; issue B has context "Click here for details", find "Click here", replace "See details".',
      'Good example, genuine judgment call: characters is "That\'s everything I need. Confirm the scope to generate the rule." and "everything" is a banned term with no single obvious replacement -> suggestionOptions: [{ "label": "Option A", "text": "I have what I need. Confirm the scope to generate the rule." }, { "label": "Option B", "text": "I have all the details I need. Confirm the scope to generate the rule." }] (no "suggestion", no "context"/"find"/"replace").',
      '',
      'If a layer has no issues, do not add it to "issues" — but its ref must still appear in "reviewedRefs". Return only valid JSON, no explanation.',
    ].join('\n');

    return { userPart, systemPart };
  }

  async function runPass(nodes) {
    var built = buildPrompt(nodes);
    var result = await callAiProvider(cfg, model, built.userPart, built.systemPart, 'content-scan');
    var obj = unwrapAiObject(result);
    return {
      issues: (obj && Array.isArray(obj.issues)) ? obj.issues : [],
      reviewedRefs: (obj && Array.isArray(obj.reviewedRefs)) ? obj.reviewedRefs : [],
    };
  }

  const firstPass = await runPass(textNodes);
  const finalIssues = await checkCompletenessAndRetry(textNodes, firstPass, runPass, 'content-scan');
  // Translate local refs (what the model saw and echoed) back to the client-facing refs.
  finalIssues.forEach(function(iss) {
    if (!iss) return;
    var lr = Number(iss.ref);
    if (Number.isFinite(lr) && localToOriginal.hasOwnProperty(lr)) iss.ref = localToOriginal[lr];
  });
  return verifyGuidelineQuotes(finalIssues, relevantGuidelines, 'content-scan', guidelinesFiles, guidelinesManual);
}

// runAiContentScanBatch: evaluates 2-3 frames in a single call to amortise the guidelines
// cache_miss across all frames instead of paying it once per concurrent call.

// `guidelines` here is already the fully-assembled document — see runAiContentScan's comment.
async function runAiContentScanBatch(cfg, model, guidelines, frames, guidelinesFiles, guidelinesManual) {
  const allTextNodes = frames.reduce(function(acc, f) {
    return acc.concat((f.textNodes || []).map(function(n, i) {
      if (n.ref !== 0 && !n.ref) n.ref = i; // safety net; ui.html normally already sets this
      n.frameName = f.frameName;
      return n;
    }));
  }, []);
  // Remap to LOCAL 0-based refs across the combined frame set — see runAiContentScan for why
  // (offset refs make the model renumber and every ref reads as "missing"). Translated back before
  // return so ui.html's ref->nodeId map (keyed on the original refs) still resolves.
  var localToOriginal = {};
  allTextNodes.forEach(function(n, i) {
    var clientRef = (n.ref === 0 || n.ref) ? n.ref : i;
    localToOriginal[i] = clientRef;
    n.ref = i;
  });
  const relevantGuidelines = guidelines;

  const persona = (cfg.persona || '').trim() || DEFAULT_AI_PERSONA;

  function buildFramesText(nodes) {
    var byFrame = {};
    var order = [];
    nodes.forEach(function(n) {
      if (!byFrame[n.frameName]) { byFrame[n.frameName] = []; order.push(n.frameName); }
      byFrame[n.frameName].push(n);
    });
    return order.map(function(frameName) {
      var textSummary = byFrame[frameName]
        .map(function(n) { return '  - [ref:' + n.ref + ']' + componentTagFor(n) + ' [' + n.path + '] ' + JSON.stringify(n.characters); })
        .join('\n');
      return '### Frame: "' + frameName + '"\n' + textSummary;
    }).join('\n\n');
  }

  function buildPrompt(nodes) {
    const systemPart = [
      persona,
      '',
      '## Content Guidelines',
      relevantGuidelines,
    ].join('\n');

    const userPart = [
      '## Text Content from Design (format: [ref:N] (component: Name, if any) [layer path] "text")',
      'When a layer is tagged with a component name, check it against both the general rules and that component\'s specific rules above, if any exist. "unconfirmed match" means the component is not from your synced/approved library — still apply its rules, just weigh a genuinely ambiguous case toward not flagging it.',
      '',
      buildFramesText(nodes),
      '',
      'Return ONLY a JSON array containing exactly one object: [{ "reviewedRefs": [...], "issues": [...] }]',
      'Write "reviewedRefs" FIRST, before "issues" — commit to the full list up front rather than getting to it last, after already spending your output on every issue. It is a flat array of integers: every single [ref:N] number from the list above that you examined, WHETHER OR NOT it had an issue. Every ref must appear exactly once, in any order — this costs nothing extra for a clean layer (just the number) and is the only way we can tell "reviewed, no issues" apart from "silently skipped". With ' + nodes.length + ' layers in this batch, "reviewedRefs" must have exactly ' + nodes.length + ' entries — do not stop partway through the list.',
      '"issues" is an array where each issue must have:',
      '- "ref": copy the exact integer from [ref:N] for the layer with the issue (e.g. 7). Just the number.',
      '- "frameName": exactly as shown in the ### Frame header above',
      '- "layerPath": the full layer path from the list above',
      '- "characters": copy the full text string for that layer exactly as it appears in the input',
      '- "issue": ONE sentence, max 24 words. State only the violation.',
      '- "suggestion": ONE sentence, max 24 words. Give the fix or an example replacement. REQUIRED for every issue except when you are using "suggestionOptions" instead (see below) — even if "context"/"find"/"replace" already show the mechanical fix, still write "suggestion" in plain words; do not skip it just because the fix is obvious or already implied elsewhere. Never provide both "suggestion" and "suggestionOptions" on the same issue.',
      '- "suggestionOptions": ONLY use this instead of "suggestion" when there are 2 genuinely reasonable, meaningfully different fixes and you cannot confidently pick one over the other. This is the exception, not the default. When used, provide exactly 2 objects: [{ "label": "Option A", "text": "..." }, { "label": "Option B", "text": "..." }], and omit "context"/"find"/"replace" entirely — there is no single unambiguous string to auto-apply when 2 different answers are both valid.',
      '- "rule": 2-4 words naming the specific guideline violated.',
      '- "guidelineQuote": the EXACT excerpt from the Content Guidelines section above (character-for-character, copy-paste, not summarized) that this specific issue violates. If you cannot quote a real excerpt that actually supports this issue, do NOT report the issue at all.',
      '- "source_file": the name from the "--- Name ---" section header where this guideline is defined. Omit if the rule comes from multiple files or is unclear.',
      '- "severity": "error" | "warning" | "suggestion"',
      '- "context": a short snippet (roughly 5-10 words) copied verbatim from "characters" that surrounds the flagged word or phrase. Must be an exact substring of "characters". If this same problem occurs more than once in this layer, create a SEPARATE issue object per occurrence, with a "context" snippet unique to that occurrence (must not also match the other occurrence).',
      '- "find": the exact word or phrase inside "context" that is wrong. Must be an exact substring of "context".',
      '- "replace": the corrected replacement for "find" ONLY, not the rest of the sentence. Omit "context"/"find"/"replace" entirely if there is no clean, isolated fix, or you used "suggestionOptions".',
      '',
      'If a layer has no issues, do not add it to "issues" — but its ref must still appear in "reviewedRefs". Return only valid JSON, no explanation.',
    ].join('\n');

    return { userPart, systemPart };
  }

  async function runPass(nodes) {
    var built = buildPrompt(nodes);
    var label = 'content-scan-batch (' + frames.length + ' frames)';
    var result = await callAiProvider(cfg, model, built.userPart, built.systemPart, label);
    var obj = unwrapAiObject(result);
    return {
      issues: (obj && Array.isArray(obj.issues)) ? obj.issues : [],
      reviewedRefs: (obj && Array.isArray(obj.reviewedRefs)) ? obj.reviewedRefs : [],
    };
  }

  const firstPass = await runPass(allTextNodes);
  const finalIssues = await checkCompletenessAndRetry(allTextNodes, firstPass, runPass, 'content-scan-batch');
  // Translate local refs back to the client-facing refs — see runAiContentScan.
  finalIssues.forEach(function(iss) {
    if (!iss) return;
    var lr = Number(iss.ref);
    if (Number.isFinite(lr) && localToOriginal.hasOwnProperty(lr)) iss.ref = localToOriginal[lr];
  });
  return verifyGuidelineQuotes(finalIssues, relevantGuidelines, 'content-scan-batch', guidelinesFiles, guidelinesManual);
}

// runAiNormalizationPass: takes raw AI issues from parallel frame scans and normalizes rule names
// and severity for consistency. Only modifies 'rule' and 'severity' — all other fields are preserved.
async function runAiNormalizationPass(cfg, model, issues) {
  const rulesInput = issues.map(function(iss, i) {
    return i + '|' + JSON.stringify(iss.rule || 'General') + '|' + (iss.severity || 'warning');
  }).join('\n');

  const prompt = [
    'You are a content review editor. Issues below were found across multiple Figma frames reviewed in parallel.',
    'Because frames were reviewed independently, the same type of violation may have inconsistent rule names or severity.',
    '',
    '## Your task',
    'Return a JSON array normalizing ONLY the `rule` and `severity` fields:',
    '- Merge synonymous rule names into one consistent name (e.g. "Sentence case violation" and "sentence case" → "Sentence case")',
    '- Use sentence case for all rule names (capitalize first word only, no trailing period)',
    '- Make severity consistent per rule type: "error" = clear rule violation, "warning" = judgment call, "suggestion" = optional',
    '',
    '## Issues (format: index|rule|severity)',
    rulesInput,
    '',
    'Return ONLY a JSON array of { "index": N, "rule": "Normalized rule", "severity": "normalized" }.',
    'One entry per line of input, in the same order. Return only valid JSON, no explanation.',
  ].join('\n');

  let rawResult;
  if (cfg.authMethod === 'cli') {
    rawResult = await runAiScanCLI(cfg.provider, model, prompt, 'normalize');
  } else if (cfg.provider === 'anthropic') {
    rawResult = await runAiScanAnthropic(cfg.apiKey, model, prompt, null, 'normalize');
  } else if (cfg.provider === 'openai') {
    rawResult = await runAiScanOpenAI(cfg.apiKey, model, prompt, 'normalize');
  } else if (cfg.provider === 'google') {
    rawResult = await runAiScanGoogle(cfg.apiKey, model, prompt, 'normalize');
  } else if (cfg.provider === 'ollama') {
    rawResult = await runAiScanOllama(cfg.ollamaEndpoint || 'http://localhost:11434', model, prompt, 'normalize');
  } else {
    return issues;
  }

  if (!Array.isArray(rawResult) || rawResult.length === 0) return issues;
  // Build an index map from the AI response so position reordering can't mis-assign fields.
  const normByIndex = {};
  rawResult.forEach(function(norm) {
    if (norm && typeof norm.index === 'number') normByIndex[norm.index] = norm;
  });
  // Merge normalized rule/severity back; preserve all other fields from original issues.
  return issues.map(function(orig, i) {
    const norm = normByIndex[i];
    return Object.assign({}, orig, {
      rule: (norm && typeof norm.rule === 'string' && norm.rule.trim()) ? norm.rule.trim() : orig.rule,
      severity: (norm && (norm.severity === 'error' || norm.severity === 'warning' || norm.severity === 'suggestion')) ? norm.severity : orig.severity,
    });
  });
}

// runAiGuidelinesEvaluation: sends guidelines content to the AI with a meta-prompt and returns quality issues.
// Returns array of { severity, category, message, suggestion } objects.
async function runAiGuidelinesEvaluation(cfg, model, content) {
  const prompt = [
    'You are a content design expert evaluating a guidelines document that will be used by an AI to review UI copy in Figma designs.',
    '',
    '## Guidelines content',
    content,
    '',
    '## Your task',
    'Evaluate this document for quality issues that would make AI enforcement unreliable. Return a JSON array of issues.',
    'Each issue must have:',
    '- "severity": "error" (AI cannot apply this rule reliably) | "warning" (may produce inconsistent results) | "suggestion" (optional improvement)',
    '- "category": 2-4 word label. Examples: "Vague rule", "Missing example", "Contradiction", "Reference not instruction", "Missing category".',
    '- "message": ONE sentence, max 24 words. State the specific problem clearly.',
    '- "suggestion": ONE sentence, max 24 words. Give actionable advice to fix it.',
    '',
    'Check for:',
    '0. Wrong file type — if the content is not UI copy guidelines at all (e.g. a workflow, code review skill, scheduling task, or technical spec), return a SINGLE error with category "Wrong file type" and message "This file does not appear to contain UI copy guidelines." Do not check anything else.',
    '1. Rules too vague to enforce — e.g., "write clearly" with no measurable criteria',
    '2. Rules without examples — especially for terminology, casing, or tone',
    '3. Contradicting rules — one rule says X, another says the opposite',
    '4. Reference-style content — documents what exists instead of instructing what to flag',
    '5. Missing major UI copy categories that are typically needed: tone, sentence case, CTAs/buttons, error messages, placeholder text, banned terms',
    '',
    'Only flag real issues. If a rule is clear and enforceable, do not flag it.',
    'If the guidelines are high quality, return only 0-2 minor suggestions or an empty array.',
    'Return ONLY a JSON array. Return [] if no issues. No explanation.',
  ].join('\n');

  const label = 'eval-guidelines (' + content.split('\n').length + ' lines)';
  if (cfg.authMethod === 'cli') {
    return await runAiScanCLI(cfg.provider, model, prompt, label);
  } else if (cfg.provider === 'anthropic') {
    return await runAiScanAnthropic(cfg.apiKey, model, prompt, null, label);
  } else if (cfg.provider === 'openai') {
    return await runAiScanOpenAI(cfg.apiKey, model, prompt, label);
  } else if (cfg.provider === 'google') {
    return await runAiScanGoogle(cfg.apiKey, model, prompt, label);
  } else if (cfg.provider === 'ollama') {
    return await runAiScanOllama(cfg.ollamaEndpoint || 'http://localhost:11434', model, prompt, label);
  }
  throw new Error('Unknown AI provider: ' + cfg.provider);
}

// runAiGuidelinesEvaluationBatch: evaluates multiple guidelines files in a single AI call.
// Returns an array of { name, issues } — one entry per file, in input order.
async function runAiGuidelinesEvaluationBatch(cfg, model, files) {
  const filesSections = files.map(function(f) {
    return '## File: ' + JSON.stringify(f.name) + '\n' + f.content;
  }).join('\n\n---\n\n');

  const prompt = [
    'You are a content design expert evaluating guidelines documents that will be used by an AI to review UI copy in Figma designs.',
    '',
    'Below are ' + files.length + ' guidelines file' + (files.length !== 1 ? 's' : '') + '. Evaluate each file independently.',
    '',
    filesSections,
    '',
    '## Your task',
    'For each file, check for quality issues that would make AI enforcement unreliable:',
    '0. Wrong file type — if the content is not UI copy guidelines (e.g. a workflow, code spec), return a SINGLE error with category "Wrong file type" and message "This file does not appear to contain UI copy guidelines." Do not check anything else.',
    '1. Rules too vague to enforce — e.g., "write clearly" with no measurable criteria',
    '2. Rules without examples — especially for terminology, casing, or tone',
    '3. Contradicting rules — one rule says X, another says the opposite',
    '4. Reference-style content — documents what exists instead of instructing what to flag',
    '5. Missing major UI copy categories: tone, sentence case, CTAs/buttons, error messages, placeholder text, banned terms',
    '',
    'Only flag real issues. If a rule is clear and enforceable, do not flag it.',
    'Each issue: { "severity": "error"|"warning"|"suggestion", "category": "2-4 words", "message": "max 24 words", "suggestion": "max 24 words" }',
    '',
    'Return ONLY a JSON array with one entry per file, in the same order as the input:',
    '[{ "name": "<exact filename as shown in ## File header>", "issues": [...] }]',
    'Use "issues": [] for a file with no problems. Return only valid JSON, no explanation.',
  ].join('\n');

  const label = 'eval-guidelines-batch (' + files.length + ' files)';
  if (cfg.authMethod === 'cli') {
    return await runAiScanCLI(cfg.provider, model, prompt, label);
  } else if (cfg.provider === 'anthropic') {
    return await runAiScanAnthropic(cfg.apiKey, model, prompt, null, label);
  } else if (cfg.provider === 'openai') {
    return await runAiScanOpenAI(cfg.apiKey, model, prompt, label);
  } else if (cfg.provider === 'google') {
    return await runAiScanGoogle(cfg.apiKey, model, prompt, label);
  } else if (cfg.provider === 'ollama') {
    return await runAiScanOllama(cfg.ollamaEndpoint || 'http://localhost:11434', model, prompt, label);
  }
  throw new Error('Unknown AI provider: ' + cfg.provider);
}

// parseAiJsonResponse: tries several increasingly-careful extraction strategies before giving up.
// Used to be a single naive "first '[' to last ']'" match with no fallback — verified directly that
// a real, substantial response (16,425 output tokens) can fail that exact match and silently come
// back as [], indistinguishable from "the model found nothing" (see checkCompletenessAndRetry's
// reviewedRefs saga — a chunk of that cost was almost certainly paying to re-run a batch whose first
// response was actually fine, just not parsed). Re-attempting extraction on text we ALREADY HAVE is
// free; a retry is a whole new paid AI call — so this is worth trying hard before ever falling back
// to that. Strategies, in order:
//   1. A markdown code fence (```json ... ```), in case the model wrapped the array in one.
//   2. The whole trimmed response, in case it's already clean JSON with nothing around it.
//   3. Greedy match: first '[' to the LAST ']' in the whole text (the original, only strategy).
//   4. Walk forward from the first '[' through EVERY subsequent ']', shortest first, and try
//      parsing up to each one — recovers the common case where trailing commentary after the real
//      JSON end ("Let me know if you need anything else!") happens to contain its own ']' and makes
//      strategy 3 overshoot past the actual end.
// Only returns [] (and logs a preview) if every single one of these fails.
// repairUnescapedQuotes: the likely cause behind failures where the model believes it finished
// normally (stop_reason=end_turn) yet the JSON won't parse — it's asked to copy layer text
// verbatim into a string value ("characters": copy... character for character), and real Figma
// text often contains literal quote characters (e.g. Enable "Advanced Mode" now) that the model
// doesn't escape. That embedded quote looks like it closes the string early, corrupting everything
// after it. Scans char-by-char tracking whether we're inside a string; when a '"' appears mid-string,
// checks whether the NEXT real character actually looks like valid JSON continuation (: , } ]) — if
// not, this wasn't a real closing quote, so escape it and keep treating the string as open.
// A heuristic, not a real parser — good enough to recover the common case, not guaranteed for every
// case, which is why it only runs as a last resort after strategies 1-4 have already failed.
function repairUnescapedQuotes(str) {
  var out = '';
  var inString = false;
  for (var i = 0; i < str.length; i++) {
    var ch = str[i];
    if (inString && ch === '\\') {
      out += ch + (str[i + 1] || '');
      i++;
      continue;
    }
    if (ch === '"') {
      if (!inString) {
        inString = true;
        out += ch;
        continue;
      }
      var j = i + 1;
      while (j < str.length && /\s/.test(str[j])) j++;
      var next = str[j];
      if (next === undefined || next === ':' || next === ',' || next === '}' || next === ']') {
        inString = false;
        out += ch;
      } else {
        out += '\\"';
      }
      continue;
    }
    out += ch;
  }
  return out;
}

function parseAiJsonResponse(text, label) {
  function tryParse(str) {
    try { return { ok: true, value: JSON.parse(str) }; } catch (e) { return { ok: false, error: e }; }
  }

  // Strategies 1-3 cover the vast majority of real responses — only strategy 4 (scanning forward
  // through every ']' in the text) does real work, and it's only computed if everything before it
  // genuinely failed, so the normal successful path pays none of that cost.
  var fenced = text.match(/```(?:json)?\s*([\s\S]*?)\s*```/i);
  if (fenced) {
    var r1 = tryParse(fenced[1]);
    if (r1.ok) return r1.value;
  }

  var r2 = tryParse(text.trim());
  if (r2.ok) return r2.value;

  var greedy = text.match(/\[[\s\S]*\]/);
  var r3 = null;
  if (greedy) {
    r3 = tryParse(greedy[0]);
    if (r3.ok) return r3.value;
  }

  var firstBracket = text.indexOf('[');
  if (firstBracket !== -1) {
    var closeIdx = text.indexOf(']', firstBracket);
    while (closeIdx !== -1) {
      var r4 = tryParse(text.slice(firstBracket, closeIdx + 1));
      if (r4.ok) {
        console.log('[Design Guardian] ' + (label || 'ai') + ': JSON recovered via fallback extraction (strategies 1-3 would have failed) — avoided a retry');
        return r4.value;
      }
      closeIdx = text.indexOf(']', closeIdx + 1);
    }
  }

  // Strategy 5: repair likely-unescaped embedded quotes (see repairUnescapedQuotes) and retry on
  // the greedy span. Last resort, after everything above already failed — a heuristic repair is
  // more likely to succeed on the widest, most complete candidate we have.
  if (greedy) {
    var r5 = tryParse(repairUnescapedQuotes(greedy[0]));
    if (r5.ok) {
      console.log('[Design Guardian] ' + (label || 'ai') + ': JSON recovered by repairing an unescaped quote — avoided a retry');
      return r5.value;
    }
  }

  // Strategy 6: bare-object equivalents of strategies 3+5. Models intermittently drop the
  // requested [ ] wrapper and return { ... } (see unwrapAiObject) — when that response also has
  // commentary around it (no code fence, not clean), none of the array-hunting strategies above
  // can find it. Greedy first-'{' to last-'}' span, then the same quote-repair pass on it.
  var greedyObj = text.match(/\{[\s\S]*\}/);
  if (greedyObj) {
    var r6 = tryParse(greedyObj[0]);
    if (!r6.ok) r6 = tryParse(repairUnescapedQuotes(greedyObj[0]));
    if (r6.ok) {
      console.log('[Design Guardian] ' + (label || 'ai') + ': JSON recovered as a bare object (model dropped the array wrapper) — avoided a retry');
      return r6.value;
    }
  }

  // Was just a fixed 300-char preview of the START of the text — useless when the actual break is
  // somewhere in the middle of a 15,000+ character response (verified directly: a real failure had
  // stop_reason=end_turn, meaning the model believes it finished normally, so the break is a genuine
  // JSON syntax problem partway through, not a truncated ending — a head-of-text preview can't show
  // that). Use the greedy attempt's own SyntaxError, which usually names a character position, to
  // show the text AROUND the actual break instead of the unrelated start of the response.
  var diag = 'preview: "' + text.slice(0, 300).replace(/\n/g, ' ') + '"';
  if (r3 && !r3.ok && r3.error && greedy) {
    var msg = r3.error.message || '';
    var posMatch = msg.match(/position (\d+)/i);
    if (posMatch) {
      var pos = parseInt(posMatch[1], 10);
      var start = Math.max(0, pos - 150);
      var end = Math.min(greedy[0].length, pos + 150);
      diag = 'JSON.parse error: "' + msg + '" — text around position ' + pos + ': "...' + greedy[0].slice(start, end).replace(/\n/g, ' ') + '..."';
    } else {
      diag = 'JSON.parse error: "' + msg + '" (no position given) — preview: "' + text.slice(0, 300).replace(/\n/g, ' ') + '"';
    }
  }
  console.warn('[Design Guardian] ' + (label || 'ai') + ': all JSON extraction strategies failed (' + text.length + ' chars) — ' + diag);
  return [];
}

// runAiScanAnthropic: calls Anthropic Messages API with the given prompt; returns parsed issues array.
// If cacheableSystem is provided, it is sent as the system prompt with prompt caching enabled,
// and prompt is sent as the user message. This reduces token costs on parallel frame scans.
async function runAiScanAnthropic(apiKey, model, prompt, cacheableSystem, label) {
  const _aiStart = Date.now();
  const reqHeaders = {
    'Content-Type': 'application/json',
    'x-api-key': apiKey,
    'anthropic-version': '2023-06-01',
  };
  let bodyData;
  if (cacheableSystem) {
    reqHeaders['anthropic-beta'] = 'prompt-caching-2024-07-31';
    bodyData = {
      model: model,
      max_tokens: 4096,
      system: [{ type: 'text', text: cacheableSystem, cache_control: { type: 'ephemeral' } }],
      messages: [{ role: 'user', content: prompt }],
    };
  } else {
    bodyData = {
      model: model,
      max_tokens: 4096,
      messages: [{ role: 'user', content: prompt }],
    };
  }
  const res = await fetchJson('https://api.anthropic.com/v1/messages', {
    method: 'POST',
    headers: reqHeaders,
    body: JSON.stringify(bodyData),
  }, 'Anthropic API');
  const usage = res && res.usage;
  const cacheRead = (usage && usage.cache_read_input_tokens) || 0;
  const cacheCreate = (usage && usage.cache_creation_input_tokens) || 0;
  logAiUsage(label, model, usage && usage.input_tokens, usage && usage.output_tokens, cacheRead, cacheCreate, Date.now() - _aiStart);
  if (res && res.stop_reason === 'max_tokens') throw new Error('AI response truncated (output limit reached). Try scanning fewer nodes at once.');
  const text = res && res.content && res.content[0] && res.content[0].text || '';
  return parseAiJsonResponse(text, label);
}

// runAiScanOpenAI: calls OpenAI Chat Completions API; returns parsed issues array.
async function runAiScanOpenAI(apiKey, model, prompt, label) {
  const _aiStart = Date.now();
  const res = await fetchJson('https://api.openai.com/v1/chat/completions', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'Authorization': 'Bearer ' + apiKey },
    body: JSON.stringify({
      model: model,
      messages: [{ role: 'user', content: prompt }],
      max_tokens: 4096,
    }),
  }, 'OpenAI API');
  const usage = res && res.usage;
  logAiUsage(label, model, usage && usage.prompt_tokens, usage && usage.completion_tokens, 0, 0, Date.now() - _aiStart);
  const finishReason = res && res.choices && res.choices[0] && res.choices[0].finish_reason;
  if (finishReason === 'length') throw new Error('AI response truncated (output limit reached). Try scanning fewer nodes at once.');
  const text = res && res.choices && res.choices[0] && res.choices[0].message && res.choices[0].message.content || '';
  return parseAiJsonResponse(text, label);
}

// runAiScanGoogle: calls Google Generative Language API (Gemini); returns parsed issues array.
async function runAiScanGoogle(apiKey, model, prompt, label) {
  const _aiStart = Date.now();
  const endpoint = 'https://generativelanguage.googleapis.com/v1beta/models/' + model + ':generateContent?key=' + apiKey;
  const res = await fetchJson(endpoint, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ contents: [{ parts: [{ text: prompt }] }], generationConfig: { maxOutputTokens: 4096 } }),
  }, 'Google AI API');
  const usage = res && res.usageMetadata;
  logAiUsage(label, model, usage && usage.promptTokenCount, usage && usage.candidatesTokenCount, 0, 0, Date.now() - _aiStart);
  const finishReason = res && res.candidates && res.candidates[0] && res.candidates[0].finishReason;
  if (finishReason === 'MAX_TOKENS') throw new Error('AI response truncated (output limit reached). Try scanning fewer nodes at once.');
  const text = res && res.candidates && res.candidates[0] && res.candidates[0].content && res.candidates[0].content.parts && res.candidates[0].content.parts[0] && res.candidates[0].content.parts[0].text || '';
  return parseAiJsonResponse(text, label);
}

// runAiScanOllama: calls a local Ollama instance; returns parsed issues array.
async function runAiScanOllama(endpoint, model, prompt, label) {
  const _aiStart = Date.now();
  const res = await fetchJson(endpoint + '/api/chat', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      model: model,
      messages: [{ role: 'user', content: prompt }],
      stream: false,
      options: { num_predict: 4096 },
    }),
  }, 'Ollama');
  logAiUsage(label, model, res && res.prompt_eval_count, res && res.eval_count, 0, 0, Date.now() - _aiStart);
  const text = res && res.message && res.message.content || '';
  return parseAiJsonResponse(text, label);
}

// ── CLI subscription helpers ───────────────────────────────────────────────────
// Spawns a CLI process, writes the prompt via stdin, and returns stdout as text.
function spawnCli(cmd, args, stdinData, timeoutMs) {
  var effectiveTimeoutMs = timeoutMs || 240000;
  return new Promise(function(resolve, reject) {
    var child = spawn(cmd, args, { env: process.env });
    var stdout = '';
    var stderr = '';
    var settled = false;
    var timeoutId = setTimeout(function() {
      if (settled) return;
      settled = true;
      try { child.kill(); } catch (_) {}
      reject(new Error(cmd + ' CLI timed out after ' + Math.round(effectiveTimeoutMs / 1000) + 's'));
    }, effectiveTimeoutMs);
    child.stdout.on('data', function(d) { stdout += d.toString(); });
    child.stderr.on('data', function(d) { stderr += d.toString(); });
    child.on('error', function() {
      if (settled) return;
      settled = true;
      clearTimeout(timeoutId);
      reject(new Error(cmd + ' CLI not found. Install it and log in.'));
    });
    child.on('close', function(code) {
      if (settled) return;
      settled = true;
      clearTimeout(timeoutId);
      if (!stdout.trim() && code !== 0) {
        var detail = stderr.trim() || ('exit code ' + code);
        console.error('[spawnCli] ' + cmd + ' failed — stderr: ' + stderr.trim());
        reject(new Error(cmd + ' CLI error: ' + detail));
      } else {
        resolve(stdout);
      }
    });
    if (stdinData) {
      try { child.stdin.write(stdinData); child.stdin.end(); } catch (_) {}
    }
  });
}

// Returns true if the given CLI command exists on PATH.
function isCliInstalled(cmd) {
  return new Promise(function(resolve) {
    var which = process.platform === 'win32' ? 'where' : 'which';
    execFile(which, [cmd], function(err) { resolve(!err); });
  });
}

// Returns true if the given provider's CLI is authenticated.
async function checkCliAuth(provider) {
  try {
    if (provider === 'anthropic') {
      // `claude auth status` is instant (reads local session, no API call) and returns
      // structured JSON: { loggedIn: true/false, authMethod, email, ... }
      return await new Promise(function(resolve) {
        execFile('claude', ['auth', 'status'], { timeout: 8000, env: process.env }, function(err, stdout) {
          if (err) { resolve(false); return; }
          try { resolve(!!JSON.parse(stdout.trim()).loggedIn); }
          catch (_) { resolve(false); }
        });
      });
    }
    if (provider === 'google') {
      var geminiAuthOk = await new Promise(function(resolve) {
        execFile('gemini', ['auth', 'status'], { timeout: 5000 }, function(err) { resolve(!err); });
      });
      if (geminiAuthOk) return true;
      var geminiFiles = [
        path.join(os.homedir(), '.gemini', 'oauth_creds.json'),
        path.join(os.homedir(), '.gemini', 'auth.json'),
      ];
      return geminiFiles.some(function(p) {
        try { return !!JSON.parse(fs.readFileSync(p, 'utf8')); } catch (_) { return false; }
      });
    }
    if (provider === 'openai') {
      var codexFiles = [
        path.join(os.homedir(), '.codex', 'auth.json'),
        path.join(os.homedir(), '.config', 'codex', 'auth.json'),
      ];
      return codexFiles.some(function(p) {
        try { return !!JSON.parse(fs.readFileSync(p, 'utf8')); } catch (_) { return false; }
      });
    }
    return false;
  } catch (_) { return false; }
}

// Cost-ordered model aliases for Anthropic CLI (cheapest first).
var ANTHROPIC_MODEL_PRIORITY = ['haiku', 'sonnet', 'opus'];

// Reads availableModels from ~/.claude/settings.json and returns the cheapest allowed alias.
// Falls back to 'haiku' when no restriction is configured.
function pickAnthropicCliModel() {
  try {
    var settingsPath = path.join(os.homedir(), '.claude', 'settings.json');
    var settings = JSON.parse(fs.readFileSync(settingsPath, 'utf8'));
    if (Array.isArray(settings.availableModels) && settings.availableModels.length > 0) {
      for (var i = 0; i < ANTHROPIC_MODEL_PRIORITY.length; i++) {
        var alias = ANTHROPIC_MODEL_PRIORITY[i];
        if (settings.availableModels.some(function(m) { return typeof m === 'string' && m.toLowerCase().includes(alias); })) {
          return alias;
        }
      }
    }
  } catch (_) {}
  return 'haiku';
}

// Cached CLI model state after first successful Anthropic call:
//   null                         = not yet determined
//   { alias, useFlag: true }     = --model <alias> accepted
//   { alias: 'default', useFlag: false } = --model blocked; use no flag
var _cliModelState = null;

// Routes a CLI subscription scan to the correct CLI binary for the provider.
// Anthropic: uses --output-format json for token counts; tries --model first with
// enterprise fallback (enterprise policies block --model; server detects and retries).
async function runAiScanCLI(provider, model, prompt, label, timeoutMs) {
  var cliConfigs = {
    // --output-format json gives token counts + cost in a wrapper object; result field has the AI text.
    anthropic: { cmd: 'claude', args: ['-p', '--output-format', 'json'], jsonWrapper: true },
    google:    { cmd: 'gemini', args: ['-p'] },
    openai:    { cmd: 'codex',  args: ['exec', '-', '--ephemeral'] },
  };
  var cli = cliConfigs[provider];
  if (!cli) throw new Error('CLI subscription is not supported for provider: ' + provider + '. Use API Key mode instead.');

  // For Anthropic: try to pass --model for cost optimisation; fall back if enterprise blocks it.
  var args;
  var modelAlias;
  if (provider === 'anthropic' && cli.jsonWrapper) {
    var requestedAlias = model
      ? (/haiku/i.test(model) ? 'haiku' : /sonnet/i.test(model) ? 'sonnet' : /opus/i.test(model) ? 'opus' : model)
      : pickAnthropicCliModel();
    if (_cliModelState === null || _cliModelState.useFlag) {
      modelAlias = requestedAlias;
      args = ['-p', '--output-format', 'json', '--model', modelAlias];
    } else {
      modelAlias = 'enterprise-default'; // --model blocked by policy; CLI uses its own locked default
      args = cli.args.slice();
    }
  } else {
    args = cli.args.slice();
  }

  const _cliStart = Date.now();
  var stdout = await spawnCli(cli.cmd, args, prompt, timeoutMs);

  var responseText = stdout;
  if (cli.jsonWrapper) {
    try {
      var wrapper = JSON.parse(stdout);
      // First call: if --model was rejected by enterprise policy, retry without it.
      if (wrapper.is_error && _cliModelState === null) {
        var errText = (typeof wrapper.result === 'string' ? wrapper.result : '').toLowerCase();
        if (errText.includes('model') || errText.includes('not found') || errText.includes('not available')) {
          console.log('[Design Guardian] --model ' + modelAlias + ' blocked by policy, retrying with default model');
          _cliModelState = { alias: 'default', useFlag: false };
          stdout = await spawnCli(cli.cmd, cli.args.slice(), prompt, timeoutMs);
          wrapper = JSON.parse(stdout);
          modelAlias = 'default';
        }
      } else if (!wrapper.is_error && _cliModelState === null) {
        _cliModelState = { alias: modelAlias, useFlag: true };
      }
      responseText = wrapper.result || '';
      var u = wrapper.usage || {};
      var cacheRead = u.cache_read_input_tokens || 0;
      var cacheMiss = u.cache_creation_input_tokens || 0;
      logAiUsage(label, (modelAlias || 'default') + ' (CLI/' + provider + ')', u.input_tokens, u.output_tokens, cacheRead, cacheMiss, Date.now() - _cliStart, wrapper.total_cost_usd != null ? wrapper.total_cost_usd : null);
      // Logged unconditionally, not just when something already looks wrong — this is the model's
      // OWN signal for whether it considers its answer complete (stop_reason). Verified directly
      // that even a genuinely broken response can carry stop_reason=end_turn (the model believes it
      // finished normally) — so this is only useful as a baseline if we can see it on EVERY call,
      // successful or not, to know what "normal" looks like and compare against.
      var stopReasonForLog = wrapper.stop_reason || wrapper.stopReason || wrapper.finish_reason || '(none on wrapper)';
      console.log('[Design Guardian] ' + label + ': model stop_reason=' + stopReasonForLog + ' result_chars=' + responseText.length + ' output_tokens=' + (u.output_tokens || '?'));
      // The direct-API paths (runAiScanAnthropic etc.) explicitly check stop_reason === 'max_tokens'
      // and throw a clear error — this CLI path never checked for the equivalent signal at all.
      // Verified directly: a content-scan call reported 18,624 output tokens billed, but the actual
      // result text handed to the parser was only 19,236 characters — at any realistic tokens-to-
      // characters ratio that's a huge mismatch, consistent with generation being cut off mid-JSON
      // rather than a parsing failure on complete text. Log everything we can about why, the first
      // time this fires, so the next occurrence gives a definitive answer instead of more guessing.
      // Strip a trailing markdown fence before checking — verified directly this was a false-
      // positive generator: a response ending "...}]\n```" has ']' as the true end of the JSON, but
      // the LITERAL last characters of the full text are the closing backticks, so the naive check
      // flagged it as truncated even though it went on to parse and process successfully (real
      // issues found, no missing-refs retry needed). Only warn when the content actually looks
      // incomplete once the fence itself is discounted.
      var trimmedResult = responseText.trim().replace(/```\s*$/, '').trim();
      var looksIncomplete = trimmedResult.length > 0 && !/[\]}]$/.test(trimmedResult);
      if (looksIncomplete || stopReasonForLog === 'max_tokens') {
        console.warn('[Design Guardian] ' + label + ': CLI response looks truncated (does not end in ] or }) — ' +
          'result_chars=' + responseText.length + ' output_tokens=' + (u.output_tokens || '?') +
          ' stop_reason=' + stopReasonForLog +
          ' wrapper_keys=' + Object.keys(wrapper).join(','));
      }
    } catch (_) {
      console.log('[Design Guardian] AI ' + (label || 'ai') + ' provider=' + provider + ' (CLI, could not parse usage) elapsed=' + (Date.now() - _cliStart) + 'ms');
    }
  } else {
    console.log('[Design Guardian] AI ' + (label || 'ai') + ' provider=' + provider + ' (CLI, no token count) elapsed=' + (Date.now() - _cliStart) + 'ms');
  }

  // Only treat as an auth error if the response literally says "not logged in".
  // Avoid matching "login" broadly — AI responses about login flows would trigger false positives.
  if (!responseText.includes('[') && (
    responseText.toLowerCase().includes('not logged in') ||
    responseText.toLowerCase().includes('please run /login') ||
    responseText.toLowerCase().includes('unauthorized')
  )) {
    throw new Error('CLI not authenticated: ' + responseText.trim() + '. Run `' + cli.cmd + '` in your terminal and use /login.');
  }
  return parseAiJsonResponse(responseText, label);
}

function findAvailablePort(preferred) {
  return new Promise(function(resolve, reject) {
    var port = preferred;
    var maxAttempts = 10;
    var attempts = 0;
    function tryPort() {
      if (attempts >= maxAttempts) {
        reject(new Error('No available port found between ' + preferred + ' and ' + (preferred + maxAttempts - 1)));
        return;
      }
      attempts++;
      var probe = net.createServer();
      probe.once('error', function(err) {
        if (err.code === 'EADDRINUSE') {
          port++;
          tryPort();
        } else {
          reject(err);
        }
      });
      probe.once('listening', function() {
        probe.close(function() { resolve(port); });
      });
      probe.listen(port, '0.0.0.0');
    }
    tryPort();
  });
}

// Cert covers design-guardian.local + localhost + 127.0.0.1 so the plugin can
// connect via either hostname without Bonjour conflicts when multiple users run
// their own server. mkcert names the file with a +2 suffix for 3 domains.
const certPath = path.join(__dirname, 'design-guardian.local+2.pem');
const keyPath = path.join(__dirname, 'design-guardian.local+2-key.pem');

function tryGenerateCertsWithMkcert() {
  var check = spawnSync('mkcert', ['--version'], { stdio: 'pipe' });
  if (check.error || check.status !== 0) return false;
  // Remove old single-host cert if present so server picks up the new multi-host one.
  var oldCert = path.join(__dirname, 'design-guardian.local.pem');
  var oldKey = path.join(__dirname, 'design-guardian.local-key.pem');
  if (fs.existsSync(oldCert)) { try { fs.unlinkSync(oldCert); fs.unlinkSync(oldKey); } catch (e) {} }
  // -install adds the local CA to the system trust store; needs sudo on macOS so inherit stdio for the password prompt
  console.log('[Design Guardian] Installing local CA via mkcert (you may be prompted for your password)...');
  var install = spawnSync('mkcert', ['-install'], { stdio: 'inherit', timeout: 60000 });
  // Check both spawn error AND exit code — non-zero means user denied the password prompt or install failed
  if (install.error || install.status !== 0) {
    console.log('[Design Guardian] mkcert -install failed or was cancelled. HTTPS cert will not be trusted.');
    return false;
  }
  var gen = spawnSync('mkcert', ['design-guardian.local', 'localhost', '127.0.0.1'], { cwd: __dirname, stdio: 'pipe', timeout: 30000 });
  return !gen.error && gen.status === 0;
}

// isCertTrusted: verifies the existing cert is signed by the mkcert root CA that is
// currently installed on this machine. Returns true if trusted, false if the CA is
// missing or the cert can't be verified (e.g. mkcert was installed AFTER the cert was
// generated, so -install was never run and the root CA was never added to the trust store).
function isCertTrusted(cert) {
  var carootResult = spawnSync('mkcert', ['-CAROOT'], { stdio: 'pipe' });
  if (carootResult.error || carootResult.status !== 0) return false; // mkcert gone or broken — cert cannot be verified as trusted
  var caroot = carootResult.stdout.toString().trim();
  var caFile = path.join(caroot, 'rootCA.pem');
  if (!fs.existsSync(caFile)) return false;
  // openssl verify returns exit 0 only when the chain is fully trusted
  var verify = spawnSync('openssl', ['verify', '-CAfile', caFile, cert], { stdio: 'pipe' });
  if (verify.error) return true; // openssl not available — skip check
  return verify.status === 0;
}

let hasTls = fs.existsSync(certPath) && fs.existsSync(keyPath);
if (!hasTls) {
  if (tryGenerateCertsWithMkcert()) {
    hasTls = fs.existsSync(certPath) && fs.existsSync(keyPath);
    if (hasTls) console.log('[Design Guardian] Generated TLS certificate via mkcert');
  } else {
    console.log('[Design Guardian] mkcert not found - run: brew install mkcert (then restart for HTTPS)');
  }
} else if (!isCertTrusted(certPath)) {
  // Cert files exist but are not trusted — most common cause: mkcert was installed after
  // the cert was first generated, so mkcert -install never ran and the root CA was never
  // added to the system trust store. Delete stale certs and regenerate with a fresh install.
  console.log('[Design Guardian] Existing TLS certificate is not trusted by this machine. Re-generating...');
  try { fs.unlinkSync(certPath); fs.unlinkSync(keyPath); } catch (e) {}
  if (tryGenerateCertsWithMkcert()) {
    hasTls = fs.existsSync(certPath) && fs.existsSync(keyPath);
    if (hasTls) console.log('[Design Guardian] Re-generated trusted TLS certificate via mkcert');
  } else {
    hasTls = false;
    console.log('[Design Guardian] mkcert not found - run: brew install mkcert (then restart for HTTPS)');
  }
}

// Guarded so requiring this file (e.g. from a test) doesn't also try to bind a real port and start
// listening — `node server.js` directly still runs exactly as before, since require.main === module
// is only true when the file is the actual entry point, not when something else requires() it.
if (require.main === module) {
findAvailablePort(PORT).then(function(port) {
  var protocol = hasTls ? 'https' : 'http';
  var serverUrl = protocol + '://localhost:' + port;

  function onListening() {
    var bar = '-'.repeat(Math.max(serverUrl.length + 6, 52));
    console.log('');
    console.log('[Design Guardian] Server started');
    if (port !== PORT) {
      console.log('[Design Guardian] Port ' + PORT + ' was in use, switched to ' + port);
    }
    console.log('');
    console.log(bar);
    console.log('  Plugin URL:');
    console.log('  ' + serverUrl);
    console.log('');
    console.log('  Copy the URL above and paste it into the plugin settings.');
    console.log(bar);
    console.log('');
    if (_bonjour) {
      var _svc = _bonjour.publish({ name: 'Design Guardian', type: hasTls ? 'https' : 'http', port: port, host: 'design-guardian.local' });
      if (_svc && typeof _svc.on === 'function') {
        _svc.on('error', function(err) {
          var msg = err && err.message ? err.message : String(err);
          if (msg.indexOf('already in use') !== -1) {
            console.log('[Design Guardian] Note: mDNS auto-discovery is already advertised by another server instance. This is harmless -- your server is running normally and the plugin can still connect using the URL above.');
          }
        });
      }
    }
    if (!hasTls) {
      var installCmd = process.platform === 'win32' ? 'choco install mkcert' : 'brew install mkcert';
      console.log('[Design Guardian] HTTPS is required for the Figma desktop app.');
      console.log('[Design Guardian] Install mkcert and restart the server:');
      console.log('[Design Guardian]   ' + installCmd);
    }
    if (!FIGMA_PAT) {
      console.warn('');
      console.warn('[Design Guardian] WARNING: FIGMA_PAT is not set in your .env file.');
      console.warn('[Design Guardian] Library sync will fail. Add FIGMA_PAT=your_token to .env and restart.');
      console.warn('');
    }
  }

  if (hasTls) {
    https.createServer({ cert: fs.readFileSync(certPath), key: fs.readFileSync(keyPath) }, requestHandler).listen(port, '0.0.0.0', onListening);
  } else {
    http.createServer(requestHandler).listen(port, '0.0.0.0', onListening);
  }
}).catch(function(err) {
  console.error('');
  console.error('[Design Guardian] Could not start: ' + err.message);
  console.error('[Design Guardian] Ports 3001-3010 are the only ones the Figma plugin is allowed to connect to.');
  console.error('[Design Guardian] Free up one of those ports and try again.');
  console.error('');
  process.exit(1);
});
}

// Exported for tests only — requiring this file never starts a server (see the require.main guard
// above); production behavior of `node server.js` is unaffected.
module.exports = { parseAiJsonResponse };