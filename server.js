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

// In-memory cache for guidelines evaluation results keyed by SHA-256 content hash.
// Avoids re-running the AI eval when the guidelines file has not changed.
const _evalGuidelinesCache = {};
// In-flight promises keyed by content hash — coalesces concurrent requests for
// identical content so only one Claude call is made even if N arrive simultaneously.
const _evalGuidelinesInFlight = {};
// URL content cache: keyed by URL, value = { content, fetchedAt }. Only successful
// fetches are cached; failures are retried on the next scan.
const _urlContentCache = {};
const _URL_CACHE_TTL = 60 * 60 * 1000; // 1 hour

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
    if (req.method === 'GET' && url.pathname === '/auth/figma') {
      const state = url.searchParams.get('state');
      if (!state) { sendJson(res, 400, { error: 'Missing state param' }); return; }
      if (!FIGMA_CLIENT_ID) { sendJson(res, 500, { error: 'OAuth not configured' }); return; }
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
    if (req.method === 'GET' && url.pathname === '/auth/figma/callback') {
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
    if (req.method === 'GET' && url.pathname === '/auth/poll') {
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
    if (req.method === 'GET' && url.pathname === '/auth/me') {
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
          sendJson(res, 200, { ok: true, content: raw, files: [legacyFile], manual: '' });
        } else {
          sendJson(res, 200, { ok: true, content: data.content || '', files: data.files || [], manual: data.manual || '' });
        }
      } catch (_) {
        sendJson(res, 200, { ok: true, content: '', files: [], manual: '' });
      }
      return;
    }

    // ── POST /ai/guidelines ──────────────────────────────────────────────────
    // Accepts { files: [{name,content,lines,enabled}], manual: string }.
    // Merges into a single content string for AI scans and stores all three.
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
          const fileContent = files.filter(function(f) { return f.enabled !== false; })
            .map(function(f) { return '--- ' + f.name + ' ---\n' + stripYamlFrontmatter(f.content || ''); }).join('\n\n');
          const content = fileContent && manual ? fileContent + '\n\n--- Manual ---\n' + manual
            : fileContent || manual;
          fs.mkdirSync(path.dirname(GUIDELINES_FILE), { recursive: true });
          fs.writeFileSync(GUIDELINES_FILE, JSON.stringify({ content, files, manual }), 'utf8');
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
          if (issues && issues.length > 0) _evalGuidelinesCache[contentHash] = issues;
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
            rawBatch.forEach(function(entry) {
              if (!entry || !entry.name) return;
              const file = uncached.find(function(f) { return f.name === entry.name; });
              if (!file) return;
              const issues = Array.isArray(entry.issues) ? entry.issues : [];
              if (issues.length > 0) _evalGuidelinesCache[file.hash] = issues;
              results[entry.name] = { issues: issues, cached: false };
            });
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
          if (provider === 'anthropic') {
            await fetchJson('https://api.anthropic.com/v1/messages', {
              method: 'POST',
              headers: { 'Content-Type': 'application/json', 'x-api-key': apiKey, 'anthropic-version': '2023-06-01' },
              body: JSON.stringify({ model, max_tokens: 5, messages: [{ role: 'user', content: testPrompt }] }),
            }, 'Anthropic API');
          } else if (provider === 'openai') {
            await fetchJson('https://api.openai.com/v1/chat/completions', {
              method: 'POST',
              headers: { 'Content-Type': 'application/json', 'Authorization': 'Bearer ' + apiKey },
              body: JSON.stringify({ model, max_tokens: 5, messages: [{ role: 'user', content: testPrompt }] }),
            }, 'OpenAI API');
          } else if (provider === 'google') {
            const endpoint = 'https://generativelanguage.googleapis.com/v1beta/models/' + model + ':generateContent?key=' + apiKey;
            await fetchJson(endpoint, {
              method: 'POST',
              headers: { 'Content-Type': 'application/json' },
              body: JSON.stringify({ contents: [{ parts: [{ text: testPrompt }] }] }),
            }, 'Google AI API');
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
      req.on('end', async function() {
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
          try {
            const raw = fs.readFileSync(GUIDELINES_FILE, 'utf8');
            let parsed;
            try { parsed = JSON.parse(raw); } catch (_) { parsed = null; }
            guidelines = (parsed && typeof parsed.content === 'string') ? parsed.content : raw;
          } catch (_) {}
          if (!guidelines.trim()) {
            sendJson(res, 400, { error: 'No content guidelines found. Upload guidelines in plugin settings.' });
            return;
          }

          const model = cfg.model || AI_DEFAULT_MODELS[cfg.provider] || '';
          const { content: resolvedGuidelines, failedUrls, fetchedUrls } = await resolveGuidelinesUrls(guidelines);
          const issues = await runAiContentScan(cfg, model, resolvedGuidelines, textNodes);
          sendJson(res, 200, { ok: true, issues, urlWarnings: failedUrls.length > 0 ? failedUrls : undefined, fetchedUrls: fetchedUrls.length > 0 ? fetchedUrls : undefined, meta: { provider: cfg.provider, model, nodeCount: textNodes.length } });
        } catch (e) {
          sendJson(res, 500, { error: e.message || 'AI scan failed' });
        }
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
      req.on('end', async function() {
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
          try {
            const raw = fs.readFileSync(GUIDELINES_FILE, 'utf8');
            let parsed;
            try { parsed = JSON.parse(raw); } catch (_) { parsed = null; }
            guidelines = (parsed && typeof parsed.content === 'string') ? parsed.content : raw;
          } catch (_) {}
          if (!guidelines.trim()) {
            sendJson(res, 400, { error: 'No content guidelines found. Upload guidelines in plugin settings.' }); return;
          }
          const model = cfg.model || AI_DEFAULT_MODELS[cfg.provider] || '';
          const { content: resolvedGuidelines, failedUrls, fetchedUrls } = await resolveGuidelinesUrls(guidelines);
          const issues = await runAiContentScanBatch(cfg, model, resolvedGuidelines, frames);
          sendJson(res, 200, { ok: true, issues, urlWarnings: failedUrls.length > 0 ? failedUrls : undefined, fetchedUrls: fetchedUrls.length > 0 ? fetchedUrls : undefined, meta: { provider: cfg.provider, model, frameCount: frames.length } });
        } catch (e) {
          sendJson(res, 500, { error: e.message || 'Batch scan failed' });
        }
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
      req.on('end', async function() {
        try {
          const body = JSON.parse(Buffer.concat(normChunks).toString('utf8'));
          const issues = Array.isArray(body.issues) ? body.issues : [];
          if (issues.length === 0) { sendJson(res, 200, { ok: true, issues: [] }); return; }
          const cfg = loadAiConfig();
          if (!cfg.provider) { sendJson(res, 400, { error: 'AI provider not configured' }); return; }
          const model = cfg.model || AI_DEFAULT_MODELS[cfg.provider] || '';
          const normalized = await runAiNormalizationPass(cfg, model, issues);
          sendJson(res, 200, { ok: true, issues: normalized });
        } catch (e) {
          sendJson(res, 500, { error: e.message || 'Normalization failed' });
        }
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

function extractUrls(text) {
  const seen = new Set();
  const results = [];
  const re = /https?:\/\/[^\s)>"'\]\\,]+/g;
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

async function fetchUrlViaCli(url) {
  const prompt = [
    'Use any available tools or connectors to fetch the full text content of this URL:',
    url,
    '',
    'Rules:',
    '- Use a connector/tool to retrieve it. Do NOT make up or summarise the content.',
    '- Return ONLY the raw text content — no markdown, no explanation, no extra commentary.',
    '- If you cannot retrieve it for any reason, output exactly: FETCH_FAILED',
  ].join('\n');
  try {
    var modelAlias = (_cliModelState && _cliModelState.useFlag) ? _cliModelState.alias : pickAnthropicCliModel();
    var args = (_cliModelState && !_cliModelState.useFlag)
      ? ['-p', '--output-format', 'json']
      : ['-p', '--output-format', 'json', '--model', modelAlias];
    const stdout = await spawnCli('claude', args, prompt);
    const wrapper = JSON.parse(stdout);
    const result = (wrapper.result || '').trim();
    if (!result || /^FETCH_FAILED/i.test(result)) {
      console.warn('[Design Guardian] fetch-url CLI returned FETCH_FAILED for ' + url);
      return null;
    }
    return result.slice(0, 20000);
  } catch (err) {
    console.error('[Design Guardian] fetch-url CLI error for ' + url + ': ' + err.message);
    return null;
  }
}

// resolveGuidelinesUrls: replaces URLs found in guidelines with their fetched content,
// so Claude sees the referenced material inline. Cached per URL for 1 hour.
// Returns { content, failedUrls, fetchedUrls } so callers can surface both successes and failures.
async function resolveGuidelinesUrls(content) {
  const urls = extractUrls(content);
  if (urls.length === 0) return { content, failedUrls: [], fetchedUrls: [] };

  const now = Date.now();

  // Fetch all URLs in parallel — each is independent.
  const fetchResults = await Promise.all(urls.map(async function(url) {
    const cached = _urlContentCache[url];
    if (cached && now - cached.fetchedAt < _URL_CACHE_TTL) {
      return { url, text: cached.content, failed: false };
    }
    let fetched = await fetchUrlDirect(url);
    if (!fetched) fetched = await fetchUrlViaCli(url);
    if (fetched) {
      _urlContentCache[url] = { content: fetched, fetchedAt: now };
      return { url, text: fetched, failed: false };
    }
    console.error('[Design Guardian] fetch-url all methods failed for: ' + url);
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
async function runAiContentScan(cfg, model, guidelines, textNodes) {
  const textSummary = textNodes
    // Each node gets a short integer ref so Claude echoes a trivially-copyable handle
    // instead of transcribing a 60-char instance-sublayer ID. Plugin maps ref -> real node.
    .map(function(n, i) { var ref = (n.ref === 0 || n.ref) ? n.ref : i; return '- [ref:' + ref + '] [' + n.path + '] ' + JSON.stringify(n.characters); })
    .join('\n');

  const persona = (cfg.persona || '').trim() || DEFAULT_AI_PERSONA;

  // systemPart: persona + guidelines (cacheable; identical across all parallel frame scans)
  const systemPart = [
    persona,
    '',
    '## Content Guidelines',
    guidelines,
  ].join('\n');

  // userPart: per-frame content + output instructions (changes each call)
  const userPart = [
    '## Text Content from Design (format: [ref:N] [layer path] "text")',
    textSummary,
    '',
    'Return ONLY a JSON array of issues. Each issue must have:',
    '- "ref": copy the exact integer from [ref:N] for the layer with the issue (e.g. 7). Just the number.',
    '- "layerPath": the layer path from the list above',
    '- "characters": copy the full text string for that layer exactly as it appears in the input above, character for character',
    '- "issue": ONE sentence, max 24 words. State only the violation. No conjunctions, no "also", no extra context.',
    '- "suggestion": ONE sentence, max 24 words. Give the fix or an example replacement.',
    '- "rule": 2-4 words naming the specific guideline violated. Examples: "Sentence case", "Banned term", "CTA specificity", "Second person", "Oxford comma".',
    '- "severity": "error" (clear rule violation) | "warning" (judgment call) | "suggestion" (optional improvement).',
    '- "source_file": the name from the "--- Name ---" section header where this guideline is defined (e.g. "Brand Voice Guide.md"). Omit if the rule comes from multiple files or the source is unclear.',
    '- "replacement": the FULL corrected text for this layer — the entire "characters" value after applying the fix, not just the changed word. Example: if characters is "I Drafted a High Severity" and the fix is sentence case, replacement must be "I drafted a High Severity". Omit this field entirely if no clean single replacement exists.',
    '',
    'Bad example: "All-caps violates sentence case. \'Action\' is flagged in the glossary and the accessibility guideline warns against generic copy."',
    'Good example issue: "All-caps violates sentence case requirement."',
    'Good example suggestion: "Use sentence case: \'Get started\' or \'Add exclusion\'."',
    'Good example rule: "Sentence case"',
    'Good example replacement: "Get started"',
    '',
    'If there are no issues, return an empty array []. Return only valid JSON, no explanation.',
  ].join('\n');

  // fullPrompt: functionally equivalent to the original joined array; used for non-Anthropic providers
  const fullPrompt = systemPart + '\n\n' + userPart;

  if (cfg.authMethod === 'cli') {
    return await runAiScanCLI(cfg.provider, model, fullPrompt, 'content-scan');
  }
  if (cfg.provider === 'anthropic') {
    // Pass systemPart separately so Anthropic can cache the guidelines across parallel frame scans
    return await runAiScanAnthropic(cfg.apiKey, model, userPart, systemPart, 'content-scan');
  } else if (cfg.provider === 'openai') {
    return await runAiScanOpenAI(cfg.apiKey, model, fullPrompt, 'content-scan');
  } else if (cfg.provider === 'google') {
    return await runAiScanGoogle(cfg.apiKey, model, fullPrompt, 'content-scan');
  } else if (cfg.provider === 'ollama') {
    return await runAiScanOllama(cfg.ollamaEndpoint || 'http://localhost:11434', model, fullPrompt, 'content-scan');
  }
  throw new Error('Unknown AI provider: ' + cfg.provider);
}

// runAiContentScanBatch: evaluates 2-3 frames in a single call to amortise the guidelines
// cache_miss across all frames instead of paying it once per concurrent call.
async function runAiContentScanBatch(cfg, model, guidelines, frames) {
  const persona = (cfg.persona || '').trim() || DEFAULT_AI_PERSONA;

  const systemPart = [
    persona,
    '',
    '## Content Guidelines',
    guidelines,
  ].join('\n');

  const framesText = frames.map(function(f) {
    const textSummary = f.textNodes
      .map(function(n, i) { var ref = (n.ref === 0 || n.ref) ? n.ref : i; return '  - [ref:' + ref + '] [' + n.path + '] ' + JSON.stringify(n.characters); })
      .join('\n');
    return '### Frame: "' + f.frameName + '"\n' + textSummary;
  }).join('\n\n');

  const userPart = [
    '## Text Content from Design (format: [ref:N] [layer path] "text")',
    '',
    framesText,
    '',
    'Return ONLY a JSON array of issues across all frames. Each issue must have:',
    '- "ref": copy the exact integer from [ref:N] for the layer with the issue (e.g. 7). Just the number.',
    '- "frameName": exactly as shown in the ### Frame header above',
    '- "layerPath": the full layer path from the list above',
    '- "characters": copy the full text string for that layer exactly as it appears in the input',
    '- "issue": ONE sentence, max 24 words. State only the violation.',
    '- "suggestion": ONE sentence, max 24 words. Give the fix or an example replacement.',
    '- "rule": 2-4 words naming the specific guideline violated.',
    '- "severity": "error" | "warning" | "suggestion"',
    '- "source_file": the name from the "--- Name ---" section header where this guideline is defined. Omit if the rule comes from multiple files or is unclear.',
    '- "replacement": the FULL corrected text for this layer (the entire "characters" value after fixing, not just the changed word). Omit if no clean single replacement exists.',
    '',
    'If there are no issues, return []. Return only valid JSON, no explanation.',
  ].join('\n');

  const fullPrompt = systemPart + '\n\n' + userPart;
  const label = 'content-scan-batch (' + frames.length + ' frames)';

  if (cfg.authMethod === 'cli') {
    return await runAiScanCLI(cfg.provider, model, fullPrompt, label);
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

// parseAiJsonResponse: extracts a JSON array from an AI response string; returns [] on parse failure.
function parseAiJsonResponse(text) {
  const match = text.match(/\[[\s\S]*\]/);
  if (!match) return [];
  try {
    return JSON.parse(match[0]);
  } catch (e) {
    return [];
  }
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
  const cacheInfo = (cacheRead || cacheCreate) ? (' cache_read=' + cacheRead + ' cache_write=' + cacheCreate) : '';
  console.log('[Design Guardian] AI ' + (label || 'ai') + ' model=' + model + ' in=' + (usage && usage.input_tokens || '?') + ' out=' + (usage && usage.output_tokens || '?') + cacheInfo + ' elapsed=' + (Date.now() - _aiStart) + 'ms');
  if (res && res.stop_reason === 'max_tokens') throw new Error('AI response truncated (output limit reached). Try scanning fewer nodes at once.');
  const text = res && res.content && res.content[0] && res.content[0].text || '';
  return parseAiJsonResponse(text);
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
  console.log('[Design Guardian] AI ' + (label || 'ai') + ' model=' + model + ' in=' + (usage && usage.prompt_tokens || '?') + ' out=' + (usage && usage.completion_tokens || '?') + ' elapsed=' + (Date.now() - _aiStart) + 'ms');
  const finishReason = res && res.choices && res.choices[0] && res.choices[0].finish_reason;
  if (finishReason === 'length') throw new Error('AI response truncated (output limit reached). Try scanning fewer nodes at once.');
  const text = res && res.choices && res.choices[0] && res.choices[0].message && res.choices[0].message.content || '';
  return parseAiJsonResponse(text);
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
  console.log('[Design Guardian] AI ' + (label || 'ai') + ' model=' + model + ' in=' + (usage && usage.promptTokenCount || '?') + ' out=' + (usage && usage.candidatesTokenCount || '?') + ' elapsed=' + (Date.now() - _aiStart) + 'ms');
  const finishReason = res && res.candidates && res.candidates[0] && res.candidates[0].finishReason;
  if (finishReason === 'MAX_TOKENS') throw new Error('AI response truncated (output limit reached). Try scanning fewer nodes at once.');
  const text = res && res.candidates && res.candidates[0] && res.candidates[0].content && res.candidates[0].content.parts && res.candidates[0].content.parts[0] && res.candidates[0].content.parts[0].text || '';
  return parseAiJsonResponse(text);
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
  console.log('[Design Guardian] AI ' + (label || 'ai') + ' model=' + model + ' in=' + (res && res.prompt_eval_count || '?') + ' out=' + (res && res.eval_count || '?') + ' elapsed=' + (Date.now() - _aiStart) + 'ms');
  const text = res && res.message && res.message.content || '';
  return parseAiJsonResponse(text);
}

// ── CLI subscription helpers ───────────────────────────────────────────────────
// Spawns a CLI process, writes the prompt via stdin, and returns stdout as text.
function spawnCli(cmd, args, stdinData) {
  return new Promise(function(resolve, reject) {
    var child = spawn(cmd, args, { env: process.env });
    var stdout = '';
    var stderr = '';
    var settled = false;
    var timeoutId = setTimeout(function() {
      if (settled) return;
      settled = true;
      try { child.kill(); } catch (_) {}
      reject(new Error(cmd + ' CLI timed out after 240s'));
    }, 240000);
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
async function runAiScanCLI(provider, model, prompt, label) {
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
  var stdout = await spawnCli(cli.cmd, args, prompt);

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
          stdout = await spawnCli(cli.cmd, cli.args.slice(), prompt);
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
      var cost = wrapper.total_cost_usd != null ? '$' + wrapper.total_cost_usd.toFixed(6) : '?';
      console.log('[Design Guardian] AI ' + (label || 'ai') + ' provider=' + provider + ' model=' + (modelAlias || 'default') + ' (CLI) in=' + (u.input_tokens || 0) + ' cache_read=' + cacheRead + ' cache_miss=' + cacheMiss + ' out=' + (u.output_tokens || 0) + ' cost=' + cost + ' elapsed=' + (Date.now() - _cliStart) + 'ms');
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
  return parseAiJsonResponse(responseText);
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