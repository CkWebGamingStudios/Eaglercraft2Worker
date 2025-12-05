// worker/index.js
// Custom JWT auth + GitHub-backed player template sync + jar proxy
// Env vars required: GITHUB_TOKEN, GITHUB_OWNER, GITHUB_REPO, JWT_SECRET

const GITHUB_API = 'https://api.github.com';
const TEMPLATE_FILES = {
  "profile.json": JSON.stringify({
    username: "", uuid: "", skinUrl: "", capeUrl: "", provider: "", createdAt: "", lastLogin: ""
  }, null, 2),
  "settings.json": JSON.stringify({
    theme: "light", vsync: true, fov: 75, guiScale: 3, sensitivity: 0.5, language: "en_US",
    video: { renderDistance: 8, brightness: 1.0, fullscreen: false, smoothLighting: true, graphics: "fancy" },
    audio: { master: 100, music: 70, weather: 80, blocks: 80, mobs: 85 },
    keybinds: { forward: "W", back: "S", left: "A", right: "D", jump: "SPACE", inventory: "E" },
    resourcePacks: { enabled: [], order: [] }, shaderPack: "", selectedVersion: ""
  }, null, 2),
  "servers.json": JSON.stringify({ servers: [], favorites: [], lastPlayed: "" }, null, 2),
  "friends.json": JSON.stringify({ friends: [], blocked: [], requests: [] }, null, 2),
  "progress.json": JSON.stringify({ achievements: [], stats: {}, level: 1, xp: 0, purchases: [] }, null, 2),
  "registry/versions.json": JSON.stringify({ installed: [], activeVersion: "" }, null, 2),
  "registry/version_index.json": JSON.stringify({ latest:{release:"1.21.9",snapshot:""}, versions:[] }, null, 2),
  "meta.json": JSON.stringify({ templateVersion: "1.0.0", lastSyncedAt: "" }, null, 2)
};

addEventListener('fetch', ev => ev.respondWith(router(ev.request, ev)));

async function router(request) {
  const url = new URL(request.url);
  const parts = url.pathname.split('/').filter(Boolean);

  try {
    // Public: download jar proxy (no auth)
    if (parts[0] === 'downloadJar' && parts[1] && request.method === 'GET') {
      return await handleDownloadJar(parts[1]);
    }

    // Auth endpoints
    if (parts[0] === 'auth' && parts[1] === 'login' && request.method === 'POST') {
      return await handleAuthLogin(request);
    }

    // From here on, require Authorization: Bearer <jwt>
    const authHeader = request.headers.get('Authorization') || '';
    const token = authHeader.replace('Bearer ', '').trim();
    if (!token) return new Response('Unauthorized', { status: 401 });

    const payload = await verifyJwt(token, env.JWT_SECRET || JWT_SECRET_FROM_ENV()); // env injection in workers
    const uid = payload.uid;
    if (!uid) return new Response('Invalid token payload', { status: 401 });

    // Route: /player/:uid/...
    if (parts[0] !== 'player') return new Response('Not found', { status: 404 });
    const requestedUid = parts[1];
    if (requestedUid !== uid) return new Response('Forbidden: uid mismatch', { status: 403 });

    const basePath = `player-data/${encodeURIComponent(requestedUid)}/Eaglercraft Advanced Player Settings`;

    // GET all main files
    if (request.method === 'GET' && parts.length === 2) {
      return await getAllMainFiles(basePath);
    }

    // GET single file
    if (request.method === 'GET' && parts.length >= 3) {
      const sub = parts.slice(2).join('/');
      return await getFileFromGitHubAsRaw(`${basePath}/${sub}`);
    }

    // POST install version
    if (request.method === 'POST' && parts.length === 4 && parts[2] === 'install') {
      const versionId = parts[3];
      return await installVersionForUser(requestedUid, versionId, basePath);
    }

    // POST write file
    if (request.method === 'POST' && parts.length >= 3) {
      const sub = parts.slice(2).join('/');
      const bodyText = await request.text();
      return await putFileToGitHub(`${basePath}/${sub}`, bodyText, `Sync write ${sub} for ${requestedUid}`);
    }

    return new Response('Method not allowed', { status: 405 });
  } catch (err) {
    return new Response(JSON.stringify({ error: err.message }), { status: 500, headers: { 'Content-Type': 'application/json' }});
  }
}

/* --------- AUTH: Login endpoint --------- */
// Body: { "email": "user@example.com" }
// Response: { token: "<jwt>", uid: "<uid>" }
async function handleAuthLogin(request) {
  const raw = await request.text();
  let body = {};
  try { body = JSON.parse(raw); } catch(e) { return new Response('Bad request', { status: 400 }); }
  if (!body.email) return new Response('Missing email', { status: 400 });

  const uid = body.email.toLowerCase(); // canonical uid; you can change mapping if you prefer
  // Ensure template exists for this uid; create initial files if missing
  await ensurePlayerTemplateExists(uid);

  // Issue JWT (HMAC-SHA256) with uid and exp
  const token = await signJwt({ uid }, 7 * 24 * 60 * 60); // 7 days
  return new Response(JSON.stringify({ token, uid }), { headers: { 'Content-Type': 'application/json' }});
}

/* --------- Template bootstrap: create default files under player's folder if not exists --------- */
async function ensurePlayerTemplateExists(uid) {
  const basePath = `player-data/${uid}/Eaglercraft Advanced Player Settings`;
  // For each key in TEMPLATE_FILES, attempt to GET, if 404 -> PUT
  for (const [relPath, content] of Object.entries(TEMPLATE_FILES)) {
    const fullPath = `${basePath}/${relPath}`;
    try {
      const url = `${GITHUB_API}/repos/${GITHUB_OWNER()}/${GITHUB_REPO()}/contents/${encodeURIComponent(fullPath)}`;
      const getRes = await fetch(url, { headers: ghHeaders() });
      if (getRes.status === 404) {
        // create parent directories via path in GitHub API — GitHub will create path as needed by PUT
        await putFileToGitHubSimple(fullPath, content, `Init ${relPath} for ${uid}`);
      }
      // if exists, do nothing
    } catch (e) {
      // ignore errors to avoid failing login; better to log in real system
      // but still try next files
    }
  }
}

/* --------- JWT helpers (HMAC SHA-256) --------- */
async function signJwt(payloadObj, expiresInSeconds=3600) {
  const header = { alg: "HS256", typ: "JWT" };
  const now = Math.floor(Date.now()/1000);
  const payload = Object.assign({}, payloadObj, { iat: now, exp: now + expiresInSeconds, iss: "eaglercraft-worker" });
  const enc = (o) => base64UrlEncode(new TextEncoder().encode(JSON.stringify(o)));
  const headerB64 = enc(header);
  const payloadB64 = enc(payload);
  const toSign = `${headerB64}.${payloadB64}`;
  const sig = await hmacSha256Sign(toSign, JWT_SECRET_FROM_ENV());
  return `${toSign}.${base64UrlEncode(sig)}`;
}

async function verifyJwt(token, jwtSecret) {
  // token -> verify signature + exp
  const parts = token.split('.');
  if (parts.length !== 3) throw new Error('Invalid token');
  const [headerB64, payloadB64, sigB64] = parts;
  const toSign = `${headerB64}.${payloadB64}`;
  const expectedSig = await hmacSha256Sign(toSign, jwtSecret);
  const sig = base64UrlDecodeToUint8Array(sigB64);
  if (!constantTimeCompare(expectedSig, sig)) throw new Error('Invalid token signature');
  const payloadJson = JSON.parse(new TextDecoder().decode(base64UrlDecodeToUint8Array(payloadB64)));
  const now = Math.floor(Date.now()/1000);
  if (payloadJson.exp && payloadJson.exp < now) throw new Error('Token expired');
  return payloadJson;
}

async function hmacSha256Sign(message, secret) {
  const key = await crypto.subtle.importKey('raw', new TextEncoder().encode(secret), { name:'HMAC', hash:'SHA-256' }, false, ['sign']);
  const sig = await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(message));
  return new Uint8Array(sig);
}

function constantTimeCompare(a, b) {
  if (a.length !== b.length) return false;
  let res = 0;
  for (let i=0;i<a.length;i++) res |= a[i] ^ b[i];
  return res === 0;
}

/* --------- GitHub helpers --------- */
function ghHeaders() {
  return { Authorization: `token ${GITHUB_TOKEN_FROM_ENV()}`, Accept: 'application/vnd.github.v3+json' };
}
function GITHUB_OWNER() { return GITHUB_OWNER_FROM_ENV(); }
function GITHUB_REPO() { return GITHUB_REPO_FROM_ENV(); }

async function getFileFromGitHubAsRaw(path) {
  const url = `${GITHUB_API}/repos/${GITHUB_OWNER()}/${GITHUB_REPO()}/contents/${encodeURIComponent(path)}`;
  const res = await fetch(url, { headers: { Authorization: `token ${GITHUB_TOKEN_FROM_ENV()}`, Accept: 'application/vnd.github.v3.raw' }});
  if (res.status === 404) return new Response(JSON.stringify({ exists: false }), { status: 404, headers: {'Content-Type':'application/json'}});
  if (!res.ok) throw new Error('GitHub GET failed: ' + res.status);
  const txt = await res.text();
  return new Response(txt, { status: 200, headers: { 'Content-Type': 'application/json' }});
}

async function getAllMainFiles(basePath) {
  const files = ['profile.json','settings.json','servers.json','friends.json','progress.json','meta.json','registry/versions.json','registry/version_index.json'];
  const out = {};
  for (const f of files) {
    try {
      const url = `${GITHUB_API}/repos/${GITHUB_OWNER()}/${GITHUB_REPO()}/contents/${encodeURIComponent(basePath + '/' + f)}`;
      const res = await fetch(url, { headers: { Authorization: `token ${GITHUB_TOKEN_FROM_ENV()}`, Accept: 'application/vnd.github.v3.raw' }});
      if (res.ok) out[f] = await res.text(); else out[f] = null;
    } catch (e) { out[f] = null; }
  }
  return new Response(JSON.stringify(out), { headers: { 'Content-Type': 'application/json' }});
}

async function putFileToGitHub(path, bodyText, message) {
  // get existing to obtain sha
  const getUrl = `${GITHUB_API}/repos/${GITHUB_OWNER()}/${GITHUB_REPO()}/contents/${encodeURIComponent(path)}`;
  const existing = await fetch(getUrl, { headers: { Authorization: `token ${GITHUB_TOKEN_FROM_ENV()}`, Accept: 'application/vnd.github.v3+json' }});
  let sha;
  if (existing.ok) {
    const exJson = await existing.json();
    sha = exJson.sha;
  }
  const contentBase64 = base64EncodeUnicode(bodyText);
  const payload = { message, content: contentBase64, committer: { name:'Eaglercraft-Sync', email:'noreply@ckwebgaming.com' } };
  if (sha) payload.sha = sha;
  const putRes = await fetch(getUrl, {
    method: 'PUT',
    headers: { Authorization: `token ${GITHUB_TOKEN_FROM_ENV()}`, Accept:'application/vnd.github.v3+json', 'Content-Type':'application/json' },
    body: JSON.stringify(payload)
  });
  if (!putRes.ok) {
    const txt = await putRes.text();
    throw new Error('GitHub PUT failed: ' + putRes.status + ' ' + txt);
  }
  const json = await putRes.json();
  // optional backup (not strict)
  return new Response(JSON.stringify({ ok:true, result: json }), { headers: {'Content-Type':'application/json'}});
}

async function putFileToGitHubSimple(path, bodyText, message) {
  const url = `${GITHUB_API}/repos/${GITHUB_OWNER()}/${GITHUB_REPO()}/contents/${encodeURIComponent(path)}`;
  const contentBase64 = base64EncodeUnicode(bodyText);
  const payload = { message, content: contentBase64, committer: { name:'Eaglercraft-Sync', email:'noreply@ckwebgaming.com' } };
  await fetch(url, { method:'PUT', headers: { Authorization:`token ${GITHUB_TOKEN_FROM_ENV()}`, Accept:'application/vnd.github.v3+json', 'Content-Type':'application/json' }, body: JSON.stringify(payload) });
}

/* --------- Install version metadata (scrape mcversions page for jar URL) --------- */
async function installVersionForUser(uid, versionId, basePath) {
  const pageUrl = `https://mcversions.net/download/${encodeURIComponent(versionId)}`;
  const pageRes = await fetch(pageUrl);
  if (!pageRes.ok) return new Response('Failed to fetch version page', { status: 500 });
  const html = await pageRes.text();
  const jarUrl = extractJarURL(html);
  if (!jarUrl) return new Response('Jar URL not found', { status: 500 });

  const metadata = { id: versionId, mainClass: "com.eagler.Main", download: { game: { url: jarUrl } }, fetchedAt: new Date().toISOString() };
  const versionFolder = `${basePath}/versions/${versionId}`;
  await putFileToGitHubSimple(`${versionFolder}/metadata.json`, JSON.stringify(metadata, null, 2), `Install metadata ${versionId} for ${uid}`);

  // update registry/versions.json
  const verPath = `${basePath}/registry/versions.json`;
  // attempt to get existing
  const getUrl = `${GITHUB_API}/repos/${GITHUB_OWNER()}/${GITHUB_REPO()}/contents/${encodeURIComponent(verPath)}`;
  const existing = await fetch(getUrl, { headers: { Authorization: `token ${GITHUB_TOKEN_FROM_ENV()}`, Accept:'application/vnd.github.v3+json' }});
  let versionsJson = { installed: [versionId], activeVersion: versionId };
  if (existing.ok) {
    const ex = await existing.json();
    const raw = atob(ex.content.replace(/\n/g,''));
    versionsJson = JSON.parse(raw);
    if (!versionsJson.installed.includes(versionId)) versionsJson.installed.push(versionId);
    versionsJson.activeVersion = versionId;
  }
  await putFileToGitHubSimple(verPath, JSON.stringify(versionsJson, null, 2), `Update installed versions for ${uid}`);

  // update meta
  await putFileToGitHubSimple(`${basePath}/meta.json`, JSON.stringify({ templateVersion:"1.0.0", lastSyncedAt: new Date().toISOString() }, null, 2), `Meta update for ${uid}`);

  return new Response(JSON.stringify({ ok:true, version:versionId, jarUrl }), { headers: { 'Content-Type': 'application/json' }});
}

/* --------- jar extraction & proxy --------- */
function extractJarURL(html) {
  const regex = /(https:\/\/piston-data\.mojang\.com\/v1\/objects\/[a-f0-9]+\/server\.jar)/i;
  const m = html.match(regex);
  return m ? m[1] : null;
}
async function handleDownloadJar(version) {
  const pageUrl = `https://mcversions.net/download/${encodeURIComponent(version)}`;
  const pageRes = await fetch(pageUrl);
  if (!pageRes.ok) return new Response('Failed to fetch version page', { status: 500 });
  const html = await pageRes.text();
  const jarUrl = extractJarURL(html);
  if (!jarUrl) return new Response('Jar not found', { status: 500 });

  const jarRes = await fetch(jarUrl);
  if (!jarRes.ok) return new Response('Failed download jar', { status: 502 });
  const headers = new Headers();
  headers.set('Content-Type', 'application/java-archive');
  headers.set('Content-Disposition', `attachment; filename="minecraft-${version}.jar"`);
  return new Response(jarRes.body, { status: 200, headers });
}

/* --------- Utilities: base64url, encoding helpers, env getters --------- */
function base64UrlEncode(uint8orString) {
  if (uint8orString instanceof Uint8Array) {
    let s = '';
    for (let i=0;i<uint8orString.length;i++) s += String.fromCharCode(uint8orString[i]);
    return btoa(s).replace(/\+/g,'-').replace(/\//g,'_').replace(/=+$/,'');
  } else {
    return btoa(typeof uint8orString === 'string' ? uint8orString : new TextDecoder().decode(uint8orString)).replace(/\+/g,'-').replace(/\//g,'_').replace(/=+$/,'');
  }
}
function base64EncodeUnicode(str) {
  return btoa(unescape(encodeURIComponent(str)));
}
function base64UrlDecodeToUint8Array(b64url) {
  let s = b64url.replace(/-/g,'+').replace(/_/g,'/');
  while (s.length % 4) s += '=';
  const raw = atob(s);
  const arr = new Uint8Array(raw.length);
  for (let i=0;i<raw.length;i++) arr[i] = raw.charCodeAt(i);
  return arr;
}

// FALLBACK env getters (for non-module envs) — Worker runtime provides env in `globalThis`
function GITHUB_TOKEN_FROM_ENV(){ return typeof GITHUB_TOKEN !== 'undefined' ? GITHUB_TOKEN : (globalThis.GITHUB_TOKEN || ''); }
function GITHUB_OWNER_FROM_ENV(){ return typeof GITHUB_OWNER !== 'undefined' ? GITHUB_OWNER : (globalThis.GITHUB_OWNER || ''); }
function GITHUB_REPO_FROM_ENV(){ return typeof GITHUB_REPO !== 'undefined' ? GITHUB_REPO : (globalThis.GITHUB_REPO || ''); }
function JWT_SECRET_FROM_ENV(){ return typeof JWT_SECRET !== 'undefined' ? JWT_SECRET : (globalThis.JWT_SECRET || 'change_this_secret'); }
