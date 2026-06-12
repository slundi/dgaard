// Cross-browser API shim (Firefox exposes `browser`, Chrome exposes `chrome`)
const api = typeof globalThis.browser !== 'undefined' ? globalThis.browser : globalThis.chrome;

const DEFAULTS = { restUrl: 'http://127.0.0.1:8080', bearerToken: '', monitorUrl: '' };
const CACHE_TTL_MS = 5 * 60 * 1000;

// In-memory score cache; reset when the service worker is terminated.
const scoreCache = new Map();

async function getSettings() {
  return api.storage.local.get(DEFAULTS);
}

async function queryDomain(domain, { restUrl, bearerToken }) {
  const now = Date.now();
  const hit = scoreCache.get(domain);
  if (hit && hit.expiry > now) return hit.data;

  const headers = { 'Content-Type': 'application/json' };
  if (bearerToken) headers['Authorization'] = `Bearer ${bearerToken}`;

  const res = await fetch(`${restUrl}/api/v1/check`, {
    method: 'POST',
    headers,
    body: JSON.stringify({ domain }),
  });
  if (!res.ok) throw new Error(`HTTP ${res.status}`);

  const data = await res.json();
  scoreCache.set(domain, { data, expiry: now + CACHE_TTL_MS });
  return data;
}

// Badge text + colour thresholds
function badgeFor(data) {
  if (data.blocked)    return { text: '✗', color: '#e53e3e' };
  if (data.score === 0) return { text: '',  color: '#48bb78' };
  if (data.score <= 3)  return { text: String(data.score), color: '#d69e2e' };
  if (data.score <= 6)  return { text: String(data.score), color: '#ed8936' };
  return                       { text: String(data.score), color: '#e53e3e' };
}

function clearBadge(tabId) {
  api.action.setBadgeText({ tabId, text: '' }).catch(() => {});
}

async function updateBadge(tabId, url) {
  let hostname;
  try {
    hostname = new URL(url).hostname;
  } catch {
    return clearBadge(tabId);
  }
  if (!hostname) return clearBadge(tabId);

  try {
    const settings = await getSettings();
    const data = await queryDomain(hostname, settings);
    const { text, color } = badgeFor(data);
    await api.action.setBadgeText({ tabId, text });
    await api.action.setBadgeBackgroundColor({ tabId, color });
  } catch {
    clearBadge(tabId);
  }
}

api.tabs.onActivated.addListener(async ({ tabId }) => {
  try {
    const tab = await api.tabs.get(tabId);
    if (tab.url) await updateBadge(tabId, tab.url);
  } catch { /* tab may be gone */ }
});

api.tabs.onUpdated.addListener(async (tabId, changeInfo, tab) => {
  if (changeInfo.status === 'complete' && tab.url) {
    await updateBadge(tabId, tab.url);
  }
});
