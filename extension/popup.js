const api = typeof globalThis.browser !== 'undefined' ? globalThis.browser : globalThis.chrome;

const DEFAULTS = { restUrl: 'http://127.0.0.1:8080', bearerToken: '', monitorUrl: '' };

// ── DOM refs ─────────────────────────────────────────────────────────────────

const $ = id => document.getElementById(id);
const stateLoading     = $('state-loading');
const stateUnavailable = $('state-unavailable');
const stateError       = $('state-error');
const stateResult      = $('state-result');
const errorMsg         = $('error-msg');
const domainEl         = $('domain');
const scoreBadge       = $('score-badge');
const statusPill       = $('status-pill');
const actionEl         = $('action');
const reasonsSection   = $('reasons-section');
const reasonsList      = $('reasons-list');
const footer           = $('footer');
const monitorLink      = $('monitor-link');

// ── State display helpers ─────────────────────────────────────────────────────

function showOnly(el) {
  [stateLoading, stateUnavailable, stateError, stateResult].forEach(e => {
    e.hidden = e !== el;
  });
}

function scoreClass(score, blocked) {
  if (blocked || score > 6) return 'crit';
  if (score > 3)            return 'high';
  if (score > 0)            return 'warn';
  return 'safe';
}

function renderResult(data) {
  const cls = scoreClass(data.score, data.blocked);

  domainEl.textContent = data.domain;

  scoreBadge.textContent = data.score;
  scoreBadge.className = `score-badge ${cls}`;

  statusPill.textContent = data.blocked ? 'Blocked' : 'Allowed';
  statusPill.className = `status-pill ${data.blocked ? 'blocked' : 'allowed'}`;

  actionEl.textContent = data.action;

  if (data.reasons && data.reasons.length > 0) {
    reasonsList.innerHTML = '';
    data.reasons.forEach(r => {
      const chip = document.createElement('span');
      chip.className = 'reason-chip';
      chip.textContent = r;
      reasonsList.appendChild(chip);
    });
    reasonsSection.hidden = false;
  } else {
    reasonsSection.hidden = true;
  }

  showOnly(stateResult);
}

// ── Core logic ────────────────────────────────────────────────────────────────

async function run() {
  const settings = await api.storage.local.get(DEFAULTS);

  // Wire up monitor link
  if (settings.monitorUrl) {
    monitorLink.href = settings.monitorUrl;
    footer.hidden = false;
  }

  // Get the active tab's URL
  const [tab] = await api.tabs.query({ active: true, currentWindow: true });
  if (!tab?.url) return showOnly(stateUnavailable);

  let hostname;
  try {
    const url = new URL(tab.url);
    if (!['http:', 'https:'].includes(url.protocol)) return showOnly(stateUnavailable);
    hostname = url.hostname;
  } catch {
    return showOnly(stateUnavailable);
  }

  // Query dgaard-rest
  try {
    const headers = { 'Content-Type': 'application/json' };
    if (settings.bearerToken) headers['Authorization'] = `Bearer ${settings.bearerToken}`;

    const res = await fetch(`${settings.restUrl}/api/v1/check`, {
      method: 'POST',
      headers,
      body: JSON.stringify({ domain: hostname }),
    });

    if (res.status === 401 || res.status === 403) {
      errorMsg.textContent = 'Authentication failed — check the bearer token in Settings.';
      return showOnly(stateError);
    }
    if (!res.ok) {
      errorMsg.textContent = `dgaard-rest returned HTTP ${res.status}.`;
      return showOnly(stateError);
    }

    renderResult(await res.json());
  } catch (err) {
    const url = settings.restUrl;
    errorMsg.textContent = `Cannot reach dgaard-rest at ${url}.\n\nMake sure dgaard-rest is running, or update the URL in Settings.`;
    showOnly(stateError);
  }
}

// ── Wire up settings button ───────────────────────────────────────────────────

$('btn-settings').addEventListener('click', () => {
  if (api.runtime.openOptionsPage) {
    api.runtime.openOptionsPage();
  }
});

run();
