const api = typeof globalThis.browser !== 'undefined' ? globalThis.browser : globalThis.chrome;

const DEFAULTS = { restUrl: 'http://127.0.0.1:8080', bearerToken: '', monitorUrl: '' };
const LOCALHOST_RE = /^https?:\/\/(127\.0\.0\.1|localhost)(:\d+)?/;

const restUrlInput    = document.getElementById('rest-url');
const bearerInput     = document.getElementById('bearer-token');
const monitorUrlInput = document.getElementById('monitor-url');
const statusMsg       = document.getElementById('status-msg');
const remoteWarning   = document.getElementById('remote-warning');

// ── Load saved settings ───────────────────────────────────────────────────────

async function loadSettings() {
  const settings = await api.storage.local.get(DEFAULTS);
  restUrlInput.value    = settings.restUrl;
  bearerInput.value     = settings.bearerToken;
  monitorUrlInput.value = settings.monitorUrl;
  toggleRemoteWarning(settings.restUrl);
}

// ── Remote URL warning ────────────────────────────────────────────────────────

function toggleRemoteWarning(url) {
  remoteWarning.hidden = LOCALHOST_RE.test(url.trim());
}

restUrlInput.addEventListener('input', () => {
  toggleRemoteWarning(restUrlInput.value);
});

// ── Save ──────────────────────────────────────────────────────────────────────

document.getElementById('settings-form').addEventListener('submit', async e => {
  e.preventDefault();
  await api.storage.local.set({
    restUrl:      restUrlInput.value.trim() || DEFAULTS.restUrl,
    bearerToken:  bearerInput.value,
    monitorUrl:   monitorUrlInput.value.trim(),
  });
  showStatus('Saved.', 'ok');
});

// ── Test connection ───────────────────────────────────────────────────────────

document.getElementById('btn-test').addEventListener('click', async () => {
  const restUrl     = restUrlInput.value.trim() || DEFAULTS.restUrl;
  const bearerToken = bearerInput.value;

  showStatus('Testing…', null);

  try {
    const headers = { 'Content-Type': 'application/json' };
    if (bearerToken) headers['Authorization'] = `Bearer ${bearerToken}`;

    const res = await fetch(`${restUrl}/api/v1/check`, {
      method: 'POST',
      headers,
      body: JSON.stringify({ domain: 'example.com' }),
    });

    if (res.status === 401 || res.status === 403) {
      return showStatus('Authentication failed — check your bearer token.', 'err');
    }
    if (!res.ok) {
      return showStatus(`HTTP ${res.status} — unexpected response.`, 'err');
    }

    const data = await res.json();
    if (typeof data.score !== 'number') {
      return showStatus('Connected, but response looks wrong.', 'err');
    }
    showStatus(`Connected. example.com → score ${data.score}`, 'ok');
  } catch {
    showStatus(`Cannot reach ${restUrl} — is dgaard-rest running?`, 'err');
  }
});

// ── Status helper ─────────────────────────────────────────────────────────────

function showStatus(text, type) {
  statusMsg.textContent = text;
  statusMsg.className = type ? `status-msg ${type}` : 'status-msg';
  statusMsg.hidden = false;
  if (type) {
    setTimeout(() => { statusMsg.hidden = true; }, 4000);
  }
}

loadSettings();
