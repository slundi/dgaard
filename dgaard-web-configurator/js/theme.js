// Theme handling, intentionally identical in behaviour to the monitor SPA
// (dgaard-monitor-rest/assets/index.html): dark tokens live on `:root`, the
// system preference is applied through `prefers-color-scheme`, and an explicit
// choice is forced with `data-theme`. The storage key is shared on purpose so
// both UIs agree when served from the same origin.

export const THEME_STORAGE_KEY = 'dgaard-theme';
export const THEME_ORDER = ['system', 'light', 'dark'];

export function readTheme() {
  try {
    const stored = localStorage.getItem(THEME_STORAGE_KEY);
    return THEME_ORDER.includes(stored) ? stored : 'system';
  } catch {
    return 'system';
  }
}

export function applyTheme(theme) {
  const root = document.documentElement;
  if (theme === 'system') {
    root.removeAttribute('data-theme');
  } else {
    root.setAttribute('data-theme', theme);
  }
  try {
    localStorage.setItem(THEME_STORAGE_KEY, theme);
  } catch {
    // Private-browsing mode: the theme simply does not persist.
  }
}

export function nextTheme(theme) {
  const index = THEME_ORDER.indexOf(theme);
  return THEME_ORDER[(index + 1) % THEME_ORDER.length];
}

/// Wire a button that cycles system → light → dark and reflects the state in
/// `labelElement`.
export function initThemeToggle(button, labelElement) {
  let current = readTheme();
  const paint = () => {
    applyTheme(current);
    if (labelElement) labelElement.textContent = current;
  };
  paint();
  button.addEventListener('click', () => {
    current = nextTheme(current);
    paint();
  });
}
