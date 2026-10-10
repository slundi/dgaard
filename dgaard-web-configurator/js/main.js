// Bootstrap: wire the store, the two schemas, the form, and the preview.

import { applySearch, renderForm, renderNav, updateModifiedMarks } from './render.js';
import { ENGINE_SCHEMA } from './schema/engine.js';
import { MONITOR_SCHEMA } from './schema/monitor.js';
import { attachDraftPersistence, loadDraft, STORAGE_KEYS, Store } from './store.js';
import { initThemeToggle } from './theme.js';
import { emitToml } from './toml-emit.js';

const SCHEMAS = { engine: ENGINE_SCHEMA, monitor: MONITOR_SCHEMA };

function readUiPrefs() {
  try {
    return JSON.parse(localStorage.getItem(STORAGE_KEYS.ui) ?? '{}');
  } catch {
    return {};
  }
}

function writeUiPrefs(prefs) {
  try {
    localStorage.setItem(STORAGE_KEYS.ui, JSON.stringify(prefs));
  } catch {
    // Private mode: preferences simply do not persist.
  }
}

function downloadText(filename, text) {
  const blob = new Blob([text], { type: 'text/plain;charset=utf-8' });
  const url = URL.createObjectURL(blob);
  const link = document.createElement('a');
  link.href = url;
  link.download = filename;
  link.click();
  URL.revokeObjectURL(url);
}

async function copyText(text, button) {
  const original = button.textContent;
  try {
    await navigator.clipboard.writeText(text);
    button.textContent = 'copied';
  } catch {
    button.textContent = 'copy failed';
  }
  setTimeout(() => {
    button.textContent = original;
  }, 1200);
}

function init() {
  const store = new Store(SCHEMAS);
  loadDraft(store);
  attachDraftPersistence(store);

  const prefs = readUiPrefs();
  let activeFile = SCHEMAS[prefs.activeFile] ? prefs.activeFile : 'engine';
  let outputMode = prefs.outputMode === 'minimal' ? 'minimal' : 'annotated';

  const host = document.getElementById('form-host');
  const nav = document.getElementById('side-nav');
  const previewBody = document.getElementById('preview-body');
  const previewTitle = document.getElementById('preview-title');
  const modifiedCount = document.getElementById('modified-count');
  const search = document.getElementById('field-search');

  initThemeToggle(document.getElementById('theme-toggle'), document.getElementById('theme-label'));

  const schema = () => SCHEMAS[activeFile];

  const refreshPreview = () => {
    const current = schema();
    previewTitle.textContent = current.file;
    previewBody.textContent = emitToml(current, store, outputMode);
    const changed = store.modifiedKeys(activeFile).length;
    modifiedCount.textContent = changed === 0 ? 'all defaults' : `${changed} changed`;
    updateModifiedMarks(nav, current, store, host);
  };

  const rebuild = () => {
    const current = schema();
    renderNav(nav, current, store);
    renderForm(host, current, store);
    applySearch(host, search.value);
    refreshPreview();
  };

  store.subscribe(refreshPreview);

  for (const tab of document.querySelectorAll('#tab-bar .tab')) {
    tab.addEventListener('click', () => {
      if (activeFile === tab.dataset.file) return;
      activeFile = tab.dataset.file;
      for (const other of document.querySelectorAll('#tab-bar .tab')) {
        other.classList.toggle('active', other === tab);
      }
      writeUiPrefs({ ...readUiPrefs(), activeFile });
      rebuild();
    });
    tab.classList.toggle('active', tab.dataset.file === activeFile);
  }

  for (const button of document.querySelectorAll('.mode-switch .mode')) {
    button.addEventListener('click', () => {
      outputMode = button.dataset.mode;
      for (const other of document.querySelectorAll('.mode-switch .mode')) {
        other.classList.toggle('active', other === button);
      }
      writeUiPrefs({ ...readUiPrefs(), outputMode });
      refreshPreview();
    });
    button.classList.toggle('active', button.dataset.mode === outputMode);
  }

  search.addEventListener('input', () => applySearch(host, search.value));

  document.getElementById('copy-btn').addEventListener('click', (event) => {
    copyText(emitToml(schema(), store, outputMode), event.currentTarget);
  });

  document.getElementById('download-btn').addEventListener('click', () => {
    downloadText(schema().file, emitToml(schema(), store, outputMode));
  });

  rebuild();
}

if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', init);
} else {
  init();
}
