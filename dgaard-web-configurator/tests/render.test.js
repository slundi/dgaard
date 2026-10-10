// Exercises the real render path against a stub DOM, so a broken widget or a
// bad selector fails here instead of in the browser.

import assert from 'node:assert/strict';
import { after, before, test } from 'node:test';
import { applySearch, renderForm, renderNav, updateModifiedMarks } from '../js/render.js';
import { ENGINE_SCHEMA } from '../js/schema/engine.js';
import { MONITOR_SCHEMA } from '../js/schema/monitor.js';
import { Store } from '../js/store.js';
import { createRoot, installDom } from './dom-stub.js';

let teardown;
before(() => {
  teardown = installDom();
});
after(() => teardown());

const makeStore = () => new Store({ engine: ENGINE_SCHEMA, monitor: MONITOR_SCHEMA });

function renderInto(schema, store) {
  const host = createRoot();
  renderForm(host, schema, store);
  return host;
}

test('both schemas render without throwing', () => {
  const store = makeStore();
  for (const schema of [ENGINE_SCHEMA, MONITOR_SCHEMA]) {
    const host = renderInto(schema, store);
    assert.equal(host.querySelectorAll('.section').length, schema.sections.length);
  }
});

test('every non-repeatable field gets a row', () => {
  const store = makeStore();
  const expected = ENGINE_SCHEMA.sections
    .filter((section) => !section.repeatable)
    .reduce((total, section) => total + section.fields.length, 0);

  const host = renderInto(ENGINE_SCHEMA, store);
  assert.equal(host.querySelectorAll('.field[data-key]').length, expected);
});

test('a widget writes straight into the store', () => {
  const store = makeStore();
  const host = renderInto(ENGINE_SCHEMA, store);

  const row = host.querySelector('[data-key="cache.max_entries"]');
  const input = row.querySelector('input');
  input.value = '2000';
  input.dispatch('input');

  assert.equal(store.get('engine', 'cache.max_entries'), 2000);
});

test('a boolean switch reflects its new state in the caption', () => {
  const store = makeStore();
  const host = renderInto(ENGINE_SCHEMA, store);

  const row = host.querySelector('[data-key="cache.enabled"]');
  const input = row.querySelector('input');
  input.checked = false;
  input.dispatch('change');

  assert.equal(store.get('engine', 'cache.enabled'), false);
  const caption = row.querySelectorAll('span').find((node) => node.textContent === 'disabled');
  assert.ok(caption, 'the switch caption did not follow the toggle');
});

test('an unset optional key renders disabled and enables when toggled on', () => {
  const store = makeStore();
  const host = renderInto(ENGINE_SCHEMA, store);

  const row = host.querySelector('[data-key="server.metrics_listen"]');
  const [toggle, text] = row.querySelectorAll('input');
  assert.equal(toggle.checked, false);
  assert.equal(text.disabled, true, 'the value input should start disabled');

  toggle.checked = true;
  toggle.dispatch('change');

  assert.equal(text.disabled, false, 'the value input should enable with the toggle');
  assert.equal(store.get('engine', 'server.metrics_listen'), '127.0.0.1:9153');

  toggle.checked = false;
  toggle.dispatch('change');
  assert.equal(store.get('engine', 'server.metrics_listen'), null);
  assert.equal(text.disabled, true);
});

test('the reset button clears the override and rebuilds the row', () => {
  const store = makeStore();
  const host = renderInto(ENGINE_SCHEMA, store);

  const row = host.querySelector('[data-key="cache.max_entries"]');
  const input = row.querySelector('input');
  input.value = '2000';
  input.dispatch('input');
  assert.ok(store.isModified('engine', 'cache.max_entries'));

  const reset = row.querySelectorAll('button').find((node) => node.className.includes('reset'));
  reset.dispatch('click');

  assert.equal(store.isModified('engine', 'cache.max_entries'), false);
  const rebuilt = host.querySelector('[data-key="cache.max_entries"]');
  assert.equal(rebuilt.querySelector('input').value, '10000');
});

test('adding and removing a repeatable entry round-trips through the store', () => {
  const store = makeStore();
  const host = renderInto(ENGINE_SCHEMA, store);

  const section = host.querySelector('[data-path="overrides"]');
  const add = section.querySelectorAll('button').find((node) => node.textContent === '+ add entry');
  add.dispatch('click');

  assert.deepEqual(store.get('engine', 'overrides'), [{ domain: 'nas.home', to: '192.168.1.50' }]);

  const entry = host.querySelector('[data-path="overrides"]').querySelector('.entry');
  const [domain] = entry.querySelectorAll('input');
  domain.value = 'printer.home';
  domain.dispatch('input');
  assert.equal(store.get('engine', 'overrides')[0].domain, 'printer.home');

  const remove = entry.querySelector('.entry-head').querySelector('button');
  remove.dispatch('click');
  assert.deepEqual(store.get('engine', 'overrides'), []);
});

test('the pipeline editor drops unchecked steps and keeps the order', () => {
  const store = makeStore();
  const host = renderInto(ENGINE_SCHEMA, store);

  const row = host.querySelector('[data-key="server.pipeline"]');
  const steps = row.querySelectorAll('.pipeline-step');
  assert.equal(steps.length, 6);

  const heuristics = steps[4].querySelector('input');
  heuristics.checked = false;
  heuristics.dispatch('change');

  assert.deepEqual(store.get('engine', 'server.pipeline'), [
    'Whitelist',
    'HotCache',
    'StaticBlock',
    'SuffixMatch',
    'Upstream',
  ]);
});

test('a chip list adds a pasted blob as separate items', () => {
  const store = makeStore();
  const host = renderInto(ENGINE_SCHEMA, store);

  const row = host.querySelector('[data-key="security.lexical.banned_keywords"]');
  const input = row.querySelector('input');
  input.value = 'casino, gambling porn';
  input.dispatch('keydown', { key: 'Enter' });

  assert.deepEqual(store.get('engine', 'security.lexical.banned_keywords'), [
    'casino',
    'gambling',
    'porn',
  ]);
});

test('nav items mark the sections that carry an override', () => {
  const store = makeStore();
  const host = renderInto(ENGINE_SCHEMA, store);
  const nav = createRoot();
  renderNav(nav, ENGINE_SCHEMA, store);

  const cacheItem = nav.querySelectorAll('.nav-item').find((node) => node.dataset.path === 'cache');
  assert.equal(cacheItem.classList.contains('modified'), false);

  store.set('engine', 'cache.enabled', false);
  updateModifiedMarks(nav, ENGINE_SCHEMA, store, host);

  assert.ok(cacheItem.classList.contains('modified'));
  assert.ok(host.querySelector('[data-key="cache.enabled"]').classList.contains('modified'));
});

test('search hides non-matching fields and empty sections', () => {
  const store = makeStore();
  const host = renderInto(ENGINE_SCHEMA, store);

  applySearch(host, 'entropy');
  const visible = host
    .querySelectorAll('.field')
    .filter((row) => !row.classList.contains('hidden'));
  assert.ok(visible.length > 0);
  assert.ok(visible.every((row) => row.dataset.search.includes('entropy')));

  const cacheSection = host.querySelector('[data-path="cache"]');
  assert.ok(cacheSection.classList.contains('hidden'));

  applySearch(host, '');
  assert.equal(host.querySelectorAll('.field.hidden').length, 0);
  assert.equal(cacheSection.classList.contains('hidden'), false);
});
