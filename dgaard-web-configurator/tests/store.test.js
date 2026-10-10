import assert from 'node:assert/strict';
import { test } from 'node:test';
import { ENGINE_SCHEMA } from '../js/schema/engine.js';
import { MONITOR_SCHEMA } from '../js/schema/monitor.js';
import { deepEqual, indexFields, Store } from '../js/store.js';

const makeStore = () => new Store({ engine: ENGINE_SCHEMA, monitor: MONITOR_SCHEMA });

test('deepEqual handles the value shapes a config can hold', () => {
  assert.ok(deepEqual(1, 1));
  assert.ok(deepEqual('a', 'a'));
  assert.ok(deepEqual(null, null));
  assert.ok(deepEqual([1, 2], [1, 2]));
  assert.ok(deepEqual([{ domain: 'a', to: 'b' }], [{ domain: 'a', to: 'b' }]));
  assert.ok(!deepEqual([1, 2], [2, 1]));
  assert.ok(!deepEqual({ a: 1 }, { a: 1, b: 2 }));
  assert.ok(!deepEqual(null, 0));
});

test('indexFields exposes repeatable sections as a single list-valued key', () => {
  const index = indexFields(ENGINE_SCHEMA);
  assert.ok(index.has('server.listen_addr'));
  assert.ok(index.has('overrides'));
  assert.deepEqual(index.get('overrides').default, []);
});

test('reading an untouched key returns the schema default', () => {
  const store = makeStore();
  assert.equal(store.get('engine', 'server.listen_addr'), '127.0.0.1:53');
  assert.equal(store.isModified('engine', 'server.listen_addr'), false);
  assert.deepEqual(store.modifiedKeys('engine'), []);
});

test('setting a value back to its default clears the override', () => {
  const store = makeStore();
  store.set('engine', 'cache.max_entries', 2000);
  assert.deepEqual(store.modifiedKeys('engine'), ['cache.max_entries']);

  store.set('engine', 'cache.max_entries', 10000);
  assert.deepEqual(store.modifiedKeys('engine'), []);
});

test('array values compare structurally, not by identity', () => {
  const store = makeStore();
  const pipelineDefault = [
    'Whitelist',
    'HotCache',
    'StaticBlock',
    'SuffixMatch',
    'Heuristics',
    'Upstream',
  ];
  store.set('engine', 'server.pipeline', [...pipelineDefault]);
  assert.deepEqual(store.modifiedKeys('engine'), []);

  store.set('engine', 'server.pipeline', ['Whitelist', 'Upstream']);
  assert.ok(store.isModified('engine', 'server.pipeline'));
});

test('stored values are cloned, so later mutation cannot corrupt the state', () => {
  const store = makeStore();
  const keywords = ['casino'];
  store.set('engine', 'security.lexical.banned_keywords', keywords);
  keywords.push('mutated');
  assert.deepEqual(store.get('engine', 'security.lexical.banned_keywords'), ['casino']);
});

test('defaults are cloned, so a caller cannot mutate the schema', () => {
  const store = makeStore();
  const first = store.get('engine', 'forwarder.servers');
  first.push('8.8.8.8:53');
  assert.deepEqual(store.get('engine', 'forwarder.servers'), ['1.1.1.1:53', '9.9.9.9:53']);
});

test('sectionIsModified covers both plain and repeatable sections', () => {
  const store = makeStore();
  assert.equal(store.sectionIsModified('engine', 'cache'), false);

  store.set('engine', 'cache.enabled', false);
  assert.equal(store.sectionIsModified('engine', 'cache'), true);

  assert.equal(store.sectionIsModified('engine', 'overrides'), false);
  store.set('engine', 'overrides', [{ domain: 'nas.home', to: '192.168.1.50' }]);
  assert.equal(store.sectionIsModified('engine', 'overrides'), true);
});

test('a section prefix does not match a longer sibling path', () => {
  const store = makeStore();
  store.set('engine', 'server.runtime.stack_size', 8388608);
  // "server" legitimately contains "server.runtime"; "serve" must not match.
  assert.equal(store.sectionIsModified('engine', 'server.runtime'), true);
  assert.equal(store.sectionIsModified('engine', 'server'), true);
  assert.equal(store.sectionIsModified('engine', 'sources'), false);
});

test('replace drops unknown keys and values equal to the default', () => {
  const store = makeStore();
  store.replace('engine', {
    'cache.max_entries': 2000,
    'cache.enabled': true, // equals the default
    'nope.not_a_key': 1,
  });
  assert.deepEqual(store.modifiedKeys('engine'), ['cache.max_entries']);
});

test('patch merges on top of existing overrides', () => {
  const store = makeStore();
  store.set('engine', 'cache.max_entries', 2000);
  store.patch('engine', { 'server.runtime.worker_threads': 1 });
  assert.deepEqual(store.modifiedKeys('engine').sort(), [
    'cache.max_entries',
    'server.runtime.worker_threads',
  ]);
});

test('a round trip through JSON preserves the overrides', () => {
  const store = makeStore();
  store.set('engine', 'server.listen_addr', '192.168.1.1:53');
  store.set('engine', 'overrides', [{ domain: 'nas.home', to: '192.168.1.50' }]);
  store.set('monitor', 'web.enabled', true);

  const restored = makeStore();
  restored.fromJSON(JSON.parse(JSON.stringify(store.toJSON())));

  assert.equal(restored.get('engine', 'server.listen_addr'), '192.168.1.1:53');
  assert.deepEqual(restored.get('engine', 'overrides'), [
    { domain: 'nas.home', to: '192.168.1.50' },
  ]);
  assert.equal(restored.get('monitor', 'web.enabled'), true);
});

test('subscribers are notified on every mutation', () => {
  const store = makeStore();
  const seen = [];
  store.subscribe((fileId, key) => seen.push([fileId, key]));

  store.set('engine', 'cache.enabled', false);
  store.unset('engine', 'cache.enabled');
  store.resetFile('monitor');

  assert.deepEqual(seen, [
    ['engine', 'cache.enabled'],
    ['engine', 'cache.enabled'],
    ['monitor', null],
  ]);
});
