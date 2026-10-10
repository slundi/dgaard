import assert from 'node:assert/strict';
import { test } from 'node:test';
import { ENGINE_SCHEMA } from '../js/schema/engine.js';
import { MONITOR_SCHEMA } from '../js/schema/monitor.js';
import { Store } from '../js/store.js';
import { emitToml, formatAssignment, formatFloat, formatString } from '../js/toml-emit.js';

const makeStore = () => new Store({ engine: ENGINE_SCHEMA, monitor: MONITOR_SCHEMA });

test('strings are escaped the way the TOML spec requires', () => {
  assert.equal(formatString('plain'), '"plain"');
  assert.equal(formatString('with "quotes"'), '"with \\"quotes\\""');
  assert.equal(formatString('C:\\path'), '"C:\\\\path"');
  assert.equal(formatString('a\nb\tc'), '"a\\nb\\tc"');
});

test('floats always carry a decimal point', () => {
  // The Rust get_float accepts integers, but `entropy_threshold = 4` reads as
  // an int and misleads anyone editing the file by hand.
  assert.equal(formatFloat(4), '4.0');
  assert.equal(formatFloat(-4), '-4.0');
  assert.equal(formatFloat(0.15), '0.15');
});

test('arrays stay inline while they fit and break by width, not item count', () => {
  const tlds = { key: 'exclude', type: 'tld-list' };
  assert.equal(formatAssignment(tlds, ['top', 'xyz']), 'exclude = ["top", "xyz"]');
  // Six short items still fit on one line.
  assert.equal(
    formatAssignment(tlds, ['top', 'xyz', 'bid', 'country', 'stream', 'gdn']),
    'exclude = ["top", "xyz", "bid", "country", "stream", "gdn"]',
  );

  const sources = { key: 'blacklists', type: 'source-list' };
  const long = formatAssignment(sources, [
    'https://easylist.to/easylist/easylist.txt',
    '/etc/dgaard/lists/malware_domains.txt',
  ]);
  assert.ok(long.startsWith('blacklists = [\n'));
  assert.ok(long.includes('\n  "https://easylist.to/easylist/easylist.txt",\n'));
  assert.ok(long.endsWith('\n]'));
});

test('integer lists are emitted as numbers, not strings', () => {
  const field = { key: 'blocked_types', type: 'int-list' };
  assert.equal(formatAssignment(field, [10, 13, 255]), 'blocked_types = [10, 13, 255]');
  assert.equal(formatAssignment(field, [10, 13, 252, 255]), 'blocked_types = [10, 13, 252, 255]');
});

test('minimal output of an untouched config is a single comment', () => {
  const store = makeStore();
  const output = emitToml(ENGINE_SCHEMA, store, 'minimal');
  assert.equal(output, '# config.toml — every value is at its default.\n');
});

test('minimal output contains only what was changed', () => {
  const store = makeStore();
  store.set('engine', 'server.listen_addr', '192.168.1.1:53');
  store.set('engine', 'security.lexical.banned_keywords', ['casino', 'porn']);

  const output = emitToml(ENGINE_SCHEMA, store, 'minimal');
  assert.equal(
    output,
    [
      '[server]',
      'listen_addr = "192.168.1.1:53"',
      '',
      '[security.lexical]',
      'banned_keywords = ["casino", "porn"]',
      '',
    ].join('\n'),
  );
});

test('minimal output carries no comments at all', () => {
  const store = makeStore();
  store.set('engine', 'cache.max_entries', 2000);
  const output = emitToml(ENGINE_SCHEMA, store, 'minimal');
  assert.ok(!output.includes('#'), output);
});

test('annotated output documents every section and key', () => {
  const store = makeStore();
  const output = emitToml(ENGINE_SCHEMA, store, 'annotated');

  for (const section of ENGINE_SCHEMA.sections) {
    const header = section.repeatable ? `[[${section.path}]]` : `[${section.path}]`;
    assert.ok(output.includes(header), `missing section header ${header}`);
  }
  assert.ok(output.includes('listen_addr = "127.0.0.1:53"'));
  assert.ok(output.includes('# Shannon entropy threshold'));
});

test('an unset optional key is emitted commented-out, with a usable example', () => {
  const store = makeStore();
  const output = emitToml(ENGINE_SCHEMA, store, 'annotated');
  assert.ok(output.includes('# metrics_listen = "127.0.0.1:9153"'));
  assert.ok(!output.includes('\nmetrics_listen ='));

  store.set('engine', 'server.metrics_listen', '0.0.0.0:9153');
  const enabled = emitToml(ENGINE_SCHEMA, store, 'annotated');
  assert.ok(enabled.includes('\nmetrics_listen = "0.0.0.0:9153"'));
});

test('an unset optional key never reaches minimal output', () => {
  const store = makeStore();
  store.set('engine', 'server.metrics_listen', '0.0.0.0:9153');
  store.set('engine', 'server.metrics_listen', null);
  assert.ok(!emitToml(ENGINE_SCHEMA, store, 'minimal').includes('metrics_listen'));
});

test('worker_threads emits "auto" as a string and a count as an integer', () => {
  const store = makeStore();
  assert.ok(emitToml(ENGINE_SCHEMA, store, 'annotated').includes('worker_threads = "auto"'));

  store.set('engine', 'server.runtime.worker_threads', 1);
  assert.ok(emitToml(ENGINE_SCHEMA, store, 'minimal').includes('worker_threads = 1'));
});

test('array-of-tables entries are emitted after their header', () => {
  const store = makeStore();
  store.set('engine', 'overrides', [
    { domain: 'nas.home', to: '192.168.1.50' },
    { domain: '*.internal.corp', to: '10.0.0.1' },
  ]);

  const output = emitToml(ENGINE_SCHEMA, store, 'minimal');
  assert.equal(
    output,
    [
      '[[overrides]]',
      'domain = "nas.home"',
      'to = "192.168.1.50"',
      '',
      '[[overrides]]',
      'domain = "*.internal.corp"',
      'to = "10.0.0.1"',
      '',
    ].join('\n'),
  );
});

test('an empty array-of-tables is shown as a commented template, not omitted', () => {
  const store = makeStore();
  const output = emitToml(ENGINE_SCHEMA, store, 'annotated');
  assert.ok(output.includes('# [[overrides]]'));
  assert.ok(output.includes('# domain = "nas.home"'));
  assert.ok(!emitToml(ENGINE_SCHEMA, store, 'minimal').includes('overrides'));
});

test('custom_flags entries keep their optional keys in annotated mode only', () => {
  const store = makeStore();
  store.set('engine', 'security.custom_flags', [
    { bit: 16, code: 'HONEYPOT', name: '', description: '', suspicious_score: 1, list_path: [] },
  ]);

  const minimal = emitToml(ENGINE_SCHEMA, store, 'minimal');
  assert.ok(minimal.includes('bit = 16'));
  assert.ok(minimal.includes('code = "HONEYPOT"'));
  assert.ok(!minimal.includes('description ='), minimal);

  const annotated = emitToml(ENGINE_SCHEMA, store, 'annotated');
  assert.ok(annotated.includes('description = ""'));
});

test('the monitor file emits its own sections', () => {
  const store = makeStore();
  store.set('monitor', 'web.enabled', true);
  store.set('monitor', 'forwarding.filter', ['Blocked', 'Suspicious']);

  const output = emitToml(MONITOR_SCHEMA, store, 'minimal');
  assert.equal(
    output,
    ['[forwarding]', 'filter = ["Blocked", "Suspicious"]', '', '[web]', 'enabled = true', ''].join(
      '\n',
    ),
  );
});

test('every annotated line that is not a comment looks like an assignment or a header', () => {
  const store = makeStore();
  for (const schema of [ENGINE_SCHEMA, MONITOR_SCHEMA]) {
    const lines = emitToml(schema, store, 'annotated').split('\n');
    for (const line of lines) {
      if (line === '' || line.startsWith('#')) continue;
      const looksRight =
        /^\[\[?[\w.]+\]\]?$/.test(line) || /^\w+ = /.test(line) || /^(\s+.*,|\])$/.test(line);
      assert.ok(looksRight, `unexpected line in ${schema.file}: ${JSON.stringify(line)}`);
    }
  }
});
