// The schema is a hand transcription of the Rust parsers, so it can drift the
// moment someone adds a key to dgaard. These tests compare the schema against
// the actual `get_*(table, "key")` calls in the Rust source, in both
// directions, so drift fails CI instead of silently producing configs that are
// missing a section.

import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { test } from 'node:test';
import { fileURLToPath } from 'node:url';

import { ENGINE_SCHEMA } from '../js/schema/engine.js';
import { MONITOR_SCHEMA } from '../js/schema/monitor.js';

const REPO_ROOT = fileURLToPath(new URL('../../', import.meta.url));

/// Strip the `#[cfg(test)] mod tests` block: its TOML fixtures mention keys
/// that are not part of the real schema (and some that belong to other crates).
function productionSource(relativePath) {
  const source = readFileSync(`${REPO_ROOT}${relativePath}`, 'utf8');
  const testModule = source.indexOf('#[cfg(test)]');
  return testModule === -1 ? source : source.slice(0, testModule);
}

/// Every key the parser reads: the `get_<helper>(table, "key")` calls, minus
/// the two helpers that descend into a sub-table rather than reading a value,
/// plus the bare `table.get("key")` lookups used for the union-typed fields
/// (`worker_threads`) and the hand-rolled enum arrays (`pipeline`).
function collectRustKeys(relativePath) {
  const source = productionSource(relativePath);
  const keys = new Set();

  const helperCall = /\bget_(\w+?)(?:::<[^>]*>)?\(\s*\w+\s*,\s*"([^"]+)"/g;
  for (const [, helper, key] of source.matchAll(helperCall)) {
    if (helper === 'table' || helper === 'table_array') continue;
    keys.add(key);
  }

  const directCall = /\.get\("([^"]+)"\)/g;
  for (const [, key] of source.matchAll(directCall)) keys.add(key);

  return keys;
}

function collectSchemaKeys(schema) {
  const keys = new Set();
  for (const section of schema.sections) {
    const fields = section.repeatable ? section.entry.fields : section.fields;
    for (const field of fields) keys.add(field.key);
  }
  return keys;
}

// `[upstream]` is looked up only so the parser can reject it with a pointer to
// `[forwarder]`; it is a tombstone, not a key the schema should carry.
const REJECTED_NAMES = new Set(['upstream']);

test('the rejected [upstream] section name is a tombstone, not a schema key', () => {
  const source = productionSource('dgaard-engine/src/config/parser.rs');
  assert.ok(
    source.includes('[upstream] has been renamed to [forwarder]'),
    'the parser no longer rejects [upstream]; revisit REJECTED_NAMES',
  );
  assert.ok(!ENGINE_SCHEMA.sections.some((section) => section.path === 'upstream'));
});

test('every engine key the Rust parser reads exists in the schema', () => {
  const rustKeys = collectRustKeys('dgaard-engine/src/config/parser.rs');
  const schemaKeys = collectSchemaKeys(ENGINE_SCHEMA);

  assert.ok(rustKeys.size > 80, `expected a large key set, got ${rustKeys.size}`);
  const missing = [...rustKeys]
    .filter((key) => !schemaKeys.has(key) && !REJECTED_NAMES.has(key))
    .sort();
  assert.deepEqual(missing, [], `keys parsed by dgaard but absent from the schema: ${missing}`);
});

test('every engine key in the schema is actually read by the Rust parser', () => {
  const rustKeys = collectRustKeys('dgaard-engine/src/config/parser.rs');
  const schemaKeys = collectSchemaKeys(ENGINE_SCHEMA);

  const unknown = [...schemaKeys].filter((key) => !rustKeys.has(key)).sort();
  assert.deepEqual(unknown, [], `schema keys dgaard would ignore: ${unknown}`);
});

test('every monitor key the Rust parser reads exists in the schema', () => {
  const rustKeys = collectRustKeys('dgaard-monitor/src/config.rs');
  const schemaKeys = collectSchemaKeys(MONITOR_SCHEMA);

  assert.ok(rustKeys.size > 20, `expected a sizeable key set, got ${rustKeys.size}`);
  const missing = [...rustKeys].filter((key) => !schemaKeys.has(key)).sort();
  assert.deepEqual(
    missing,
    [],
    `keys parsed by dgaard-monitor but absent from the schema: ${missing}`,
  );
});

test('every monitor key in the schema is actually read by the Rust parser', () => {
  const rustKeys = collectRustKeys('dgaard-monitor/src/config.rs');
  const schemaKeys = collectSchemaKeys(MONITOR_SCHEMA);

  const unknown = [...schemaKeys].filter((key) => !rustKeys.has(key)).sort();
  assert.deepEqual(unknown, [], `schema keys dgaard-monitor would ignore: ${unknown}`);
});

test('enum values match the strings the Rust parser accepts', () => {
  const source = productionSource('dgaard-engine/src/config/parser.rs');
  const expectations = {
    'server.mode': ['forwarder', 'recursive'],
    'security.idn.mode': ['Off', 'Strict', 'Smart'],
    'security.dnssec.action': ['block', 'log'],
    'nxdomain_hunting.action': ['log', 'block_client'],
    'recursive.ns_concurrency': ['sequential', 'staggered', 'parallel'],
  };

  for (const [path, values] of Object.entries(expectations)) {
    const sectionPath = path.slice(0, path.lastIndexOf('.'));
    const fieldKey = path.slice(path.lastIndexOf('.') + 1);
    const section = ENGINE_SCHEMA.sections.find((item) => item.path === sectionPath);
    const field = section.fields.find((item) => item.key === fieldKey);
    assert.deepEqual(field.values, values, `${path} values drifted`);
    // And each value really appears as a match arm in the parser.
    for (const value of values) {
      assert.ok(source.includes(`"${value}" =>`), `parser has no match arm for "${value}"`);
    }
  }
});

test('schema structure is well formed', () => {
  for (const schema of [ENGINE_SCHEMA, MONITOR_SCHEMA]) {
    const paths = new Set();
    for (const section of schema.sections) {
      assert.ok(!paths.has(section.path), `duplicate section ${section.path}`);
      paths.add(section.path);

      if (section.repeatable) {
        assert.ok(section.entry?.fields?.length, `${section.path} has no entry fields`);
        assert.ok(section.entry.labelKey, `${section.path} has no labelKey`);
        continue;
      }

      const keys = new Set();
      for (const field of section.fields) {
        assert.ok(!keys.has(field.key), `duplicate key ${section.path}.${field.key}`);
        keys.add(field.key);
        assert.ok(field.type, `${section.path}.${field.key} has no type`);
        assert.ok(Object.hasOwn(field, 'default'), `${section.path}.${field.key} has no default`);
        if (field.type === 'enum') {
          assert.ok(
            field.values.includes(field.default),
            `${section.path}.${field.key} default is not one of its values`,
          );
        }
        if (field.optional) {
          assert.equal(
            field.default,
            null,
            `${section.path}.${field.key} is optional so its default must be null`,
          );
        }
      }
    }
  }
});
