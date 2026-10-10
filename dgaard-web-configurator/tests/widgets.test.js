// widgets.js touches the DOM only inside its factories, so it imports cleanly
// in Node. These tests cover the parts that are pure logic — which field types
// exist, and the numeric bounds derived from the Rust integer types — without
// needing a browser.

import assert from 'node:assert/strict';
import { test } from 'node:test';
import { ENGINE_SCHEMA } from '../js/schema/engine.js';
import { MONITOR_SCHEMA } from '../js/schema/monitor.js';
import { numericBounds, RUST_INT_RANGE, WIDGET_TYPES } from '../js/widgets.js';

function allFields(schema) {
  return schema.sections.flatMap((section) =>
    section.repeatable ? section.entry.fields : section.fields,
  );
}

test('every field type used by a schema has a widget factory', () => {
  for (const schema of [ENGINE_SCHEMA, MONITOR_SCHEMA]) {
    for (const field of allFields(schema)) {
      assert.ok(
        WIDGET_TYPES.includes(field.type),
        `${schema.file}: no widget for type "${field.type}" (field ${field.key})`,
      );
    }
  }
});

test('every widget factory is actually used by a schema', () => {
  const used = new Set(
    [ENGINE_SCHEMA, MONITOR_SCHEMA].flatMap((schema) =>
      allFields(schema).map((field) => field.type),
    ),
  );
  const unused = WIDGET_TYPES.filter((type) => !used.has(type));
  assert.deepEqual(unused, [], `widget factories with no field using them: ${unused}`);
});

test('numeric bounds follow the Rust integer type', () => {
  assert.deepEqual(numericBounds({ type: 'int', rust: 'u8' }), { min: 0, max: 255 });
  assert.deepEqual(numericBounds({ type: 'int', rust: 'u16' }), { min: 0, max: 65535 });
  assert.deepEqual(numericBounds({ type: 'int', rust: 'u32' }), { min: 0, max: 4294967295 });
});

test('explicit schema bounds win over the Rust type range', () => {
  // security.custom_flags[].bit is a u8 the parser restricts to 16–31.
  assert.deepEqual(numericBounds({ type: 'int', rust: 'u8', min: 16, max: 31 }), {
    min: 16,
    max: 31,
  });
});

test('a field with no rust type and no bounds is unconstrained', () => {
  assert.deepEqual(numericBounds({ type: 'float' }), { min: undefined, max: undefined });
});

test('every integer field declares the Rust type the parser converts to', () => {
  for (const schema of [ENGINE_SCHEMA, MONITOR_SCHEMA]) {
    for (const field of allFields(schema)) {
      if (field.type !== 'int') continue;
      assert.ok(
        Object.hasOwn(RUST_INT_RANGE, field.rust),
        `${schema.file}: ${field.key} has no (or an unknown) rust type: ${field.rust}`,
      );
    }
  }
});

test('integer defaults fit the range their Rust type allows', () => {
  for (const schema of [ENGINE_SCHEMA, MONITOR_SCHEMA]) {
    for (const field of allFields(schema)) {
      if (field.type !== 'int' || field.default === null) continue;
      const { min, max } = numericBounds(field);
      assert.ok(
        field.default >= min && field.default <= max,
        `${schema.file}: ${field.key} default ${field.default} is outside ${min}–${max}`,
      );
    }
  }
});
