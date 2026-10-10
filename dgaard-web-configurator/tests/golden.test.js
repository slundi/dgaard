// The golden files in tests/golden/ are the contract between this page and the
// Rust parser: dgaard-engine/tests/configurator_golden.rs parses and validates
// them with the real `Config::parse` + `Config::validate`.
//
// This test asserts the generator still produces exactly those bytes, so a
// change to the emitter is an explicit `just configurator-golden` away rather
// than a silent divergence from what the Rust side verified.

import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { test } from 'node:test';
import { fileURLToPath } from 'node:url';
import { buildGoldenFiles } from '../scripts/gen-golden.js';

const GOLDEN_DIR = fileURLToPath(new URL('./golden/', import.meta.url));

for (const [name, expected] of Object.entries(buildGoldenFiles())) {
  test(`golden file ${name} is up to date`, () => {
    let actual;
    try {
      actual = readFileSync(GOLDEN_DIR + name, 'utf8');
    } catch {
      assert.fail(`tests/golden/${name} is missing — run: just configurator-golden`);
    }
    assert.equal(
      actual,
      expected,
      `tests/golden/${name} is stale.\n` +
        'If the emitter change is intended, run: just configurator-golden',
    );
  });
}

test('the populated golden exercises the shapes a default config never reaches', () => {
  const populated = readFileSync(`${GOLDEN_DIR}config.populated.minimal.toml`, 'utf8');

  // Both array-of-tables sections, with more than one entry each.
  assert.equal(populated.match(/^\[\[overrides\]\]$/gm).length, 3);
  assert.equal(populated.match(/^\[\[security\.custom_flags\]\]$/gm).length, 2);
  // An optional key that is set, a float, an IPv6 value, and a multi-line array.
  assert.ok(populated.includes('metrics_listen = "0.0.0.0:9153"'));
  assert.ok(populated.includes('entropy_threshold = 4.2'));
  assert.ok(populated.includes('to = "fd00::1"'));
  assert.ok(populated.includes('blacklists = [\n'));
});
