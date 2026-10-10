// State → TOML.
//
// Two modes:
//   "annotated" — every key written, each preceded by its documentation, in the
//                 shape of the shipped example files. Optional keys that are
//                 unset are emitted commented-out so they are discoverable.
//   "minimal"   — only keys the user actually changed. Because the store is a
//                 sparse diff against the defaults, this is a direct read.

const RULE = `# ${'-'.repeat(77)}`;

// An array stays on one line while it fits; past that it breaks one item per
// line. Width alone, not item count: `[10, 13, 252, 255]` reads better inline
// than four short lines, while two blocklist URLs do not.
const INLINE_ARRAY_MAX_WIDTH = 72;

/// Quote a TOML basic string, escaping what the spec requires.
export function formatString(value) {
  const escaped = String(value)
    .replace(/\\/g, '\\\\')
    .replace(/"/g, '\\"')
    .replace(/\n/g, '\\n')
    .replace(/\r/g, '\\r')
    .replace(/\t/g, '\\t');
  return `"${escaped}"`;
}

/// Floats always keep a decimal point: `get_float` in the Rust parser accepts
/// integers, but a config that reads `entropy_threshold = 4` misleads.
export function formatFloat(value) {
  return Number.isInteger(value) ? `${value}.0` : String(value);
}

function formatScalar(field, value) {
  switch (field.type) {
    case 'bool':
      return value ? 'true' : 'false';
    case 'int':
      return String(value);
    case 'float':
      return formatFloat(value);
    case 'worker-threads':
      return typeof value === 'number' ? String(value) : formatString(value);
    default:
      return formatString(value);
  }
}

function formatArrayItem(field, item) {
  if (field.type === 'int-list') return String(item);
  return formatString(item);
}

function formatArray(field, items, indent = '') {
  const parts = items.map((item) => formatArrayItem(field, item));
  const inline = `[${parts.join(', ')}]`;
  if (inline.length <= INLINE_ARRAY_MAX_WIDTH) return inline;
  const body = parts.map((part) => `${indent}  ${part},`).join('\n');
  return `[\n${body}\n${indent}]`;
}

const ARRAY_TYPES = new Set([
  'string-list',
  'tld-list',
  'cidr-list',
  'source-list',
  'int-list',
  'ordered-enum-list',
]);

/// Render `key = value` for one field.
export function formatAssignment(field, value, indent = '') {
  const rendered = ARRAY_TYPES.has(field.type)
    ? formatArray(field, value, indent)
    : formatScalar(field, value);
  return `${indent}${field.key} = ${rendered}`;
}

function commentLines(text, indent = '') {
  return String(text)
    .split('\n')
    .map((line) => (line.length ? `${indent}# ${line}` : `${indent}#`))
    .join('\n');
}

function bannerBlock(lines) {
  return [RULE, commentLines(lines.join('\n')), RULE].join('\n');
}

/// A stand-in value for a key with nothing stored — an unset optional, or an
/// entry template for an empty array-of-tables. Keeping it a real value (rather
/// than a raw string) means the commented-out line stays valid TOML if the user
/// uncomments it.
function exampleValue(field) {
  if (field.example !== undefined) return field.example;
  if (field.placeholder !== undefined) return field.placeholder;
  if (ARRAY_TYPES.has(field.type)) return [];
  if (field.type === 'int' || field.type === 'float') return 0;
  if (field.type === 'bool') return false;
  if (field.values) return field.values[0];
  return '';
}

function placeholderLiteral(field) {
  const value = exampleValue(field);
  return ARRAY_TYPES.has(field.type) ? formatArray(field, value) : formatScalar(field, value);
}

function emitRepeatableSection(section, entries, mode) {
  const header = `[[${section.path}]]`;
  const chunks = [];

  if (mode === 'annotated') {
    chunks.push(bannerBlock([`${header} — ${section.title}`]));
    chunks.push(commentLines(section.doc));
  }

  if (entries.length === 0) {
    if (mode !== 'annotated') return null;
    // Nothing configured: show the shape as a commented-out template.
    const template = [
      header,
      ...section.entry.fields.map((field) => `${field.key} = ${placeholderLiteral(field)}`),
    ].join('\n');
    chunks.push(commentLines(template));
    return chunks.join('\n');
  }

  for (const entry of entries) {
    const lines = [header];
    for (const field of section.entry.fields) {
      const value = Object.hasOwn(entry, field.key) ? entry[field.key] : field.default;
      // Optional-ish entry keys (name, description) are skipped when empty in
      // minimal mode; the Rust parser defaults them to "".
      if (mode === 'minimal' && !field.required && value === field.default) continue;
      lines.push(formatAssignment(field, value));
    }
    chunks.push(lines.join('\n'));
  }
  return chunks.join('\n\n');
}

function emitSection(schema, section, store, mode) {
  const fileId = schema.id;

  if (section.repeatable) {
    return emitRepeatableSection(section, store.get(fileId, section.path) ?? [], mode);
  }

  const rows = [];
  for (const field of section.fields) {
    const key = `${section.path}.${field.key}`;
    const modified = store.isModified(fileId, key);
    const value = store.get(fileId, key);
    const unsetOptional = field.optional && (value === null || value === undefined);

    if (mode === 'minimal') {
      if (!modified || unsetOptional) continue;
      rows.push(formatAssignment(field, value));
      continue;
    }

    const doc = field.doc ? commentLines(field.doc) : null;
    const line = unsetOptional
      ? `# ${field.key} = ${placeholderLiteral(field)}`
      : formatAssignment(field, value);
    rows.push([doc, line].filter(Boolean).join('\n'));
  }

  if (rows.length === 0) return null;

  const header = [];
  if (mode === 'annotated') {
    header.push(bannerBlock([`[${section.path}] — ${section.title}`]));
    if (section.doc) header.push(commentLines(section.doc));
  }
  header.push(`[${section.path}]`);

  return `${header.join('\n')}\n${rows.join(mode === 'annotated' ? '\n\n' : '\n')}`;
}

/// Render a whole config file. `mode` is "annotated" (default) or "minimal".
export function emitToml(schema, store, mode = 'annotated') {
  const blocks = [];

  if (mode === 'annotated' && schema.banner) {
    blocks.push(bannerBlock(schema.banner));
  }

  for (const section of schema.sections) {
    const block = emitSection(schema, section, store, mode);
    if (block) blocks.push(block);
  }

  if (blocks.length === 0) {
    return mode === 'minimal' ? `# ${schema.file} — every value is at its default.\n` : '';
  }
  return `${blocks.join('\n\n')}\n`;
}
