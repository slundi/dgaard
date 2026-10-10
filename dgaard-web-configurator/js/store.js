// Configuration state.
//
// The state is a *sparse diff against the schema defaults*: a key is present
// only when its value differs from the default declared in the schema (which
// mirrors the Rust `Default` impls). That makes "minimal" TOML output a direct
// read of the state, keeps drafts small, turns "reset to default" into a key
// deletion, and lets a dgaard release that changes a default propagate to every
// key the user never touched.

export const SCHEMA_VERSION = 1;

export const STORAGE_KEYS = {
  draft: 'dgaard-cfg:draft',
  profiles: 'dgaard-cfg:profiles',
  ui: 'dgaard-cfg:ui',
};

/// Structural equality for the value shapes a TOML config can hold:
/// primitives, arrays, and plain objects (array-of-tables entries).
export function deepEqual(left, right) {
  if (left === right) return true;
  if (left === null || right === null) return false;
  if (Array.isArray(left) !== Array.isArray(right)) return false;

  if (Array.isArray(left)) {
    if (left.length !== right.length) return false;
    return left.every((item, index) => deepEqual(item, right[index]));
  }
  if (typeof left === 'object' && typeof right === 'object') {
    const leftKeys = Object.keys(left);
    const rightKeys = Object.keys(right);
    if (leftKeys.length !== rightKeys.length) return false;
    return leftKeys.every(
      (name) => Object.hasOwn(right, name) && deepEqual(left[name], right[name]),
    );
  }
  return false;
}

export function deepClone(value) {
  if (Array.isArray(value)) return value.map(deepClone);
  if (value !== null && typeof value === 'object') {
    const copy = {};
    for (const name of Object.keys(value)) copy[name] = deepClone(value[name]);
    return copy;
  }
  return value;
}

/// Flatten a schema into `dotted.key -> field descriptor`.
///
/// Repeatable sections (`[[overrides]]`) contribute a single entry under their
/// section path whose default is the empty list, so the rest of the code can
/// treat them like any other value.
export function indexFields(schema) {
  const index = new Map();
  for (const section of schema.sections) {
    if (section.repeatable) {
      index.set(section.path, {
        key: section.path,
        type: 'repeatable',
        default: [],
        entry: section.entry,
        section,
      });
      continue;
    }
    for (const field of section.fields) {
      index.set(`${section.path}.${field.key}`, { ...field, section });
    }
  }
  return index;
}

export class Store {
  /// `schemas` maps a file id ("engine", "monitor") to its schema object.
  constructor(schemas) {
    this.schemas = schemas;
    this.indexes = {};
    this.values = {};
    for (const fileId of Object.keys(schemas)) {
      this.indexes[fileId] = indexFields(schemas[fileId]);
      this.values[fileId] = {};
    }
    this.listeners = new Set();
  }

  field(fileId, key) {
    return this.indexes[fileId].get(key);
  }

  defaultOf(fileId, key) {
    const field = this.field(fileId, key);
    return field ? deepClone(field.default) : undefined;
  }

  /// The value to display: the override when set, the schema default otherwise.
  get(fileId, key) {
    const overrides = this.values[fileId];
    if (Object.hasOwn(overrides, key)) return deepClone(overrides[key]);
    return this.defaultOf(fileId, key);
  }

  isModified(fileId, key) {
    return Object.hasOwn(this.values[fileId], key);
  }

  /// Store `value`, or drop the override when it is equal to the default.
  set(fileId, key, value) {
    const fallback = this.defaultOf(fileId, key);
    if (deepEqual(value, fallback)) {
      delete this.values[fileId][key];
    } else {
      this.values[fileId][key] = deepClone(value);
    }
    this.emit(fileId, key);
  }

  unset(fileId, key) {
    delete this.values[fileId][key];
    this.emit(fileId, key);
  }

  modifiedKeys(fileId) {
    return Object.keys(this.values[fileId]);
  }

  /// Keys of `sectionPath` that carry an override — used for the nav dots.
  sectionIsModified(fileId, sectionPath) {
    const prefix = `${sectionPath}.`;
    return this.modifiedKeys(fileId).some((key) => key === sectionPath || key.startsWith(prefix));
  }

  /// The sparse override map for one file; this is exactly the minimal output.
  sparse(fileId) {
    return deepClone(this.values[fileId]);
  }

  /// Replace a file's overrides wholesale (import, preset, profile load).
  /// Unknown keys are ignored here; the import UI reports them separately.
  replace(fileId, overrides) {
    const next = {};
    for (const [key, value] of Object.entries(overrides)) {
      if (!this.indexes[fileId].has(key)) continue;
      if (deepEqual(value, this.defaultOf(fileId, key))) continue;
      next[key] = deepClone(value);
    }
    this.values[fileId] = next;
    this.emit(fileId, null);
  }

  /// Apply a sparse patch on top of the current state (presets).
  patch(fileId, overrides) {
    for (const [key, value] of Object.entries(overrides)) {
      if (!this.indexes[fileId].has(key)) continue;
      const fallback = this.defaultOf(fileId, key);
      if (deepEqual(value, fallback)) delete this.values[fileId][key];
      else this.values[fileId][key] = deepClone(value);
    }
    this.emit(fileId, null);
  }

  resetFile(fileId) {
    this.values[fileId] = {};
    this.emit(fileId, null);
  }

  subscribe(listener) {
    this.listeners.add(listener);
    return () => this.listeners.delete(listener);
  }

  emit(fileId, key) {
    for (const listener of this.listeners) listener(fileId, key);
  }

  toJSON() {
    return { schemaVersion: SCHEMA_VERSION, files: deepClone(this.values) };
  }

  /// Restore from `toJSON()` output. A payload from a newer schema version is
  /// loaded on a best-effort basis rather than discarded: losing someone's
  /// draft is worse than carrying a few unknown keys, which `replace` drops.
  fromJSON(payload) {
    if (!payload || typeof payload !== 'object' || !payload.files) return false;
    for (const fileId of Object.keys(this.values)) {
      this.replace(fileId, payload.files[fileId] ?? {});
    }
    return true;
  }
}

/// Persist the store to `localStorage` on every change, debounced so typing
/// into a text field does not write once per keystroke.
export function attachDraftPersistence(store, delayMs = 400) {
  let timer = null;
  const flush = () => {
    try {
      localStorage.setItem(STORAGE_KEYS.draft, JSON.stringify(store.toJSON()));
    } catch {
      // Quota exceeded or private mode: the draft is not persisted.
    }
  };
  store.subscribe(() => {
    clearTimeout(timer);
    timer = setTimeout(flush, delayMs);
  });
  return flush;
}

export function loadDraft(store) {
  try {
    const raw = localStorage.getItem(STORAGE_KEYS.draft);
    if (!raw) return false;
    return store.fromJSON(JSON.parse(raw));
  } catch {
    return false;
  }
}
