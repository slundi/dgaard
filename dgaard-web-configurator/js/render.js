// Schema → DOM.
//
// The store is the only source of truth; the DOM is never read back. Widgets
// push changes into the store, and the store notifies the preview and the
// "modified" indicators. A field is only re-rendered when something *other*
// than its own widget changed it (reset, preset, import), so typing never
// loses focus.

import { createWidget, element } from './widgets.js';

function fieldDomId(fileId, key) {
  return `f-${fileId}-${key.replace(/[^\w]/g, '-')}`;
}

function helpText(doc) {
  return doc ? element('p', { class: 'help', text: doc }) : null;
}

/// One `label / control / reset` row. `onReset` is omitted inside repeatable
/// entries, where the whole array is a single store key.
function buildFieldRow({ field, value, onChange, domId, modified, onReset }) {
  const described = { ...field, domId };
  const control = createWidget(described, value, onChange);

  const row = element('div', { class: modified ? 'field modified' : 'field' }, [
    element('label', { for: domId, text: field.key }),
    element('div', { class: 'control' }, [control]),
    onReset
      ? element('button', {
          type: 'button',
          class: 'btn icon reset',
          text: '↺',
          title: 'Reset to default',
          onClick: onReset,
        })
      : null,
    helpText(field.doc),
  ]);
  row.dataset.search = `${field.key} ${field.doc ?? ''}`.toLowerCase();
  return row;
}

function buildPlainSection(schema, section, store, rerenderField) {
  const body = element('div', { class: 'section-body' });

  for (const field of section.fields) {
    const key = `${section.path}.${field.key}`;
    const domId = fieldDomId(schema.id, key);

    const make = () =>
      buildFieldRow({
        field,
        domId,
        value: store.get(schema.id, key),
        modified: store.isModified(schema.id, key),
        onChange: (next) => store.set(schema.id, key, next),
        onReset: () => {
          store.unset(schema.id, key);
          rerenderField(key, make());
        },
      });

    const row = make();
    row.dataset.key = key;
    body.append(row);
  }
  return body;
}

/// `[[array of tables]]` — one card per entry, add/remove, and a label that
/// tracks the entry's identifying field so a long list stays navigable.
function buildRepeatableSection(schema, section, store, rerenderSection) {
  const key = section.path;
  const entries = store.get(schema.id, key) ?? [];
  const body = element('div', { class: 'section-body' });
  const list = element('div', { class: 'entries' });

  const commit = (next) => {
    store.set(schema.id, key, next);
    rerenderSection();
  };

  entries.forEach((entry, index) => {
    const label = entry[section.entry.labelKey] || `${section.entry.labelFallback} ${index + 1}`;
    const card = element('div', { class: 'entry' }, [
      element('div', { class: 'entry-head' }, [
        element('strong', { text: `[[${section.path}]]` }),
        element('span', { text: label }),
        element('span', { class: 'spacer' }),
        element('button', {
          type: 'button',
          class: 'btn icon',
          text: '×',
          title: 'Remove this entry',
          onClick: () => commit(entries.filter((_, other) => other !== index)),
        }),
      ]),
    ]);

    for (const field of section.entry.fields) {
      const domId = `${fieldDomId(schema.id, key)}-${index}-${field.key}`;
      const value = Object.hasOwn(entry, field.key) ? entry[field.key] : field.default;
      card.append(
        buildFieldRow({
          field,
          domId,
          value,
          modified: false,
          onChange: (next) => {
            const copy = entries.map((item, other) =>
              other === index ? { ...item, [field.key]: next } : item,
            );
            // No re-render here: that would drop focus mid-typing. The label
            // refreshes on the next add/remove.
            store.set(schema.id, key, copy);
          },
        }),
      );
    }
    list.append(card);
  });

  if (entries.length === 0) {
    list.append(element('p', { class: 'chips-empty', text: 'No entries.' }));
  }

  const blank = () =>
    Object.fromEntries(
      section.entry.fields.map((field) => [
        field.key,
        field.required ? (field.example ?? field.default) : field.default,
      ]),
    );

  body.append(
    list,
    element('button', {
      type: 'button',
      class: 'btn',
      text: '+ add entry',
      onClick: () => commit([...entries, blank()]),
    }),
  );
  return body;
}

/// Render a whole file's form into `host`. Returns nothing; call again to
/// rebuild after an external state change.
export function renderForm(host, schema, store) {
  host.replaceChildren();

  for (const section of schema.sections) {
    const wrapper = element('section', { class: 'section', id: `s-${schema.id}-${section.path}` });
    wrapper.dataset.path = section.path;

    wrapper.append(
      element('div', { class: 'section-head' }, [
        element('h2', {}, [
          element('span', { text: section.title }),
          element('span', {
            class: 'path',
            text: ` ${section.repeatable ? `[[${section.path}]]` : `[${section.path}]`}`,
          }),
        ]),
      ]),
    );
    if (section.doc) wrapper.append(element('p', { class: 'section-doc', text: section.doc }));

    const rerenderSection = () => {
      const fresh = section.repeatable
        ? buildRepeatableSection(schema, section, store, rerenderSection)
        : buildPlainSection(schema, section, store, rerenderField);
      wrapper.querySelector('.section-body').replaceWith(fresh);
    };
    const rerenderField = (key, row) => {
      const existing = wrapper.querySelector(`[data-key="${CSS.escape(key)}"]`);
      row.dataset.key = key;
      if (existing) existing.replaceWith(row);
    };

    wrapper.append(
      section.repeatable
        ? buildRepeatableSection(schema, section, store, rerenderSection)
        : buildPlainSection(schema, section, store, rerenderField),
    );
    host.append(wrapper);
  }
}

/// Section list in the sidebar. Clicking scrolls the form to that section.
export function renderNav(nav, schema, store) {
  nav.replaceChildren();
  for (const section of schema.sections) {
    const item = element(
      'button',
      {
        type: 'button',
        class: 'nav-item',
        onClick: () => {
          document
            .getElementById(`s-${schema.id}-${section.path}`)
            ?.scrollIntoView({ behavior: 'smooth', block: 'start' });
        },
      },
      [element('span', { class: 'dot' }), element('span', { text: section.title })],
    );
    item.dataset.path = section.path;
    nav.append(item);
  }
  updateModifiedMarks(nav, schema, store);
}

/// Refresh the per-section dots and the per-field accent bar without
/// rebuilding any widget.
export function updateModifiedMarks(nav, schema, store, host) {
  for (const item of nav.querySelectorAll('.nav-item')) {
    item.classList.toggle('modified', store.sectionIsModified(schema.id, item.dataset.path));
  }
  if (!host) return;
  for (const row of host.querySelectorAll('.field[data-key]')) {
    row.classList.toggle('modified', store.isModified(schema.id, row.dataset.key));
  }
}

/// Filter visible fields by a free-text query over key names and help text.
export function applySearch(host, query) {
  const needle = query.trim().toLowerCase();
  for (const section of host.querySelectorAll('.section')) {
    let visible = 0;
    for (const row of section.querySelectorAll('.field')) {
      const matches = needle === '' || (row.dataset.search ?? '').includes(needle);
      row.classList.toggle('hidden', !matches);
      if (matches) visible += 1;
    }
    section.classList.toggle('hidden', needle !== '' && visible === 0);
  }
}
