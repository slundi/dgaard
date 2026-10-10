// Widget factories: one per schema field `type`.
//
// Every factory has the same contract — `(field, value, onChange) => Element` —
// so render.js never special-cases a type, and a new field in the schema needs
// no DOM code at all as long as it reuses an existing type.

export const RUST_INT_RANGE = {
  u8: [0, 255],
  u16: [0, 65535],
  u32: [0, 4294967295],
  u64: [0, Number.MAX_SAFE_INTEGER],
  usize: [0, Number.MAX_SAFE_INTEGER],
  i64: [Number.MIN_SAFE_INTEGER, Number.MAX_SAFE_INTEGER],
};

/// Bounds for a numeric field: explicit schema min/max win over the range
/// implied by the Rust integer type the parser converts into.
export function numericBounds(field) {
  const [rangeMin, rangeMax] = RUST_INT_RANGE[field.rust] ?? [undefined, undefined];
  return {
    min: field.min ?? rangeMin,
    max: field.max ?? rangeMax,
  };
}

export function element(tag, props = {}, children = []) {
  const node = document.createElement(tag);
  for (const [name, value] of Object.entries(props)) {
    if (name === 'class') node.className = value;
    else if (name === 'text') node.textContent = value;
    else if (name.startsWith('on')) node.addEventListener(name.slice(2).toLowerCase(), value);
    else if (value !== undefined && value !== null && value !== false) {
      node.setAttribute(name, value === true ? '' : String(value));
    }
  }
  for (const child of [].concat(children)) {
    if (child) node.append(child);
  }
  return node;
}

function iconButton(label, title, onClick) {
  return element('button', {
    type: 'button',
    class: 'btn icon',
    text: label,
    title,
    'aria-label': title,
    onClick,
  });
}

// ── Scalars ───────────────────────────────────────────────────────

function booleanWidget(field, value, onChange) {
  const caption = element('span', { class: 'muted', text: value ? 'enabled' : 'disabled' });
  const input = element('input', {
    type: 'checkbox',
    id: field.domId,
    onChange: (event) => {
      caption.textContent = event.target.checked ? 'enabled' : 'disabled';
      onChange(event.target.checked);
    },
  });
  input.checked = Boolean(value);
  return element('label', { class: 'switch' }, [
    input,
    element('span', { class: 'track' }),
    caption,
  ]);
}

function numberWidget(field, value, onChange) {
  const bounds = numericBounds(field);
  const isFloat = field.type === 'float';
  return element('input', {
    type: 'number',
    id: field.domId,
    min: bounds.min,
    max: bounds.max,
    step: isFloat ? (field.step ?? 'any') : 1,
    value: value ?? '',
    placeholder: field.placeholder,
    onInput: (event) => {
      const raw = event.target.value;
      if (raw === '') return;
      const parsed = isFloat ? Number.parseFloat(raw) : Number.parseInt(raw, 10);
      if (!Number.isNaN(parsed)) onChange(parsed);
    },
  });
}

function textWidget(field, value, onChange) {
  return element('input', {
    type: 'text',
    id: field.domId,
    value: value ?? '',
    placeholder: field.placeholder,
    spellcheck: 'false',
    onInput: (event) => onChange(event.target.value),
  });
}

function enumWidget(field, value, onChange) {
  const select = element('select', {
    id: field.domId,
    onChange: (event) => onChange(event.target.value),
  });
  for (const option of field.values) {
    const node = element('option', { value: option, text: option });
    if (option === value) node.selected = true;
    select.append(node);
  }
  return select;
}

/// `worker_threads` is a union in the Rust model: the string "auto", or a
/// thread count. Two radios keep that explicit instead of hiding it behind a
/// magic number.
function workerThreadsWidget(field, value, onChange) {
  const isAuto = value === 'auto';
  const count = element('input', {
    type: 'number',
    min: 1,
    value: isAuto ? 1 : value,
    onInput: (event) => {
      const parsed = Number.parseInt(event.target.value, 10);
      if (!Number.isNaN(parsed)) onChange(parsed);
    },
  });
  count.disabled = isAuto;

  const makeRadio = (label, selectAuto) => {
    const radio = element('input', {
      type: 'radio',
      name: `${field.domId}-mode`,
      onChange: () => {
        count.disabled = selectAuto;
        onChange(selectAuto ? 'auto' : Math.max(1, Number.parseInt(count.value, 10) || 1));
      },
    });
    radio.checked = selectAuto === isAuto;
    return element('label', { class: 'inline-row' }, [radio, element('span', { text: label })]);
  };

  return element('div', { class: 'inline-row' }, [
    makeRadio('auto', true),
    makeRadio('fixed', false),
    count,
  ]);
}

// ── Lists ─────────────────────────────────────────────────────────

/// Chip editor for short scalar items (keywords, TLDs, CIDRs, qtype numbers).
function chipListWidget(field, value, onChange) {
  const items = Array.isArray(value) ? [...value] : [];
  const container = element('div', { class: 'control-list' });
  const chips = element('div', { class: 'chips' });

  const toItem = (raw) => {
    const trimmed = raw.trim();
    if (!trimmed) return null;
    if (field.type !== 'int-list') return trimmed;
    const parsed = Number.parseInt(trimmed, 10);
    return Number.isNaN(parsed) ? null : parsed;
  };

  const commit = () => onChange([...items]);

  const paint = () => {
    chips.replaceChildren();
    if (items.length === 0) {
      chips.append(element('span', { class: 'chips-empty', text: '(empty)' }));
    }
    items.forEach((item, index) => {
      chips.append(
        element('span', { class: 'chip' }, [
          element('span', { text: String(item) }),
          iconButton('×', `Remove ${item}`, () => {
            items.splice(index, 1);
            paint();
            commit();
          }),
        ]),
      );
    });
  };

  const add = (raw) => {
    // Accept a pasted "a, b c" blob as several items.
    const parts = String(raw)
      .split(/[\s,]+/)
      .map(toItem)
      .filter((item) => item !== null);
    const fresh = parts.filter((item) => !items.includes(item));
    if (fresh.length === 0) return false;
    items.push(...fresh);
    paint();
    commit();
    return true;
  };

  const entry = element('input', {
    type: 'text',
    id: field.domId,
    placeholder: field.placeholder ?? 'type and press Enter',
    spellcheck: 'false',
    list: field.values ? `${field.domId}-options` : undefined,
    onKeydown: (event) => {
      if (event.key !== 'Enter') return;
      event.preventDefault();
      if (add(event.target.value)) event.target.value = '';
    },
  });

  const row = element('div', { class: 'inline-row' }, [
    entry,
    iconButton('+', 'Add item', () => {
      if (add(entry.value)) entry.value = '';
    }),
  ]);

  paint();
  container.append(chips, row);

  if (field.values) {
    const datalist = element('datalist', { id: `${field.domId}-options` });
    for (const option of field.values) datalist.append(element('option', { value: option }));
    container.append(datalist);
  }
  if (field.presets) {
    const presets = element('div', { class: 'inline-row' });
    for (const [label, preset] of Object.entries(field.presets)) {
      presets.append(
        element('button', {
          type: 'button',
          class: 'btn icon',
          text: label,
          title: `Add ${label} (${preset})`,
          onClick: () => add(String(preset)),
        }),
      );
    }
    container.append(presets);
  }
  return container;
}

/// One text input per item, for values too long to read as chips: file paths,
/// URLs, resolver addresses. Order is meaningful, so entries can be moved.
function rowListWidget(field, value, onChange) {
  const items = Array.isArray(value) ? [...value] : [];
  const container = element('div', { class: 'control-list' });
  const rows = element('div', { class: 'rows' });

  const commit = () => onChange(items.filter((item) => item.trim() !== ''));

  const paint = () => {
    rows.replaceChildren();
    items.forEach((item, index) => {
      const input = element('input', {
        type: 'text',
        value: item,
        spellcheck: 'false',
        placeholder: field.placeholder ?? '/path/to/list.txt or https://…',
        onInput: (event) => {
          items[index] = event.target.value;
          commit();
        },
      });
      rows.append(
        element('div', { class: 'row-item' }, [
          input,
          iconButton('↑', 'Move up', () => {
            if (index === 0) return;
            [items[index - 1], items[index]] = [items[index], items[index - 1]];
            paint();
            commit();
          }),
          iconButton('↓', 'Move down', () => {
            if (index === items.length - 1) return;
            [items[index + 1], items[index]] = [items[index], items[index + 1]];
            paint();
            commit();
          }),
          iconButton('×', 'Remove', () => {
            items.splice(index, 1);
            paint();
            commit();
          }),
        ]),
      );
    });
    if (items.length === 0) {
      rows.append(element('span', { class: 'chips-empty', text: '(empty)' }));
    }
  };

  paint();
  container.append(
    rows,
    element('button', {
      type: 'button',
      class: 'btn',
      text: '+ add',
      onClick: () => {
        items.push('');
        paint();
        // No commit: an empty row is not a value until it is typed into.
      },
    }),
  );
  return container;
}

/// Pipeline editor: every stage can be toggled and reordered. Disabled stages
/// simply drop out of the emitted array.
function orderedEnumListWidget(field, value, onChange) {
  const selected = Array.isArray(value) ? [...value] : [];
  const disabled = field.values.filter((step) => !selected.includes(step));
  const order = [...selected, ...disabled];
  const container = element('div', { class: 'pipeline' });

  const commit = () => onChange(order.filter((step) => selected.includes(step)));

  const paint = () => {
    container.replaceChildren();
    order.forEach((step, index) => {
      const isOn = selected.includes(step);
      const toggle = element('input', {
        type: 'checkbox',
        onChange: (event) => {
          if (event.target.checked) selected.push(step);
          else selected.splice(selected.indexOf(step), 1);
          paint();
          commit();
        },
      });
      toggle.checked = isOn;
      container.append(
        element('div', { class: isOn ? 'pipeline-step' : 'pipeline-step off' }, [
          element('span', {
            class: 'order',
            text: isOn ? String(selected.indexOf(step) + 1) : '–',
          }),
          toggle,
          element('span', { text: step }),
          element('span', { class: 'spacer' }),
          iconButton('↑', 'Move earlier', () => {
            if (index === 0) return;
            [order[index - 1], order[index]] = [order[index], order[index - 1]];
            paint();
            commit();
          }),
          iconButton('↓', 'Move later', () => {
            if (index === order.length - 1) return;
            [order[index + 1], order[index]] = [order[index], order[index + 1]];
            paint();
            commit();
          }),
        ]),
      );
    });
  };

  paint();
  return container;
}

const FACTORIES = {
  bool: booleanWidget,
  int: numberWidget,
  float: numberWidget,
  string: textWidget,
  path: textWidget,
  socketaddr: textWidget,
  enum: enumWidget,
  'worker-threads': workerThreadsWidget,
  'string-list': chipListWidget,
  'tld-list': chipListWidget,
  'cidr-list': chipListWidget,
  'int-list': chipListWidget,
  'source-list': rowListWidget,
  'ordered-enum-list': orderedEnumListWidget,
};

export const WIDGET_TYPES = Object.keys(FACTORIES);

/// Every focusable control inside a widget, including the widget root itself —
/// a scalar factory returns the `<input>` directly rather than a wrapper.
function controlsOf(root) {
  const nested = [...root.querySelectorAll('input, select, button')];
  return root.matches?.('input, select, button') ? [root, ...nested] : nested;
}

/// Build the control for one field. `Option<T>` fields are wrapped in a
/// set/unset checkbox so "no value" stays distinct from "empty value".
export function createWidget(field, value, onChange) {
  const factory = FACTORIES[field.type];
  if (!factory) throw new Error(`no widget for field type "${field.type}"`);

  if (!field.optional) return factory(field, value, onChange);

  const fallback = field.example ?? field.placeholder ?? '';
  const isSet = value !== null && value !== undefined;
  const inner = factory(field, isSet ? value : fallback, onChange);
  const controls = controlsOf(inner);
  for (const control of controls) control.disabled = !isSet;

  const toggle = element('input', {
    type: 'checkbox',
    onChange: (event) => {
      const enabled = event.target.checked;
      // Reflect the new state here rather than waiting for a re-render: the
      // form only rebuilds a field when something *other* than its own widget
      // changed it, so without this the input would stay greyed out.
      for (const control of controls) control.disabled = !enabled;
      onChange(enabled ? fallback : null);
    },
  });
  toggle.checked = isSet;

  return element('div', { class: 'inline-row' }, [
    element('label', { class: 'inline-row', title: 'Set this optional key' }, [
      toggle,
      element('span', { class: 'muted', text: 'set' }),
    ]),
    inner,
  ]);
}
