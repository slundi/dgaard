// A DOM small enough to run render.js and widgets.js under `node --test`.
//
// The page has no build step and no test browser, so without this the render
// path would only ever be exercised by opening the page by hand. This stub
// implements the handful of APIs the UI actually uses — element creation,
// append/replace, class lists, datasets, a simple selector matcher, and event
// dispatch — which is enough to catch a missing widget factory, a bad
// selector, or a handler that throws.

/// Parse a selector list like `input, select, button` or `.field[data-key]`
/// into predicates. Only compound selectors (no combinators) are supported,
/// which is all the UI uses.
function compileSelector(selector) {
  const alternatives = selector
    .split(',')
    .map((part) => part.trim())
    .filter(Boolean);

  return (node) =>
    alternatives.some((alternative) => {
      const pattern = /^([a-zA-Z][\w-]*)?((?:[.#][\w-]+|\[[^\]]+\])*)$/.exec(alternative);
      if (!pattern) throw new Error(`dom-stub: unsupported selector "${alternative}"`);

      const [, tag, rest = ''] = pattern;
      if (tag && node.tagName !== tag.toUpperCase()) return false;

      for (const [, token] of rest.matchAll(/([.#][\w-]+|\[[^\]]+\])/g)) {
        if (token.startsWith('.')) {
          if (!node.classList.contains(token.slice(1))) return false;
        } else if (token.startsWith('#')) {
          if (node.id !== token.slice(1)) return false;
        } else {
          const attribute = /^\[([\w-]+)(?:=["']?([^"'\]]*)["']?)?\]$/.exec(token);
          if (!attribute) throw new Error(`dom-stub: unsupported attribute "${token}"`);
          const [, name, expected] = attribute;
          const actual = node.getAttribute(name);
          if (actual === null) return false;
          if (expected !== undefined && actual !== expected) return false;
        }
      }
      return true;
    });
}

function toKebabCase(name) {
  return name.replace(/[A-Z]/g, (letter) => `-${letter.toLowerCase()}`);
}

class StubNode {
  constructor(tagName) {
    this.tagName = tagName.toUpperCase();
    this.children = [];
    this.parentNode = null;
    this.attributes = new Map();
    this.handlers = new Map();
    this.textContent = '';
    this.checked = false;
    this.selected = false;
    this.disabled = false;

    const node = this;
    this.classList = {
      contains: (name) => (node.attributes.get('class') ?? '').split(/\s+/).includes(name),
      add(name) {
        if (!this.contains(name)) {
          node.attributes.set('class', `${node.attributes.get('class') ?? ''} ${name}`.trim());
        }
      },
      remove(name) {
        const kept = (node.attributes.get('class') ?? '')
          .split(/\s+/)
          .filter((item) => item && item !== name);
        node.attributes.set('class', kept.join(' '));
      },
      toggle(name, force) {
        const shouldHave = force === undefined ? !this.contains(name) : force;
        if (shouldHave) this.add(name);
        else this.remove(name);
      },
    };

    this.dataset = new Proxy(
      {},
      {
        get: (_, property) => node.attributes.get(`data-${toKebabCase(String(property))}`),
        set: (_, property, value) => {
          node.attributes.set(`data-${toKebabCase(String(property))}`, String(value));
          return true;
        },
        has: (_, property) => node.attributes.has(`data-${toKebabCase(String(property))}`),
      },
    );
  }

  get className() {
    return this.attributes.get('class') ?? '';
  }
  set className(value) {
    this.attributes.set('class', value);
  }

  get id() {
    return this.attributes.get('id') ?? '';
  }
  set id(value) {
    this.attributes.set('id', value);
  }

  get value() {
    return this.attributes.get('value') ?? '';
  }
  set value(next) {
    this.attributes.set('value', String(next));
  }

  setAttribute(name, value) {
    this.attributes.set(name, String(value));
  }

  getAttribute(name) {
    return this.attributes.has(name) ? this.attributes.get(name) : null;
  }

  append(...nodes) {
    for (const node of nodes) {
      if (typeof node === 'string') {
        this.textContent += node;
        continue;
      }
      node.parentNode = this;
      this.children.push(node);
    }
  }

  replaceChildren(...nodes) {
    this.children = [];
    this.append(...nodes);
  }

  replaceWith(node) {
    const siblings = this.parentNode?.children;
    if (!siblings) return;
    siblings[siblings.indexOf(this)] = node;
    node.parentNode = this.parentNode;
  }

  /// Depth-first over descendants, excluding the node itself (as the DOM does).
  *descendants() {
    for (const child of this.children) {
      yield child;
      yield* child.descendants();
    }
  }

  matches(selector) {
    return compileSelector(selector)(this);
  }

  querySelector(selector) {
    return this.querySelectorAll(selector)[0] ?? null;
  }

  querySelectorAll(selector) {
    const matches = compileSelector(selector);
    return [...this.descendants()].filter(matches);
  }

  addEventListener(type, handler) {
    const existing = this.handlers.get(type) ?? [];
    existing.push(handler);
    this.handlers.set(type, existing);
  }

  /// Fire a handler the way a browser would, with the node as `event.target`.
  dispatch(type, event = {}) {
    for (const handler of this.handlers.get(type) ?? []) {
      handler({ target: this, currentTarget: this, preventDefault() {}, ...event });
    }
  }

  scrollIntoView() {}
}

/// Install the stub as a global `document`. Returns a teardown function.
export function installDom() {
  const previousDocument = globalThis.document;
  const previousCss = globalThis.CSS;

  globalThis.document = {
    createElement: (tagName) => new StubNode(tagName),
    getElementById: () => null,
  };
  globalThis.CSS = { escape: (value) => String(value).replace(/["\\]/g, '\\$&') };

  return () => {
    globalThis.document = previousDocument;
    globalThis.CSS = previousCss;
  };
}

export function createRoot() {
  return new StubNode('div');
}
