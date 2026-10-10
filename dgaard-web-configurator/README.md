# dgaard-web-configurator

A static, dependency-free web page that generates `config.toml` (the dgaard DNS proxy) and
`dgaard-monitor.toml` (the telemetry agent). No framework, no CDN, no network access at runtime.

See [DESIGN.md](DESIGN.md) for the architecture and the rationale behind it.

## Using it

**Offline, no tooling** — build the single-file version once and open it with a browser:

```sh
just configurator-build
xdg-open dgaard-web-configurator/dist/dgaard-configurator.html
```

**During development** — ES modules are blocked by CORS on `file://`, so serve over HTTP:

```sh
just configurator-serve        # http://127.0.0.1:8000
```

Pick a tab (`config.toml` or `dgaard-monitor.toml`), edit the fields you care about, and copy or
download the result from the preview pane on the right.

- **annotated** output writes every key with its documentation — the shape of the shipped example
  files, good for a first deployment.
- **minimal** output writes only what you changed — good for OpenWrt and for diffing against a
  running deployment.

Your edits are saved to `localStorage` as you type, so closing the tab does not lose them.
The theme control cycles system → light → dark and shares its storage key with the monitor's
web UI.

## Working on it

```sh
just configurator-test    # node --test, no npm dependencies
just configurator-lint    # biome check
just configurator-fmt     # biome check --write
just configurator-build   # dist/dgaard-configurator.html
just configurator-golden  # regenerate tests/golden/ after an emitter change
```

### How the output is proven valid

`tests/golden/` holds configs produced by this generator, and
[dgaard-engine/tests/configurator_golden.rs](../dgaard-engine/tests/configurator_golden.rs) runs
them through the real `Config::parse` and `Config::validate`. One of those tests asserts that the
all-defaults file parses back to exactly `Config::default()`, so a single drifted default in the
schema fails `cargo test`.

Changing the emitter or a default therefore means: `just configurator-golden`, then `just test`.
The JavaScript side checks the golden files still match what the emitter produces, so the two
halves cannot diverge silently.

`dgaard-monitor` is a binary-only crate, so its goldens are generated but not yet parse-checked
from Rust; that needs a `lib` target on the crate.

### Adding a config key

dgaard gained a new key? Add one entry to [js/schema/engine.js](js/schema/engine.js) or
[js/schema/monitor.js](js/schema/monitor.js):

```js
{
  key: 'my_new_key',
  type: 'int',          // picks the widget and the validation
  rust: 'u32',          // the type the parser converts to; bounds come from it
  default: 42,          // must match the Rust `Default` impl
  doc: 'What it does.', // becomes the comment in annotated output
}
```

That is the whole change — the form, the TOML output and the storage all follow from it. No DOM
code is involved unless the key needs a widget type that does not exist yet.

`tests/schema-coverage.test.js` reads `dgaard-engine/src/config/parser.rs` and
`dgaard-monitor/src/config.rs` and compares both directions, so a key added to dgaard but not here
(or a typo here) fails CI.

### Module rules

`scripts/build.sh` inlines the modules into one `<script>` by stripping imports and `export`
keywords, which requires two things of every file in `js/`:

- imports are single-line: `import { thing } from './module.js';`
- exports are inline — `export const` / `export function` / `export class`; never
  `export { … }` and never `export default`.

The build checks both and fails rather than emitting a broken page.
