// Regenerate the golden config files in tests/golden/.
//
// Those files are parsed and validated by the real Rust parser
// (dgaard-engine/tests/configurator_golden.rs), which is the only way to prove
// that what this page emits is something dgaard actually accepts. The files are
// checked in so the Rust test needs no JavaScript toolchain.
//
// Run with:  just configurator-golden

import { mkdirSync, writeFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { ENGINE_SCHEMA } from '../js/schema/engine.js';
import { MONITOR_SCHEMA } from '../js/schema/monitor.js';
import { Store } from '../js/store.js';
import { emitToml } from '../js/toml-emit.js';

const GOLDEN_DIR = fileURLToPath(new URL('../tests/golden/', import.meta.url));

/// A config that exercises the shapes a plain default config never reaches:
/// optional keys that are set, both array-of-tables sections, every list
/// widget, and the IDN cross-field rule in its *valid* combination.
///
/// `security.geo_ip.enabled` stays false on purpose: the default build has no
/// `geoip` feature and `Config::validate` rejects it there.
export const POPULATED_ENGINE = {
  'server.listen_addr': '192.168.1.1:53',
  'server.mode': 'recursive',
  'server.allowed_networks': ['127.0.0.1/32', '10.0.0.0/8', '192.168.1.0/24'],
  'server.block_idn': false,
  'server.metrics_listen': '0.0.0.0:9153',
  'server.pipeline': ['Whitelist', 'HotCache', 'StaticBlock', 'SuffixMatch', 'Upstream'],
  'server.runtime.worker_threads': 1,
  'server.runtime.max_concurrent_queries': 256,
  'security.structure.force_lowercase_ascii': false,
  'security.idn.mode': 'Smart',
  'security.idn.allowed_scripts': ['Latin'],
  'security.lexical.banned_keywords': ['casino', 'gambling', 'porn'],
  'security.intelligence.entropy_threshold': 4.2,
  'security.intelligence.ngram_embedded_languages': ['english', 'french', 'german'],
  'security.qtype_warden.blocked_types': [10, 13, 252, 255],
  'security.low_ttl.min_ttl_floor_secs': 30,
  'security.asn_filter.enabled': true,
  'security.asn_filter.blocked_ranges': ['203.0.113.0/24', '198.51.100.0/24', '2001:db8::/32'],
  'security.special_use.extra_local_tlds': ['corp', 'lan', 'home'],
  'security.dnssec.enabled': true,
  'security.dnssec.action': 'log',
  'security.custom_flags': [
    {
      bit: 16,
      code: 'AI_GENERATED',
      name: 'AI generated domains',
      description: 'Domains flagged by an LLM-assisted feed',
      suspicious_score: 4,
      list_path: ['/etc/dgaard/lists/ai_generated.txt'],
    },
    {
      bit: 17,
      code: 'HONEYPOT',
      name: 'Honeypot hits',
      description: '',
      suspicious_score: 6,
      list_path: ['/etc/dgaard/lists/honeypot.txt'],
    },
  ],
  'recursive.root_hints_path': '/etc/dgaard/root.hints',
  'recursive.ns_concurrency': 'staggered',
  'tld.exclude': ['top', 'xyz', 'bid', 'country', 'stream', 'gdn'],
  'tld.suspicious_tlds': ['biz', 'click', 'vip'],
  'nxdomain_hunting.action': 'block_client',
  'sources.blacklists': [
    'https://easylist.to/easylist/easylist.txt',
    '/etc/dgaard/lists/malware_domains.txt',
  ],
  'sources.whitelists': ['/etc/dgaard/lists/personal_whitelist.txt'],
  overrides: [
    { domain: 'nas.home', to: '192.168.1.50' },
    { domain: '*.internal.corp', to: '10.0.0.1' },
    { domain: 'metrics.internal', to: 'fd00::1' },
  ],
};

export const POPULATED_MONITOR = {
  'input.socket': '/var/run/dgaard/stats.sock',
  'input.index': '/var/dgaard/host_mapping.bin',
  'input.engine_config_path': '/etc/dgaard/config.toml',
  'forwarding.file': '/var/log/dgaard/dns.log',
  'forwarding.format': 'json',
  'forwarding.forward_url': 'https://soar.internal/api/v1/dns-alert',
  'forwarding.filter': ['Blocked', 'Suspicious', 'HighlySuspicious'],
  'server.token': 'a-real-token',
  'api.enabled': true,
  'websocket.enabled': true,
  'web.enabled': true,
  'nats.enabled': true,
  'nats.subscribe_subject': 'dgaard.events',
};

/// The golden set: file name → the TOML it must contain.
export function buildGoldenFiles() {
  const defaults = new Store({ engine: ENGINE_SCHEMA, monitor: MONITOR_SCHEMA });

  const populated = new Store({ engine: ENGINE_SCHEMA, monitor: MONITOR_SCHEMA });
  populated.replace('engine', POPULATED_ENGINE);
  populated.replace('monitor', POPULATED_MONITOR);

  return {
    'config.default.annotated.toml': emitToml(ENGINE_SCHEMA, defaults, 'annotated'),
    'config.populated.annotated.toml': emitToml(ENGINE_SCHEMA, populated, 'annotated'),
    'config.populated.minimal.toml': emitToml(ENGINE_SCHEMA, populated, 'minimal'),
    'dgaard-monitor.default.annotated.toml': emitToml(MONITOR_SCHEMA, defaults, 'annotated'),
    'dgaard-monitor.populated.annotated.toml': emitToml(MONITOR_SCHEMA, populated, 'annotated'),
  };
}

function main() {
  mkdirSync(GOLDEN_DIR, { recursive: true });
  for (const [name, content] of Object.entries(buildGoldenFiles())) {
    writeFileSync(GOLDEN_DIR + name, content);
    process.stdout.write(`wrote tests/golden/${name}\n`);
  }
}

if (process.argv[1] === fileURLToPath(import.meta.url)) main();
