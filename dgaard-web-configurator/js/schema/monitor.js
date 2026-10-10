// Schema for dgaard-monitor.toml.
//
// Transcribed from the parser and the `Default` impls, never from the example
// file:
//   dgaard-monitor/src/config.rs          [input] [persistence] + dispatch
//   dgaard-monitor-tui/src/config.rs      [tui]
//   dgaard-monitor-core/src/config.rs     [forwarding]
//   dgaard-monitor-rest/src/config.rs     [server] [api] [websocket] [mcp] [web]
//   dgaard-monitor-nats/src/config.rs     [nats]

export const MONITOR_SCHEMA = {
  id: 'monitor',
  file: 'dgaard-monitor.toml',
  title: 'dgaard-monitor',
  banner: [
    'dgaard-monitor — telemetry agent configuration',
    'Pass to the binary with:  dgaard-monitor -c /path/to/dgaard-monitor.toml',
  ],
  sections: [
    {
      path: 'input',
      title: 'Input',
      doc: 'Where the monitor reads events and domain names from.',
      fields: [
        {
          key: 'socket',
          type: 'path',
          default: '/tmp/dgaard_stats.sock',
          doc: 'Unix domain socket exposed by the dgaard DNS proxy.\nMust match server.stats_socket_path in config.toml.',
        },
        {
          key: 'index',
          type: 'path',
          default: '/var/lib/dns/hosts.bin',
          doc: 'Binary host-index file produced by dgaard (hash → domain mapping).\nMust match sources.host_index_path in config.toml.',
        },
        {
          key: 'engine_config_path',
          type: 'path',
          optional: true,
          default: null,
          example: '/etc/dgaard/config.toml',
          doc: 'Optional path to the dgaard engine config. When set, the monitor reads\n[[security.custom_flags]] from it to resolve custom bits (16–31) to their\nconfigured code labels. Bits with no entry render as CUSTOM_BIT_<n>.',
        },
      ],
    },
    {
      path: 'persistence',
      title: 'Persistence',
      doc: 'Local SQLite storage: a rolling event log plus hourly aggregates.',
      fields: [
        {
          key: 'db',
          type: 'path',
          default: '/var/dgaard/stats.sqlite',
          doc: 'SQLite database file (opened in WAL mode).',
        },
        {
          key: 'events_retention_hours',
          type: 'int',
          rust: 'u32',
          default: 72,
          doc: 'Tier 1 — rolling event log retention, in hours.',
        },
        {
          key: 'aggregates_retention_days',
          type: 'int',
          rust: 'u32',
          default: 90,
          doc: 'Tier 2 — hourly aggregates retention, in days.',
        },
      ],
    },
    {
      path: 'tui',
      title: 'TUI',
      doc: 'Terminal user interface. Requires a build with the `tui` feature.',
      fields: [
        {
          key: 'tick_ms',
          type: 'int',
          rust: 'u64',
          default: 250,
          doc: 'Terminal refresh rate in milliseconds.',
        },
        {
          key: 'key_quit',
          type: 'string',
          default: 'q',
          doc: 'Key binding: quit. Single character or a named key.',
        },
        {
          key: 'key_pause',
          type: 'string',
          default: 'space',
          doc: 'Key binding: pause the live feed.',
        },
        { key: 'key_scroll_up', type: 'string', default: 'up', doc: 'Key binding: scroll up.' },
        {
          key: 'key_scroll_down',
          type: 'string',
          default: 'down',
          doc: 'Key binding: scroll down.',
        },
      ],
    },
    {
      path: 'forwarding',
      title: 'Forwarding',
      doc: 'Route enriched events to external sinks (file, stdout, HTTP endpoint).',
      fields: [
        {
          key: 'file',
          type: 'path',
          optional: true,
          default: null,
          example: '/var/log/dgaard/dns.log',
          doc: 'Append formatted lines to this file. Unset writes to stdout.',
        },
        {
          key: 'template',
          type: 'string',
          default: '{timestamp} {client_ip} {action} {domain}',
          doc: 'Line template used when format = "template".\nPlaceholders: {timestamp}, {client_ip}, {action}, {domain}.',
        },
        {
          key: 'format',
          type: 'enum',
          values: ['template', 'json', 'syslog', 'cef', 'elasticsearch'],
          default: 'template',
          doc: 'Wire format for both file/stdout and HTTP POST output.\nsyslog is RFC 5424, cef is ArcSight CEF:0, elasticsearch is Bulk API NDJSON.',
        },
        {
          key: 'forward_url',
          type: 'string',
          optional: true,
          default: null,
          example: 'https://soar.internal/api/v1/dns-alert',
          doc: 'HTTP(S) endpoint for POSTing events (SOAR, Slack incoming webhook, …).',
        },
        {
          key: 'filter',
          type: 'string-list',
          values: ['Allowed', 'Proxied', 'Blocked', 'Suspicious', 'HighlySuspicious'],
          default: [],
          doc: 'Which action variants to forward. Empty list forwards every event.',
        },
      ],
    },
    {
      path: 'server',
      title: 'Server',
      doc: 'Shared listener settings inherited by every REST module below.\nEach module binds its own port but shares this address and bearer token.',
      fields: [
        {
          key: 'listen',
          type: 'string',
          default: '127.0.0.1',
          doc: 'Listen address shared by [api], [websocket], [mcp] and [web].',
        },
        {
          key: 'token',
          type: 'string',
          default: 'changeme',
          doc: 'Static bearer token required on every authenticated request.',
        },
      ],
    },
    {
      path: 'api',
      title: 'REST API',
      doc: 'JSON REST endpoints.',
      fields: [
        { key: 'enabled', type: 'bool', default: false, doc: 'Enable the REST API module.' },
        { key: 'port', type: 'int', rust: 'u16', default: 8080, doc: 'TCP port for the REST API.' },
        {
          key: 'root_path',
          type: 'string',
          default: '/api/v1',
          doc: 'URL prefix the API is mounted under.',
        },
      ],
    },
    {
      path: 'websocket',
      title: 'WebSocket',
      doc: 'Live event stream over WebSocket.',
      fields: [
        { key: 'enabled', type: 'bool', default: false, doc: 'Enable the WebSocket module.' },
        {
          key: 'port',
          type: 'int',
          rust: 'u16',
          default: 8081,
          doc: 'TCP port for the WebSocket stream.',
        },
        {
          key: 'root_path',
          type: 'string',
          default: '/ws',
          doc: 'URL prefix the stream is mounted under.',
        },
      ],
    },
    {
      path: 'mcp',
      title: 'MCP',
      doc: 'Model Context Protocol endpoint.',
      fields: [
        { key: 'enabled', type: 'bool', default: false, doc: 'Enable the MCP module.' },
        {
          key: 'port',
          type: 'int',
          rust: 'u16',
          default: 8082,
          doc: 'TCP port for the MCP endpoint.',
        },
        {
          key: 'root_path',
          type: 'string',
          default: '/mcp',
          doc: 'URL prefix the endpoint is mounted under.',
        },
      ],
    },
    {
      path: 'web',
      title: 'Web UI',
      doc: 'Embedded single-page dashboard, mounted at "/".',
      fields: [
        { key: 'enabled', type: 'bool', default: false, doc: 'Enable the embedded web UI.' },
        { key: 'port', type: 'int', rust: 'u16', default: 8083, doc: 'TCP port for the web UI.' },
        {
          key: 'history_size',
          type: 'int',
          rust: 'usize',
          default: 1000,
          doc: 'Maximum number of DNS events kept in the in-memory rolling log.',
        },
        {
          key: 'beaconing_min_observations',
          type: 'int',
          rust: 'usize',
          default: 5,
          doc: 'Minimum queries from one client to the same domain before the pair is\neligible for beaconing analysis (GET /api/v1/beaconing).',
        },
        {
          key: 'beaconing_cov_threshold',
          type: 'float',
          default: 0.15,
          step: 0.01,
          min: 0,
          doc: 'Coefficient of variation (std_dev / mean of inter-arrival times) below\nwhich a client/domain pair is flagged as a potential beacon. Lower is\nstricter; 0.15 catches regular C2 beacons while avoiding most false\npositives from bursty background traffic.',
        },
      ],
    },
    {
      path: 'nats',
      title: 'NATS',
      doc: 'Optional pub/sub federation. When enabled the local Unix socket input\nstill runs in parallel. Requires a build with the `nats` feature.',
      fields: [
        {
          key: 'enabled',
          type: 'bool',
          default: false,
          doc: 'Enable the NATS publisher and subscriber.',
        },
        { key: 'url', type: 'string', default: 'nats://127.0.0.1:4222', doc: 'NATS server URL.' },
        {
          key: 'publish_subject',
          type: 'string',
          default: 'dgaard.events',
          doc: 'Subject enriched events are published on. Empty disables publishing.',
        },
        {
          key: 'subscribe_subject',
          type: 'string',
          default: '',
          doc: 'Subject the monitor subscribes to. Set to "dgaard.events" to relay a peer\nmonitor, or "dgaard.scores" to consume a daemon scoring feed.\nEmpty disables subscription.',
        },
      ],
    },
  ],
};
