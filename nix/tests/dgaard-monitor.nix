{ pkgs, lib }:
let
  base = {
    boot.loader.grub.enable = false;
    system.stateVersion = "24.11";
  };

  eval =
    extraCfg:
    (pkgs.nixos [
      ../../nix/modules/dgaard-monitor.nix
      base
      {
        services.dgaard-monitor = {
          enable = true;
          package = pkgs.hello;
        }
        // extraCfg;
      }
    ]).config;

  # --- scenario: all defaults ---
  cfgDefaults = eval { };

  # --- scenario: dgaard on the same host — the monitor follows its paths ---
  cfgWithDgaard =
    (pkgs.nixos [
      ../../nix/modules/dgaard-monitor.nix
      ../../nix/modules/dgaard.nix
      base
      {
        services.dgaard = {
          enable = true;
          package = pkgs.hello;
        };
        services.dgaard-monitor = {
          enable = true;
          package = pkgs.hello;
        };
      }
    ]).config;

  # --- scenario: engine_config_path set ---
  cfgWithEngineConfig = eval {
    input.engineConfigPath = "/etc/dgaard/dgaard.toml";
  };

  # --- scenario: headless = false (TUI mode) ---
  cfgTui = eval { headless = false; };

  # --- scenario: forwarding sinks active ---
  cfgForwarding = eval {
    forwarding.file = "/var/log/dgaard/dns.log";
    forwarding.forwardUrl = "https://soar.internal/api/v1/dns-alert";
    forwarding.filter = [
      "Blocked"
      "HighlySuspicious"
    ];
  };

  # --- scenario: web UI enabled ---
  cfgWeb = eval {
    server.token = "s3cr3t";
    web = {
      enabled = true;
      port = 9090;
      historySize = 5000;
      beaconingCovThreshold = 0.10;
    };
  };

  # --- scenario: connectivity endpoints enabled ---
  cfgApi = eval {
    server = {
      listen = "0.0.0.0";
      token = "api-token";
    };
    api = {
      enabled = true;
      port = 8080;
      rootPath = "/api/v2";
    };
  };

  # --- scenario: structured forwarding format ---
  cfgJson = eval { forwarding.format = "json"; };

  # --- scenario: NATS federation enabled ---
  cfgNats = eval {
    nats = {
      enable = true;
      url = "nats://broker.internal:4222";
      publishSubject = "site42.events";
      subscribeSubject = "upstream.events";
    };
  };

  toml = cfg: cfg.environment.etc."dgaard-monitor/dgaard-monitor.toml".source;
  execStart = cfg: cfg.systemd.services.dgaard-monitor.serviceConfig.ExecStart;
  restrictAddr = cfg: cfg.systemd.services.dgaard-monitor.serviceConfig.RestrictAddressFamilies;
in

# ---------------------------------------------------------------------------
# Structural assertions
# ---------------------------------------------------------------------------
assert cfgDefaults.environment.etc ? "dgaard-monitor/dgaard-monitor.toml";
assert cfgDefaults.systemd.services ? "dgaard-monitor";
assert cfgDefaults.systemd.services.dgaard-monitor.serviceConfig.Restart == "on-failure";
# headless = true (default) → --headless must appear
assert lib.hasInfix "--headless" (execStart cfgDefaults);
# headless = false → --headless must NOT appear
assert !(lib.hasInfix "--headless" (execStart cfgTui));
# engine_config_path absent when null
assert !(lib.hasInfix "engine_config_path" (builtins.readFile (toml cfgDefaults)));
# engine_config_path present when set
assert lib.hasInfix "engine_config_path" (builtins.readFile (toml cfgWithEngineConfig));
# [nats] table absent when nats.enable = false
assert !(lib.hasInfix "[nats]" (builtins.readFile (toml cfgDefaults)));
# UDS-only by default
assert restrictAddr cfgDefaults == [ "AF_UNIX" ];
# NATS-only (no web/api/ws/mcp) still opens AF_INET / AF_INET6
assert
  restrictAddr cfgNats == [
    "AF_UNIX"
    "AF_INET"
    "AF_INET6"
  ];

# ---------------------------------------------------------------------------
# Content assertions
# ---------------------------------------------------------------------------
pkgs.runCommand "test-dgaard-monitor-module" { nativeBuildInputs = [ pkgs.ripgrep ]; } ''
  echo "=== dgaard-monitor: default TOML ==="
  cat ${toml cfgDefaults}
  # [input] defaults
  rg -qF 'socket = "/tmp/dgaard_stats.sock"'    ${toml cfgDefaults}
  rg -qF 'index = "/var/dgaard/host_mapping.bin"' ${toml cfgDefaults}
  # [input] follows services.dgaard when it runs on the same host
  rg -qF 'socket = "/run/dgaard/stats.sock"'           ${toml cfgWithDgaard}
  rg -qF 'index = "/var/lib/dgaard/host_mapping.bin"'  ${toml cfgWithDgaard}
  rg -qF 'event_buffer = 8192'                  ${toml cfgDefaults}
  # engine_config_path must be absent when null
  if rg -q 'engine_config_path' ${toml cfgDefaults}; then
    echo "FAIL: engine_config_path should be absent"
    exit 1
  fi
  # peer_uid must be absent when null (the monitor then decides itself)
  if rg -q 'peer_uid' ${toml cfgDefaults}; then
    echo "FAIL: peer_uid should be absent"
    exit 1
  fi
  # [persistence] defaults
  rg -qF 'db = "/var/dgaard/stats.sqlite"'           ${toml cfgDefaults}
  rg -qF 'events_retention_hours = 72'               ${toml cfgDefaults}
  rg -qF 'aggregates_retention_days = 90'            ${toml cfgDefaults}
  # [stats] defaults
  rg -qF 'window_secs = 3600'                        ${toml cfgDefaults}
  rg -qF 'max_window_events = 200000'                ${toml cfgDefaults}
  # [tui] defaults
  rg -qF 'tick_ms = 250'   ${toml cfgDefaults}
  rg -qF 'key_quit = "q"'  ${toml cfgDefaults}
  # [forwarding] defaults
  rg -qF 'format = "template"' ${toml cfgDefaults}
  # [server] defaults, shared by every REST module
  rg -qF '[server]'              ${toml cfgDefaults}
  rg -qF 'listen = "127.0.0.1"'  ${toml cfgDefaults}
  rg -qF 'token = "changeme"'    ${toml cfgDefaults}
  # listen/token live only in [server]: exactly one occurrence each
  test "$(rg -c '^(listen|token) = ' ${toml cfgDefaults})" -eq 2
  # [api] default root path matches the monitor's compiled-in one
  rg -qF 'root_path = "/api/v1"' ${toml cfgDefaults}
  # [web] defaults
  rg -qF 'enabled = false'                    ${toml cfgDefaults}
  rg -qF 'port = 8083'                        ${toml cfgDefaults}
  rg -qF 'history_size = 1000'               ${toml cfgDefaults}
  rg -qF 'beaconing_min_observations = 5'    ${toml cfgDefaults}
  rg -qF 'beaconing_cov_threshold = 0.15'    ${toml cfgDefaults}

  echo "=== dgaard-monitor: engine_config_path set ==="
  cat ${toml cfgWithEngineConfig}
  rg -qF 'engine_config_path = "/etc/dgaard/dgaard.toml"' ${toml cfgWithEngineConfig}

  echo "=== dgaard-monitor: forwarding sinks ==="
  cat ${toml cfgForwarding}
  rg -qF 'file = "/var/log/dgaard/dns.log"'                    ${toml cfgForwarding}
  rg -qF 'forward_url = "https://soar.internal/api/v1/dns-alert"' ${toml cfgForwarding}
  rg -qF '"Blocked"'         ${toml cfgForwarding}
  rg -qF '"HighlySuspicious"' ${toml cfgForwarding}
  # file / forward_url must be absent in defaults
  if rg -q 'forward_url' ${toml cfgDefaults}; then
    echo "FAIL: forward_url should be absent in defaults"
    exit 1
  fi

  echo "=== dgaard-monitor: json forwarding ==="
  cat ${toml cfgJson}
  rg -qF 'format = "json"' ${toml cfgJson}

  echo "=== dgaard-monitor: web UI ==="
  cat ${toml cfgWeb}
  rg -qF 'enabled = true'                  ${toml cfgWeb}
  rg -qF 'port = 9090'                     ${toml cfgWeb}
  rg -qF 'token = "s3cr3t"'               ${toml cfgWeb}
  rg -qF 'history_size = 5000'            ${toml cfgWeb}
  rg -qF 'beaconing_cov_threshold = 0.1'  ${toml cfgWeb}

  echo "=== dgaard-monitor: REST API ==="
  cat ${toml cfgApi}
  rg -qF 'enabled = true'      ${toml cfgApi}
  rg -qF 'listen = "0.0.0.0"' ${toml cfgApi}
  rg -qF 'port = 8080'        ${toml cfgApi}
  rg -qF 'token = "api-token"' ${toml cfgApi}
  rg -qF 'root_path = "/api/v2"' ${toml cfgApi}

  echo "=== dgaard-monitor: [nats] absent by default ==="
  if rg -q '\[nats\]' ${toml cfgDefaults}; then
    echo "FAIL: [nats] section should be absent when nats.enable = false"
    exit 1
  fi

  echo "=== dgaard-monitor: [nats] populated when enabled ==="
  cat ${toml cfgNats}
  rg -qF '[nats]'                                       ${toml cfgNats}
  rg -qF 'url = "nats://broker.internal:4222"'          ${toml cfgNats}
  rg -qF 'publish_subject = "site42.events"'            ${toml cfgNats}
  rg -qF 'subscribe_subject = "upstream.events"'        ${toml cfgNats}

  echo "All dgaard-monitor checks passed"
  touch $out
''
