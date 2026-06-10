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
    web = {
      enabled = true;
      port = 9090;
      token = "s3cr3t";
      historySize = 5000;
      beaconingCovThreshold = 0.10;
    };
  };

  # --- scenario: connectivity endpoints enabled ---
  cfgApi = eval {
    api = {
      enabled = true;
      listen = "0.0.0.0";
      port = 8080;
      token = "api-token";
      rootPath = "/api/v1";
    };
  };

  toml = cfg: cfg.environment.etc."dgaard-monitor/dgaard-monitor.toml".source;
  execStart = cfg: cfg.systemd.services.dgaard-monitor.serviceConfig.ExecStart;
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

# ---------------------------------------------------------------------------
# Content assertions
# ---------------------------------------------------------------------------
pkgs.runCommand "test-dgaard-monitor-module" { nativeBuildInputs = [ pkgs.ripgrep ]; } ''
  echo "=== dgaard-monitor: default TOML ==="
  cat ${toml cfgDefaults}
  # [input] defaults
  rg -qF 'socket = "/tmp/dgaard_stats.sock"'    ${toml cfgDefaults}
  rg -qF 'index = "/var/lib/dns/hosts.bin"'     ${toml cfgDefaults}
  # engine_config_path must be absent when null
  if rg -q 'engine_config_path' ${toml cfgDefaults}; then
    echo "FAIL: engine_config_path should be absent"
    exit 1
  fi
  # [persistence] defaults
  rg -qF 'db = "/var/dgaard/stats.sqlite"'           ${toml cfgDefaults}
  rg -qF 'events_retention_hours = 72'               ${toml cfgDefaults}
  rg -qF 'aggregates_retention_days = 90'            ${toml cfgDefaults}
  # [tui] defaults
  rg -qF 'tick_ms = 250'   ${toml cfgDefaults}
  rg -qF 'key_quit = "q"'  ${toml cfgDefaults}
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
  rg -qF 'root_path = "/api/v1"' ${toml cfgApi}

  echo "All dgaard-monitor checks passed"
  touch $out
''
