{
  config,
  lib,
  pkgs,
  ...
}:
let
  cfg = config.services.dgaard-monitor;
  tomlFormat = pkgs.formats.toml { };

  mkConnectivity = desc: defaultPort: defaultRootPath: {
    enabled = lib.mkOption {
      type = lib.types.bool;
      default = false;
      description = "Enable the ${desc} endpoint.";
    };
    listen = lib.mkOption {
      type = lib.types.str;
      default = "127.0.0.1";
      description = "Listen address for the ${desc} endpoint.";
    };
    port = lib.mkOption {
      type = lib.types.port;
      default = defaultPort;
      description = "Port for the ${desc} endpoint.";
    };
    token = lib.mkOption {
      type = lib.types.str;
      default = "changeme";
      description = "Static bearer token for the ${desc} endpoint.";
    };
    rootPath = lib.mkOption {
      type = lib.types.str;
      default = defaultRootPath;
      description = "URL root path prefix for the ${desc} endpoint.";
    };
  };

  # Build the TOML attrset from individual options.
  # Optional fields (null values) are omitted from the generated file so
  # dgaard-monitor falls back to its compiled-in defaults.
  monitorSettings = {
    input = {
      socket = cfg.input.socket;
      index = cfg.input.index;
    }
    // lib.optionalAttrs (cfg.input.engineConfigPath != null) {
      engine_config_path = cfg.input.engineConfigPath;
    };

    persistence = {
      db = cfg.persistence.db;
      events_retention_hours = cfg.persistence.eventsRetentionHours;
      aggregates_retention_days = cfg.persistence.aggregatesRetentionDays;
    };

    tui = {
      tick_ms = cfg.tui.tickMs;
      key_quit = cfg.tui.keyQuit;
      key_pause = cfg.tui.keyPause;
      key_scroll_up = cfg.tui.keyScrollUp;
      key_scroll_down = cfg.tui.keyScrollDown;
    };

    forwarding = {
      template = cfg.forwarding.template;
      filter = cfg.forwarding.filter;
    }
    // lib.optionalAttrs (cfg.forwarding.file != null) { file = cfg.forwarding.file; }
    // lib.optionalAttrs (cfg.forwarding.forwardUrl != null) {
      forward_url = cfg.forwarding.forwardUrl;
    };

    api = {
      enabled = cfg.api.enabled;
      listen = cfg.api.listen;
      port = cfg.api.port;
      token = cfg.api.token;
      root_path = cfg.api.rootPath;
    };

    websocket = {
      enabled = cfg.websocket.enabled;
      listen = cfg.websocket.listen;
      port = cfg.websocket.port;
      token = cfg.websocket.token;
      root_path = cfg.websocket.rootPath;
    };

    mcp = {
      enabled = cfg.mcp.enabled;
      listen = cfg.mcp.listen;
      port = cfg.mcp.port;
      token = cfg.mcp.token;
      root_path = cfg.mcp.rootPath;
    };

    web = {
      enabled = cfg.web.enabled;
      listen = cfg.web.listen;
      port = cfg.web.port;
      token = cfg.web.token;
      history_size = cfg.web.historySize;
      beaconing_min_observations = cfg.web.beaconingMinObservations;
      beaconing_cov_threshold = cfg.web.beaconingCovThreshold;
    };
  };

  configFile = tomlFormat.generate "dgaard-monitor.toml" monitorSettings;
in
{
  options.services.dgaard-monitor = {
    enable = lib.mkEnableOption "dgaard-monitor DNS telemetry agent";

    package = lib.mkOption {
      type = lib.types.package;
      description = ''
        The dgaard-monitor package to use.
        Example: inputs.dgaard.packages.''${pkgs.system}.dgaard-monitor
      '';
    };

    headless = lib.mkOption {
      type = lib.types.bool;
      default = true;
      description = "Run without the TUI. Must be true when running as a systemd service.";
    };

    # -------------------------------------------------------------------------
    # [input]
    # -------------------------------------------------------------------------
    input = {
      socket = lib.mkOption {
        type = lib.types.str;
        default = "/tmp/dgaard_stats.sock";
        description = "Unix Domain Socket exposed by the dgaard DNS proxy.";
      };
      index = lib.mkOption {
        type = lib.types.str;
        default = "/var/lib/dns/hosts.bin";
        description = "Binary host-index file produced by dgaard (hash → domain mapping).";
      };
      engineConfigPath = lib.mkOption {
        type = lib.types.nullOr lib.types.str;
        default = null;
        example = "/etc/dgaard/dgaard.toml";
        description = ''
          Path to the dgaard engine config file (dgaard.toml).
          When set, the monitor resolves custom security flag bit indices (16–31)
          to their configured labels. Bits without a matching entry render as CUSTOM_BIT_<n>.
        '';
      };
    };

    # -------------------------------------------------------------------------
    # [persistence]
    # -------------------------------------------------------------------------
    persistence = {
      db = lib.mkOption {
        type = lib.types.str;
        default = "/var/dgaard/stats.sqlite";
        description = "Path to the SQLite database file.";
      };
      eventsRetentionHours = lib.mkOption {
        type = lib.types.int;
        default = 72;
        description = "Rolling event log retention in hours (Tier 1).";
      };
      aggregatesRetentionDays = lib.mkOption {
        type = lib.types.int;
        default = 90;
        description = "Hourly aggregates retention in days (Tier 2).";
      };
    };

    # -------------------------------------------------------------------------
    # [tui]
    # -------------------------------------------------------------------------
    tui = {
      tickMs = lib.mkOption {
        type = lib.types.int;
        default = 250;
        description = "Terminal refresh interval in milliseconds.";
      };
      keyQuit = lib.mkOption {
        type = lib.types.str;
        default = "q";
        description = "Key binding for quit.";
      };
      keyPause = lib.mkOption {
        type = lib.types.str;
        default = "space";
        description = "Key binding for pause/resume.";
      };
      keyScrollUp = lib.mkOption {
        type = lib.types.str;
        default = "up";
        description = "Key binding for scroll up.";
      };
      keyScrollDown = lib.mkOption {
        type = lib.types.str;
        default = "down";
        description = "Key binding for scroll down.";
      };
    };

    # -------------------------------------------------------------------------
    # [forwarding]
    # -------------------------------------------------------------------------
    forwarding = {
      file = lib.mkOption {
        type = lib.types.nullOr lib.types.str;
        default = null;
        example = "/var/log/dgaard/dns.log";
        description = "Append formatted event lines to this file. Null writes to stdout.";
      };
      template = lib.mkOption {
        type = lib.types.str;
        default = "{timestamp} {client_ip} {action} {domain}";
        description = "Template for each forwarded line. Placeholders: {timestamp}, {client_ip}, {action}, {domain}.";
      };
      forwardUrl = lib.mkOption {
        type = lib.types.nullOr lib.types.str;
        default = null;
        example = "https://soar.internal/api/v1/dns-alert";
        description = "HTTP(S) endpoint to POST JSON events to (SOAR, Slack webhook, …).";
      };
      filter = lib.mkOption {
        type = lib.types.listOf (
          lib.types.enum [
            "Allowed"
            "Proxied"
            "Blocked"
            "Suspicious"
            "HighlySuspicious"
          ]
        );
        default = [ ];
        example = [
          "Blocked"
          "Suspicious"
          "HighlySuspicious"
        ];
        description = "Action variants to forward. Empty list forwards all events.";
      };
    };

    # -------------------------------------------------------------------------
    # [api] / [websocket] / [mcp]
    # -------------------------------------------------------------------------
    api = mkConnectivity "REST API" 8080 "/api";
    websocket = mkConnectivity "WebSocket" 8081 "/ws";
    mcp = mkConnectivity "MCP (Model Context Protocol)" 8082 "/mcp";

    # -------------------------------------------------------------------------
    # [web]
    # -------------------------------------------------------------------------
    web = {
      enabled = lib.mkOption {
        type = lib.types.bool;
        default = false;
        description = "Enable the embedded web UI server.";
      };
      listen = lib.mkOption {
        type = lib.types.str;
        default = "127.0.0.1";
        description = "Listen address for the web UI.";
      };
      port = lib.mkOption {
        type = lib.types.port;
        default = 8083;
        description = "Port for the web UI.";
      };
      token = lib.mkOption {
        type = lib.types.str;
        default = "changeme";
        description = "Static bearer token for all web UI requests.";
      };
      historySize = lib.mkOption {
        type = lib.types.int;
        default = 1000;
        description = "Maximum DNS events kept in the in-memory rolling log.";
      };
      beaconingMinObservations = lib.mkOption {
        type = lib.types.int;
        default = 5;
        description = "Minimum queries from a single client to a domain before beaconing analysis.";
      };
      beaconingCovThreshold = lib.mkOption {
        type = lib.types.float;
        default = 0.15;
        description = ''
          Coefficient of Variation (std_dev / mean of inter-arrival times) threshold
          below which a client/domain pair is flagged as a potential beacon.
          Lower = stricter. 0.15 catches highly regular C2 beacons.
        '';
      };
    };
  };

  config = lib.mkIf cfg.enable {
    environment.etc."dgaard-monitor/dgaard-monitor.toml".source = configFile;

    systemd.services.dgaard-monitor = {
      description = "Dgaard DNS telemetry monitor";
      wantedBy = [ "multi-user.target" ];
      after = [ "network.target" ];

      serviceConfig = {
        ExecStart = lib.concatStringsSep " " (
          [
            "${lib.getExe cfg.package}"
            "--config /etc/dgaard-monitor/dgaard-monitor.toml"
          ]
          ++ lib.optional cfg.headless "--headless"
        );
        Restart = "on-failure";
        RestartSec = "5s";

        DynamicUser = true;
        StateDirectory = "dgaard";
        StateDirectoryMode = "0750";

        NoNewPrivileges = true;
        ProtectSystem = "strict";
        ProtectHome = true;
        PrivateTmp = true;
        PrivateDevices = true;
        ProtectKernelTunables = true;
        ProtectKernelModules = true;
        ProtectControlGroups = true;
        RestrictNamespaces = true;
        LockPersonality = true;
        MemoryDenyWriteExecute = true;
        RestrictRealtime = true;
      }
      //
        lib.optionalAttrs (cfg.web.enabled || cfg.api.enabled || cfg.websocket.enabled || cfg.mcp.enabled)
          {
            RestrictAddressFamilies = [
              "AF_UNIX"
              "AF_INET"
              "AF_INET6"
            ];
          }
      //
        lib.optionalAttrs
          (!(cfg.web.enabled || cfg.api.enabled || cfg.websocket.enabled || cfg.mcp.enabled))
          {
            RestrictAddressFamilies = [ "AF_UNIX" ];
          };
    };
  };
}
