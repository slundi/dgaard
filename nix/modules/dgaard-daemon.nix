{
  config,
  lib,
  pkgs,
  ...
}:
let
  cfg = config.services.dgaard-daemon;
  tomlFormat = pkgs.formats.toml { };
  # Optional [nats] table is omitted from the generated TOML when disabled
  # so the daemon falls back to its compiled-in default (publisher off).
  configFile = tomlFormat.generate "dgaard-daemon.toml" (
    {
      socket_path = cfg.socketPath;
      config_file = cfg.configFile;
      log_level = cfg.logLevel;
    }
    // lib.optionalAttrs cfg.nats.enable {
      nats = {
        enabled = true;
        url = cfg.nats.url;
        subject = cfg.nats.subject;
      };
    }
  );
in
{
  options.services.dgaard-daemon = {
    enable = lib.mkEnableOption "dgaard-daemon Unix socket domain scoring daemon";

    package = lib.mkOption {
      type = lib.types.package;
      description = ''
        The dgaard-daemon package to use.
        Example: inputs.dgaard.packages.''${pkgs.system}.dgaard-daemon
      '';
    };

    socketPath = lib.mkOption {
      type = lib.types.str;
      default = "/run/dgaard/dgaard-daemon.sock";
      description = "Path to the Unix domain socket the daemon listens on.";
    };

    configFile = lib.mkOption {
      type = lib.types.str;
      default = "/etc/dgaard/dgaard.toml";
      description = "Path to the dgaard engine configuration file (dgaard.toml).";
    };

    logLevel = lib.mkOption {
      type = lib.types.enum [
        "error"
        "warn"
        "info"
        "debug"
        "trace"
      ];
      default = "info";
      description = "env_logger-compatible log level filter.";
    };

    # -------------------------------------------------------------------------
    # [nats] — optional publisher
    # -------------------------------------------------------------------------
    nats = {
      enable = lib.mkOption {
        type = lib.types.bool;
        default = false;
        description = ''
          Publish one JSON ScoreEvent per scoring decision on a NATS subject.
          The Unix socket reply path is never blocked by broker latency.
        '';
      };
      url = lib.mkOption {
        type = lib.types.str;
        default = "nats://127.0.0.1:4222";
        example = "nats://broker.internal:4222";
        description = "NATS server URL the daemon connects to at startup.";
      };
      subject = lib.mkOption {
        type = lib.types.str;
        default = "dgaard.scores";
        example = "site42.scores";
        description = "Subject every ScoreEvent is published on.";
      };
    };
  };

  config = lib.mkIf cfg.enable {
    environment.etc."dgaard-daemon/dgaard-daemon.toml".source = configFile;

    systemd.services.dgaard-daemon = {
      description = "Dgaard domain scoring daemon";
      wantedBy = [ "multi-user.target" ];
      after = [ "network.target" ];

      serviceConfig = {
        ExecStart = "${lib.getExe cfg.package} --config /etc/dgaard-daemon/dgaard-daemon.toml";
        Restart = "on-failure";
        RestartSec = "5s";
        ExecReload = "${pkgs.coreutils}/bin/kill -HUP $MAINPID";

        DynamicUser = true;
        RuntimeDirectory = "dgaard";
        RuntimeDirectoryMode = "0750";

        NoNewPrivileges = true;
        ProtectSystem = "strict";
        ProtectHome = true;
        PrivateTmp = true;
        PrivateDevices = true;
        ProtectKernelTunables = true;
        ProtectKernelModules = true;
        ProtectControlGroups = true;
        # NATS uses TCP — when the publisher is on we must allow IP families.
        RestrictAddressFamilies =
          if cfg.nats.enable then
            [
              "AF_UNIX"
              "AF_INET"
              "AF_INET6"
            ]
          else
            [ "AF_UNIX" ];
        RestrictNamespaces = true;
        LockPersonality = true;
        MemoryDenyWriteExecute = true;
        RestrictRealtime = true;
      };
    };
  };
}
