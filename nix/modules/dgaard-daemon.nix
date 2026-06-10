{
  config,
  lib,
  pkgs,
  ...
}:
let
  cfg = config.services.dgaard-daemon;
  tomlFormat = pkgs.formats.toml { };
  configFile = tomlFormat.generate "dgaard-daemon.toml" {
    socket_path = cfg.socketPath;
    config_file = cfg.configFile;
    log_level = cfg.logLevel;
  };
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
        RestrictAddressFamilies = [ "AF_UNIX" ];
        RestrictNamespaces = true;
        LockPersonality = true;
        MemoryDenyWriteExecute = true;
        RestrictRealtime = true;
      };
    };
  };
}
