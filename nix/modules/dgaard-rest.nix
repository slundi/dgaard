{
  config,
  lib,
  pkgs,
  ...
}:
let
  cfg = config.services.dgaard-rest;
  tomlFormat = pkgs.formats.toml { };
  configFile = tomlFormat.generate "dgaard-rest.toml" {
    listen_addr = cfg.listenAddr;
    config_file = cfg.configFile;
    log_level = cfg.logLevel;
    blocked_status_code = cfg.blockedStatusCode;
  };
in
{
  options.services.dgaard-rest = {
    enable = lib.mkEnableOption "dgaard-rest HTTP REST API for domain scoring";

    package = lib.mkOption {
      type = lib.types.package;
      description = ''
        The dgaard-rest package to use.
        Example: inputs.dgaard.packages.''${pkgs.system}.dgaard-rest
      '';
    };

    listenAddr = lib.mkOption {
      type = lib.types.str;
      default = "127.0.0.1:8080";
      description = "Address and port the HTTP server binds to (host:port).";
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

    blockedStatusCode = lib.mkOption {
      type = lib.types.enum [
        200
        403
      ];
      default = 200;
      description = "HTTP status code returned for blocked domains (200 or 403).";
    };
  };

  config = lib.mkIf cfg.enable {
    environment.etc."dgaard-rest/dgaard-rest.toml".source = configFile;

    systemd.services.dgaard-rest = {
      description = "Dgaard REST API for domain scoring";
      wantedBy = [ "multi-user.target" ];
      after = [ "network.target" ];

      serviceConfig = {
        ExecStart = "${lib.getExe cfg.package} --config /etc/dgaard-rest/dgaard-rest.toml";
        Restart = "on-failure";
        RestartSec = "5s";
        ExecReload = "${pkgs.coreutils}/bin/kill -HUP $MAINPID";

        DynamicUser = true;

        NoNewPrivileges = true;
        ProtectSystem = "strict";
        ProtectHome = true;
        PrivateTmp = true;
        PrivateDevices = true;
        ProtectKernelTunables = true;
        ProtectKernelModules = true;
        ProtectControlGroups = true;
        RestrictAddressFamilies = [
          "AF_UNIX"
          "AF_INET"
          "AF_INET6"
        ];
        RestrictNamespaces = true;
        LockPersonality = true;
        MemoryDenyWriteExecute = true;
        RestrictRealtime = true;
      };
    };
  };
}
