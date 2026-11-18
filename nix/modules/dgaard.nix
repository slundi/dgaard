{
  config,
  lib,
  pkgs,
  ...
}:
let
  cfg = config.services.dgaard;
  tomlFormat = pkgs.formats.toml { };
  configFile = tomlFormat.generate "dgaard.toml" cfg.settings;
in
{
  options.services.dgaard = {
    enable = lib.mkEnableOption "dgaard DNS security proxy";

    package = lib.mkOption {
      type = lib.types.package;
      description = ''
        The dgaard package to use.
        Example: inputs.dgaard.packages.''${pkgs.system}.dgaard
      '';
    };

    settings = lib.mkOption {
      type = tomlFormat.type;
      default = { };
      description = ''
        dgaard configuration as a Nix attribute set. The entire structure maps
        1:1 to dgaard.toml. See config.example.toml in the dgaard source for
        the full reference with comments.

        Minimal required keys: server.listen_addr, forwarder.servers (or
        server.mode = "recursive"). The former [upstream] table is rejected
        by dgaard: use [forwarder]. TLD lists take bare lowercase labels
        ("xyz", not ".xyz").

        Paths dgaard writes to (stats socket, host index, list cache,
        popularity snapshot) default to the service's RuntimeDirectory and
        StateDirectory, the only writable locations under ProtectSystem=strict.
      '';
      example = lib.literalExpression ''
        {
          server = {
            listen_addr = "192.168.1.1:53";
            mode = "forwarder";
            allowed_networks = [ "127.0.0.1/32" "192.168.1.0/24" ];
            metrics_listen = "127.0.0.1:9153";
            pipeline = [ "Whitelist" "HotCache" "StaticBlock" "SuffixMatch" "Heuristics" "Upstream" ];
          };
          server.runtime = {
            worker_threads = 1;
          };
          security.structure = {
            max_subdomain_depth = 5;
            max_domain_length = 128;
            force_lowercase_ascii = true;
            block_chaos_class = true;
          };
          security.intelligence = {
            enabled = true;
            entropy_threshold = 4.0;
          };
          security.special_use = {
            enabled = true;
            isolate_local = true;
          };
          forwarder = {
            servers = [ "1.1.1.1:53" "9.9.9.9:53" ];
            timeout_ms = 2000;
            use_0x20_randomization = true;
          };
          tld.exclude = [ "top" "xyz" ];
          cache = {
            enabled = true;
            max_entries = 10000;
          };
          sources = {
            blacklists = [ "https://pgl.yoyo.org/as/serverlist.php?hostformat=adblock&showintro=1&mimetype=plaintext" ];
            whitelists = [ ];
            update_interval_hours = 24;
          };
        }
      '';
    };
  };

  config = lib.mkIf cfg.enable {
    # The compiled-in defaults point at /tmp (private here) and /var/dgaard
    # (read-only here), so redirect every written path into the unit's own
    # runtime and state directories.
    services.dgaard.settings = {
      server.stats_socket_path = lib.mkDefault "/run/dgaard/stats.sock";
      sources = {
        host_index_path = lib.mkDefault "/var/lib/dgaard/host_mapping.bin";
        browser_rules_path = lib.mkDefault "/var/lib/dgaard/browser_rules.txt";
        list_cache_dir = lib.mkDefault "/var/lib/dgaard/lists";
      };
      recursive.save_path = lib.mkDefault "/var/lib/dgaard/top-domains.bin";
    };

    environment.etc."dgaard/dgaard.toml".source = configFile;

    systemd.services.dgaard = {
      description = "Dgaard DNS security proxy";
      wantedBy = [ "multi-user.target" ];
      after = [ "network.target" ];

      serviceConfig = {
        ExecStart = "${lib.getExe cfg.package} --config /etc/dgaard/dgaard.toml";
        Restart = "on-failure";
        RestartSec = "5s";
        ExecReload = "${pkgs.coreutils}/bin/kill -HUP $MAINPID";

        DynamicUser = true;
        RuntimeDirectory = "dgaard";
        RuntimeDirectoryMode = "0750";
        StateDirectory = "dgaard";
        StateDirectoryMode = "0750";

        # Port 53 requires this capability when running as non-root.
        AmbientCapabilities = [ "CAP_NET_BIND_SERVICE" ];
        CapabilityBoundingSet = [ "CAP_NET_BIND_SERVICE" ];

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
        RestrictRealtime = true;
      };
    };
  };
}
