{ pkgs, lib }:
let
  base = {
    boot.loader.grub.enable = false;
    system.stateVersion = "24.11";
  };

  eval =
    settings:
    (pkgs.nixos [
      ../../nix/modules/dgaard.nix
      base
      {
        services.dgaard = {
          enable = true;
          package = pkgs.hello;
          inherit settings;
        };
      }
    ]).config;

  # --- scenario: minimal required settings ---
  cfgMinimal = eval {
    server = {
      listen_addr = "127.0.0.1:53";
      allowed_networks = [ "127.0.0.1/32" ];
      stats_socket_path = "/run/dgaard/stats.sock";
      pipeline = [
        "Whitelist"
        "HotCache"
        "Upstream"
      ];
    };
    upstream = {
      servers = [
        "1.1.1.1:53"
        "9.9.9.9:53"
      ];
      timeout_ms = 2000;
    };
    cache = {
      enabled = true;
      max_entries = 10000;
    };
  };

  # --- scenario: security subsections ---
  cfgSecurity = eval {
    server = {
      listen_addr = "192.168.1.1:53";
      allowed_networks = [ "192.168.1.0/24" ];
      stats_socket_path = "/run/dgaard/stats.sock";
      pipeline = [
        "Whitelist"
        "HotCache"
        "StaticBlock"
        "SuffixMatch"
        "Heuristics"
        "Upstream"
      ];
    };
    upstream.servers = [ "9.9.9.9:53" ];
    security = {
      structure = {
        max_subdomain_depth = 5;
        force_lowercase_ascii = true;
        block_chaos_class = true;
      };
      intelligence = {
        enabled = true;
        entropy_threshold = 4.0;
        entropy_fast = true;
      };
      lexical = {
        enabled = true;
        banned_keywords = [
          "casino"
          "porno"
        ];
        strict_keyword_matching = true;
      };
      scoring = {
        blocking_threshold = 10;
        highly_suspicious_threshold = 7;
      };
    };
    tld.exclude = [
      ".top"
      ".xyz"
    ];
    sources = {
      blacklists = [ "https://example.com/blocklist.txt" ];
      whitelists = [ ];
      update_interval_hours = 24;
    };
  };

  toml = cfg: cfg.environment.etc."dgaard/dgaard.toml".source;
  svc = cfgMinimal.systemd.services.dgaard;
in

# ---------------------------------------------------------------------------
# Structural assertions
# ---------------------------------------------------------------------------
assert cfgMinimal.environment.etc ? "dgaard/dgaard.toml";
assert cfgMinimal.systemd.services ? "dgaard";
assert svc.serviceConfig.Restart == "on-failure";
assert lib.hasInfix "--config /etc/dgaard/dgaard.toml" svc.serviceConfig.ExecStart;
# Port 53 requires this capability
assert lib.elem "CAP_NET_BIND_SERVICE" svc.serviceConfig.AmbientCapabilities;
assert lib.elem "CAP_NET_BIND_SERVICE" svc.serviceConfig.CapabilityBoundingSet;
# SIGHUP reload
assert lib.hasInfix "-HUP" svc.serviceConfig.ExecReload;

# ---------------------------------------------------------------------------
# Content assertions
# ---------------------------------------------------------------------------
pkgs.runCommand "test-dgaard-module" { nativeBuildInputs = [ pkgs.ripgrep ]; } ''
  echo "=== dgaard: minimal settings ==="
  cat ${toml cfgMinimal}
  rg -qF 'listen_addr = "127.0.0.1:53"'           ${toml cfgMinimal}
  rg -qF '"1.1.1.1:53"'                            ${toml cfgMinimal}
  rg -qF '"9.9.9.9:53"'                            ${toml cfgMinimal}
  rg -qF 'timeout_ms = 2000'                       ${toml cfgMinimal}
  rg -qF 'enabled = true'                          ${toml cfgMinimal}
  rg -qF 'max_entries = 10000'                     ${toml cfgMinimal}

  echo "=== dgaard: security subsections ==="
  cat ${toml cfgSecurity}
  rg -qF 'listen_addr = "192.168.1.1:53"'          ${toml cfgSecurity}
  rg -qF 'max_subdomain_depth = 5'                 ${toml cfgSecurity}
  rg -qF 'force_lowercase_ascii = true'            ${toml cfgSecurity}
  rg -qF 'entropy_threshold = 4.0'                 ${toml cfgSecurity}
  rg -qF '"casino"'                                ${toml cfgSecurity}
  rg -qF 'blocking_threshold = 10'                 ${toml cfgSecurity}
  rg -qF '".top"'                                  ${toml cfgSecurity}
  rg -qF '"https://example.com/blocklist.txt"'     ${toml cfgSecurity}

  echo "All dgaard checks passed"
  touch $out
''
