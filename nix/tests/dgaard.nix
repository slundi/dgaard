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
      pipeline = [
        "Whitelist"
        "HotCache"
        "Upstream"
      ];
    };
    forwarder = {
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

  # --- scenario: security subsections, recursive mode, overridden paths ---
  cfgSecurity = eval {
    server = {
      listen_addr = "192.168.1.1:53";
      mode = "recursive";
      allowed_networks = [ "192.168.1.0/24" ];
      stats_socket_path = "/run/custom/stats.sock";
      pipeline = [
        "Whitelist"
        "HotCache"
        "StaticBlock"
        "SuffixMatch"
        "Heuristics"
        "Upstream"
      ];
    };
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
      special_use = {
        enabled = true;
        isolate_local = false;
      };
    };
    recursive.qname_minimization = true;
    tld.exclude = [
      "top"
      "xyz"
    ];
    sources = {
      blacklists = [ "https://example.com/blocklist.txt" ];
      whitelists = [ ];
      update_interval_hours = 24;
      list_cache_dir = "/var/lib/dgaard/custom-lists";
    };
  };

  toml = cfg: cfg.environment.etc."dgaard/dgaard.toml".source;
  svc = cfgMinimal.systemd.services.dgaard;
  settingsMinimal = cfgMinimal.services.dgaard.settings;
  settingsSecurity = cfgSecurity.services.dgaard.settings;
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
# Written paths default into RuntimeDirectory / StateDirectory
assert settingsMinimal.server.stats_socket_path == "/run/dgaard/stats.sock";
assert settingsMinimal.sources.host_index_path == "/var/lib/dgaard/host_mapping.bin";
assert settingsMinimal.sources.browser_rules_path == "/var/lib/dgaard/browser_rules.txt";
assert settingsMinimal.sources.list_cache_dir == "/var/lib/dgaard/lists";
assert settingsMinimal.recursive.save_path == "/var/lib/dgaard/top-domains.bin";
# User values win over the module defaults
assert settingsSecurity.server.stats_socket_path == "/run/custom/stats.sock";
assert settingsSecurity.sources.list_cache_dir == "/var/lib/dgaard/custom-lists";
# Module defaults merge with sibling user keys instead of replacing the table
assert settingsSecurity.recursive.qname_minimization == true;
assert settingsSecurity.recursive.save_path == "/var/lib/dgaard/top-domains.bin";

# ---------------------------------------------------------------------------
# Content assertions
# ---------------------------------------------------------------------------
pkgs.runCommand "test-dgaard-module" { nativeBuildInputs = [ pkgs.ripgrep ]; } ''
  echo "=== dgaard: minimal settings ==="
  cat ${toml cfgMinimal}
  rg -qF 'listen_addr = "127.0.0.1:53"'           ${toml cfgMinimal}
  rg -qF '[forwarder]'                             ${toml cfgMinimal}
  rg -qF '"1.1.1.1:53"'                            ${toml cfgMinimal}
  rg -qF '"9.9.9.9:53"'                            ${toml cfgMinimal}
  rg -qF 'timeout_ms = 2000'                       ${toml cfgMinimal}
  rg -qF 'enabled = true'                          ${toml cfgMinimal}
  rg -qF 'max_entries = 10000'                     ${toml cfgMinimal}
  rg -qF 'stats_socket_path = "/run/dgaard/stats.sock"'          ${toml cfgMinimal}
  rg -qF 'host_index_path = "/var/lib/dgaard/host_mapping.bin"'  ${toml cfgMinimal}
  rg -qF 'list_cache_dir = "/var/lib/dgaard/lists"'              ${toml cfgMinimal}
  rg -qF 'save_path = "/var/lib/dgaard/top-domains.bin"'         ${toml cfgMinimal}
  # dgaard rejects the pre-recursive [upstream] table outright
  if rg -q '^\[upstream\]' ${toml cfgMinimal}; then
    echo "FAIL: [upstream] must not be generated (renamed to [forwarder])"
    exit 1
  fi

  echo "=== dgaard: security subsections ==="
  cat ${toml cfgSecurity}
  rg -qF 'listen_addr = "192.168.1.1:53"'          ${toml cfgSecurity}
  rg -qF 'mode = "recursive"'                      ${toml cfgSecurity}
  rg -qF 'max_subdomain_depth = 5'                 ${toml cfgSecurity}
  rg -qF 'force_lowercase_ascii = true'            ${toml cfgSecurity}
  rg -qF 'entropy_threshold = 4.0'                 ${toml cfgSecurity}
  rg -qF '"casino"'                                ${toml cfgSecurity}
  rg -qF 'blocking_threshold = 10'                 ${toml cfgSecurity}
  rg -qF 'isolate_local = false'                   ${toml cfgSecurity}
  rg -qF '"top"'                                   ${toml cfgSecurity}
  rg -qF '"https://example.com/blocklist.txt"'     ${toml cfgSecurity}
  rg -qF 'stats_socket_path = "/run/custom/stats.sock"'          ${toml cfgSecurity}
  rg -qF 'list_cache_dir = "/var/lib/dgaard/custom-lists"'       ${toml cfgSecurity}

  echo "All dgaard checks passed"
  touch $out
''
