{ pkgs, lib }:
let
  # Minimal base config required to silence unrelated NixOS assertions.
  base = {
    boot.loader.grub.enable = false;
    system.stateVersion = "24.11";
  };

  # --- scenario: all defaults ---
  cfgDefaults =
    (pkgs.nixos [
      ../../nix/modules/dgaard-rest.nix
      base
      {
        services.dgaard-rest = {
          enable = true;
          package = pkgs.hello; # stub — only the store path matters for ExecStart
        };
      }
    ]).config;

  # --- scenario: every option overridden ---
  cfgCustom =
    (pkgs.nixos [
      ../../nix/modules/dgaard-rest.nix
      base
      {
        services.dgaard-rest = {
          enable = true;
          package = pkgs.hello;
          listenAddr = "0.0.0.0:9090";
          configFile = "/etc/custom/engine.toml";
          logLevel = "debug";
          blockedStatusCode = 403;
        };
      }
    ]).config;

  tomlDefaults = cfgDefaults.environment.etc."dgaard-rest/dgaard-rest.toml".source;
  tomlCustom = cfgCustom.environment.etc."dgaard-rest/dgaard-rest.toml".source;
  svc = cfgDefaults.systemd.services.dgaard-rest;
in

# ---------------------------------------------------------------------------
# Structural assertions (evaluated at nix eval time, fail fast)
# ---------------------------------------------------------------------------
assert cfgDefaults.environment.etc ? "dgaard-rest/dgaard-rest.toml";
assert cfgDefaults.systemd.services ? "dgaard-rest";
assert svc.serviceConfig.Restart == "on-failure";
assert lib.hasInfix "--config /etc/dgaard-rest/dgaard-rest.toml" svc.serviceConfig.ExecStart;
assert svc.serviceConfig.NoNewPrivileges == true;

# ---------------------------------------------------------------------------
# Content assertions (run at build time via shell)
# ---------------------------------------------------------------------------
pkgs.runCommand "test-dgaard-rest-module" { nativeBuildInputs = [ pkgs.ripgrep ]; } ''
  echo "=== dgaard-rest: default TOML ==="
  cat ${tomlDefaults}
  rg -qF 'listen_addr = "127.0.0.1:8080"'         ${tomlDefaults}
  rg -qF 'config_file = "/etc/dgaard/dgaard.toml"' ${tomlDefaults}
  rg -qF 'log_level = "info"'                      ${tomlDefaults}
  rg -qF 'blocked_status_code = 200'               ${tomlDefaults}

  echo "=== dgaard-rest: custom TOML ==="
  cat ${tomlCustom}
  rg -qF 'listen_addr = "0.0.0.0:9090"'            ${tomlCustom}
  rg -qF 'config_file = "/etc/custom/engine.toml"' ${tomlCustom}
  rg -qF 'log_level = "debug"'                     ${tomlCustom}
  rg -qF 'blocked_status_code = 403'               ${tomlCustom}

  echo "All dgaard-rest checks passed"
  touch $out
''
