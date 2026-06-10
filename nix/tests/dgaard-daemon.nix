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
      ../../nix/modules/dgaard-daemon.nix
      base
      {
        services.dgaard-daemon = {
          enable = true;
          package = pkgs.hello; # stub — only the store path matters for ExecStart
        };
      }
    ]).config;

  # --- scenario: every option overridden ---
  cfgCustom =
    (pkgs.nixos [
      ../../nix/modules/dgaard-daemon.nix
      base
      {
        services.dgaard-daemon = {
          enable = true;
          package = pkgs.hello;
          socketPath = "/run/custom/daemon.sock";
          configFile = "/etc/custom/engine.toml";
          logLevel = "debug";
        };
      }
    ]).config;

  tomlDefaults = cfgDefaults.environment.etc."dgaard-daemon/dgaard-daemon.toml".source;
  tomlCustom = cfgCustom.environment.etc."dgaard-daemon/dgaard-daemon.toml".source;
  svc = cfgDefaults.systemd.services.dgaard-daemon;
in

# ---------------------------------------------------------------------------
# Structural assertions (evaluated at nix eval time, fail fast)
# ---------------------------------------------------------------------------
assert cfgDefaults.environment.etc ? "dgaard-daemon/dgaard-daemon.toml";
assert cfgDefaults.systemd.services ? "dgaard-daemon";
assert svc.serviceConfig.Restart == "on-failure";
assert lib.hasInfix "--config /etc/dgaard-daemon/dgaard-daemon.toml" svc.serviceConfig.ExecStart;
assert svc.serviceConfig.NoNewPrivileges == true;

# ---------------------------------------------------------------------------
# Content assertions (run at build time via shell)
# ---------------------------------------------------------------------------
pkgs.runCommand "test-dgaard-daemon-module" { nativeBuildInputs = [ pkgs.ripgrep ]; } ''
  echo "=== dgaard-daemon: default TOML ==="
  cat ${tomlDefaults}
  rg -qF 'socket_path = "/run/dgaard/dgaard-daemon.sock"' ${tomlDefaults}
  rg -qF 'config_file = "/etc/dgaard/dgaard.toml"'       ${tomlDefaults}
  rg -qF 'log_level = "info"'                            ${tomlDefaults}

  echo "=== dgaard-daemon: custom TOML ==="
  cat ${tomlCustom}
  rg -qF 'socket_path = "/run/custom/daemon.sock"' ${tomlCustom}
  rg -qF 'config_file = "/etc/custom/engine.toml"' ${tomlCustom}
  rg -qF 'log_level = "debug"'                     ${tomlCustom}

  echo "All dgaard-daemon checks passed"
  touch $out
''
