# When adding new tools to this template, always check the official registry to
# find the correct attribute name:
# * Search Tool: NixOS Package Search
# * Usage: If you find ripgrep, simply add pkgs.ripgrep to the buildInputs in your flake.nix.
{
  description = "Rust Template with automatic pre-commit hooks";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";
    rust-overlay.url = "github:oxalica/rust-overlay";
  };

  outputs =
    {
      self,
      nixpkgs,
      flake-utils,
      rust-overlay,
    }:
    (flake-utils.lib.eachDefaultSystem (
      system:
      let
        overlays = [ (import rust-overlay) ];
        pkgs = import nixpkgs { inherit system overlays; };
        marketplaceExtensions = map pkgs.vscode-utils.buildVscodeMarketplaceExtension [
          {
            mktplcRef = {
              publisher = "ryanluker";
              name = "vscode-coverage-gutters";
              version = "2.14.0";
            };
            sha256 = "sha256-kCJK+Hq08cl0OqJbDOI8nvdDFUiuTolr+Rqrc86OqRo=";
          }
          {
            mktplcRef = {
              publisher = "swellaby";
              name = "vscode-rust-test-adapter";
              version = "0.11.0";
            };
            sha256 = "sha256-BHcShZ3h4OvSQT+0jQSuQIOCfAMc26bxVJPXloAY3Z8=";
          }
          {
            mktplcRef = {
              publisher = "nefrob";
              name = "vscode-just-syntax";
              version = "0.10.1";
            };
            sha256 = "sha256-Eyye+kFdDI2SWtUdyR36QvZ9YVkvRma5aPqDxMfSZKw=";
          }
        ];
        extensions =
          with pkgs.vscode-extensions;
          [
            rust-lang.rust-analyzer
            tamasfe.even-better-toml
            jnoortheen.nix-ide
            mkhl.direnv
            vadimcn.vscode-lldb
            redhat.vscode-yaml
          ]
          ++ marketplaceExtensions;
        # Create a custom VSCodium with these extensions
        custom-codium = pkgs.vscode-with-extensions.override {
          vscode = pkgs.vscodium;
          vscodeExtensions = extensions;
        };

        # Define the rust toolchain from your toml
        rustToolchain = pkgs.rust-bin.fromRustupToolchainFile ./rust-toolchain.toml;

        # Read per-crate Cargo.toml files for package metadata
        mkCrate =
          name:
          pkgs.rustPlatform.buildRustPackage {
            pname = name;
            version = (builtins.fromTOML (builtins.readFile ./${name}/Cargo.toml)).package.version;
            src = ./.;
            cargoLock.lockFile = ./Cargo.lock;
            cargoBuildFlags = [
              "-p"
              name
            ];
          };
      in
      {
        # `nix build .#dgaard` / `nix run .#dgaard`
        packages.dgaard = mkCrate "dgaard";
        packages.dgaard-daemon = mkCrate "dgaard-daemon";
        packages.dgaard-monitor = mkCrate "dgaard-monitor";
        packages.default = self.packages.${system}.dgaard;

        # `nix run .#codium` — VSCodium with all extensions pre-installed
        packages.codium = custom-codium;

        # NixOS module evaluation tests — `nix build .#checks.<system>.dgaard-*-module`
        checks = {
          dgaard-daemon-module = pkgs.callPackage ./nix/tests/dgaard-daemon.nix { };
          dgaard-monitor-module = pkgs.callPackage ./nix/tests/dgaard-monitor.nix { };
          dgaard-module = pkgs.callPackage ./nix/tests/dgaard.nix { };
        };

        devShells.default = pkgs.mkShell {
          buildInputs = with pkgs; [
            rustToolchain
            cargo-dist
            cargo-nextest
            cargo-cross
            cargo-machete
            cargo-audit
            cargo-deny
            cargo-llvm-cov # Coverage instrumentation via LLVM
            jaq # JSON processor (used by coverage-check)
            prek # pre-commit
            gitleaks # The compiled secret scanner or trufflehog or ripgrep
            just # Command runner
            bacon # Background checker (cargo check/clippy/test on save)
            git-cliff # Changelog generator from conventional commits
            mold # Fast linker (referenced in .cargo/config.toml)
            dprint # Formatter for JSON, TOML, Markdown
            nixfmt-rfc-style # Nix formatter (RFC 166)
            yamlfmt # YAML formatter
            nil # Nix language server (referenced in .vscode/settings.json)
          ];

          # This runs when the shell starts
          shellHook = ''
            echo "Rust Dev Shell Loaded"
            echo "Tip: Run 'nix run .#codium -- .' to start VSCodium with all extensions pre-installed."
            # Automatically install hooks if .git exists
            if [ -d .git ] && command -v prek >/dev/null; then
              prek install
            fi
          '';
        };
      }
    ))
    // {
      nixosModules = {
        dgaard = import ./nix/modules/dgaard.nix;
        dgaard-daemon = import ./nix/modules/dgaard-daemon.nix;
        dgaard-monitor = import ./nix/modules/dgaard-monitor.nix;
      };
    };
}
