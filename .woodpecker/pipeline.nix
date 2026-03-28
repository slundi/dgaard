{pkgs}: let
  woodpecker-yml = pkgs.callPackage ./woodpecker/.woodpecker.yaml {};
in
  pkgs.stdenv.mkDerivation {
    name = "woodpecker-pipeline";

    phases = ["unpackPhase"];

    unpackPhase = ''
      mkdir -p $out/nix-support
      echo "file ${woodpecker-yml} .woodpecker.yaml" > $out/nix-support/hydra-build-products
    '';
  }
