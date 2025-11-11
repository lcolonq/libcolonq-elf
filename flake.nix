{
  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixpkgs-unstable";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = { self, nixpkgs, ... }@inputs:
    inputs.flake-utils.lib.eachDefaultSystem
      (system:
        let
          nm = "elf";
          pkgs = nixpkgs.legacyPackages.${system};
          p = pkgs.pkgsMusl.stdenv.mkDerivation {
            pname = nm;
            version = "git";
            src = ./.;
            hardeningDisable = ["all"];
            installPhase = ''
              make prefix=$out install
            '';
          };
        in {
          packages = {
            "${nm}" = p;
            default = p;
          };
          devShells.default = pkgs.mkShell {
            hardeningDisable = ["all"];
            NIX_ENFORCE_NO_NATIVE = "";
            buildInputs = [
              pkgs.musl
              pkgs.valgrind
              pkgs.universal-ctags
            ];
          };
        }
      );
}
