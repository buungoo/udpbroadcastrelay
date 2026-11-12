{
  description = "UDP broadcast relay and IPv6-to-IPv4 DIAL gateway";

  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";

  outputs = {nixpkgs, ...}: let
    systems = ["x86_64-linux" "aarch64-linux"];
    forSystems = nixpkgs.lib.genAttrs systems;
  in {
    packages = forSystems (system: let
      pkgs = nixpkgs.legacyPackages.${system};
      package = pkgs.callPackage ./package.nix {};
    in {
      default = package;
      udpbroadcastrelay = package;
    });

    devShells = forSystems (system: let
      pkgs = nixpkgs.legacyPackages.${system};
    in {
      default = pkgs.mkShell {
        inputsFrom = [(pkgs.callPackage ./package.nix {})];
      };
    });

    nixosModules.default = import ./module.nix;
  };
}
