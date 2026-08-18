{
  description = "Flakes file for flakevuln";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    # Allows structuring the flake with the NixOS module system
    flake-parts = {
      url = "github:hercules-ci/flake-parts";
      inputs.nixpkgs-lib.follows = "nixpkgs";
    };
    # flake-parts module for finding the project root directory
    flake-root.url = "github:srid/flake-root";
    # pre-commit hooks, also wired up as the `nix fmt` formatter
    git-hooks-nix = {
      url = "github:cachix/git-hooks.nix";
      inputs.nixpkgs.follows = "nixpkgs";
    };
    sbomnix = {
      url = "github:tiiuae/sbomnix";
      inputs = {
        flake-root.follows = "flake-root";
        flake-parts.follows = "flake-parts";
        nixpkgs.follows = "nixpkgs";
      };
    };
  };

  outputs =
    inputs@{ flake-parts, ... }:
    flake-parts.lib.mkFlake { inherit inputs; } {
      systems = [
        "x86_64-linux"
        "aarch64-linux"
        "x86_64-darwin"
        "aarch64-darwin"
      ];

      imports = [
        ./nix
      ];
    };
}
