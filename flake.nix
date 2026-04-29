{
  description = "Shikumi (仕組み) — config discovery, hot-reload, and ArcSwap store";

  inputs = {
    nixpkgs.url = "github:nixos/nixpkgs?ref=nixos-25.11";
    crate2nix.url = "github:nix-community/crate2nix";
    fenix = {
      url = "github:nix-community/fenix";
      inputs.nixpkgs.follows = "nixpkgs";
    };
    substrate = {
      url = "github:pleme-io/substrate";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };

  outputs =
    { self, nixpkgs, crate2nix, fenix, substrate, ... }:
    (import "${substrate}/lib/rust-library-flake.nix" {
      inherit nixpkgs crate2nix fenix;
    }) {
      libraryName = "shikumi";
      src = self;
    };
}
