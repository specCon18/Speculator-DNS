{ pkgs ? import <nixpkgs> { } }:
pkgs.mkShell {
  # Get dependencies from the main package
  inputsFrom = [ (pkgs.callPackage ./default.nix { }) ];
  # Additional tooling
  buildInputs = with pkgs; [
    cargo
    cargo-watch
    rustc
    rustup
    clippy
    rust-analyzer
    pkg-config
  ];
}
