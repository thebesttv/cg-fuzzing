let
  # 2025-11-24: 205b12d8b7cd4802fbcb8e8ef6a0f1408781a4f9
  pkgs = import <nixpkgs> { config = {}; overlays = []; };

  # nix-shell --pure
  # nixpkgs = fetchTarball "https://github.com/NixOS/nixpkgs/tarball/nixos-unstable";
  # pkgs = import nixpkgs { config = {}; overlays = []; };
in

# { pkgs ? import <nixpkgs> { config = {}; overlays = []; } }:

pkgs.mkShell
# (pkgs.mkShell.override { stdenv = pkgs.ccacheStdenv; })
# (pkgs.mkShell.override { stdenv = pkgs.clangStdenv; })
{
  packages = with pkgs; [
    aflplusplus
    gnuplot
    uftraceFull
    wllvm
    libllvm
    parallel-full
  ];
}
