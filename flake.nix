# Nix Flake for R-SRP Ultra - Hermetic Build System
# Provides reproducible, offline-capable builds

{
  description = "R-SRP Ultra - Hermetic Build Configuration";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-24.05";
    flake-utils.url = "github:numtide/flake-utils";
    rust-overlay = {
      url = "github:oxalica/rust-overlay";
      inputs = {
        nixpkgs.follows = "nixpkgs";
        flake-utils.follows = "flake-utils";
      };
    };
  };

  outputs = { self, nixpkgs, flake-utils, rust-overlay }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        pkgs = import nixpkgs {
          inherit system;
          overlays = [ rust-overlay.overlays.default ];
        };
      in
      {
        packages = {
          rsrp-ultra = pkgs.rustPlatform.buildRustPackage {
            pname = "rsrp-ultra";
            version = "1.0.0";
            
            src = ./.;
            
            cargoLock = ./Cargo.lock;
            
            # Offline build - no network
            # All dependencies must be in Cargo.lock
            buildInputs = with pkgs; [
              pkg-config
              openssl
              zlib
            ];
            
            # Security hardening
            hardeningDisable = [ "pie" ];
            hardeningEnable = [ "all" ];
            
            # Reproducible build settings
            dontStrip = false;
            stripDebugFlags = [ "-S" "-s" ];
            
            # Locked dependencies
            # Uses Cargo.lock - no network access during build
          };

          # Individual services
          api-service = pkgs.rustPlatform.buildRustPackage {
            pname = "api-service";
            version = "1.0.0";
            src = ./services/api-service;
            cargoLock = ./Cargo.lock;
            buildInputs = with pkgs; [ pkg-config openssl ];
          };

          crue-engine = pkgs.rustPlatform.buildRustPackage {
            pname = "crue-engine";
            version = "1.0.0";
            src = ./crates/crue-engine;
            cargoLock = ./Cargo.lock;
          };

          crypto-core = pkgs.rustPlatform.buildRustPackage {
            pname = "crypto-core";
            version = "1.0.0";
            src = ./crates/crypto-core;
            cargoLock = ./Cargo.lock;
          };

          # Development shell
          devShells.default = pkgs.mkShell {
            buildInputs = with pkgs; [
              (pkgs.rust-bin.stable.latest.default.override {
                extensions = [ "rust-src" "rustfmt" "clippy" "miri" ];
              })
              cargo
              rustup
              pkg-config
              openssl
              # Verification tools
              kani
            ];

            # Prevent network access
            # This can be enabled in development but disabled in CI
            # NIX_NETWORK_ALLOW = "";
            # NIX_NETWORK_FORBID = "1";
          };

          # Verifier shell - includes all verification tools
          verifierShells = {
            default = pkgs.mkShell {
              buildInputs = with pkgs; [
                (pkgs.rust-bin.nightly.latest.default.override {
                  extensions = [ "rust-src" "miri" ];
                })
                # Kani model checker
                kani
                # Fuzzing
                cargo-fuzz
                # Coverage
                cargo-llvm-cov
                # Security audit
                cargo-audit
                cargo-deny
                # SBOM
                cargo-sbom
                syft
              ];
            };
          };
        };

        # Default package
        defaultPackage = self.packages.${system}.rsrp-ultra;
      }
    );

  # Nix configuration for hermetic builds
  nixConfig = {
    # Use binary caches
    binary-caches = [ "https://cache.nixos.org" ];
    
    # Trusted users (add CI users here)
    # trusted-users = [ "ci" ];
    
    # Allow insecure hashes for reproducibility
    # allow-insecure-hashes = false;
  };
}
