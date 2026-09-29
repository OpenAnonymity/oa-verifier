{
  description = "OA-Verifier - Zero-trust attestation service";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-25.05";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = { self, nixpkgs, flake-utils }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        pkgs = import nixpkgs { inherit system; };
        
        # Fixed timestamp for reproducibility (2024-01-01T00:00:00Z)
        SOURCE_DATE_EPOCH = "1704067200";

        # Go toolchain. Go 1.22 is out of upstream support (no security
        # fixes); nixos-25.05 ships Go 1.24. go.mod's "go 1.22.0" directive
        # stays: it is the minimum language version, and a newer toolchain
        # builds it unchanged.
        #
        # NOTE: after changing the nixpkgs input above, flake.lock must be
        # re-pinned with `nix flake update nixpkgs` (or
        # `nix flake lock --update-input nixpkgs`) and committed; otherwise
        # `nix build` re-resolves the branch tip on every run and the build is
        # no longer reproducible.
        go = pkgs.go_1_24;

        # Go server binary (reproducible)
        server = pkgs.buildGo124Module {
          pname = "oa-verifier";
          version = "0.1.0";
          src = ./.;

          subPackages = [ "cmd/verifier" ];
          # vendorHash covers the vendored module tree derived from go.mod /
          # go.sum, not the toolchain. Only change it when go.mod or go.sum
          # change; a mismatch fails the build and prints the expected hash.
          vendorHash = "sha256-Gw49LP2f8VWvUqViQayxKH+fMuj4OCjCHIgFSBGPvuw=";
          
          CGO_ENABLED = 0;
          
          ldflags = [ "-s" "-w" "-buildid=" ];
          
          preBuild = ''
            export SOURCE_DATE_EPOCH=${SOURCE_DATE_EPOCH}
          '';

          postInstall = ''
            mv $out/bin/verifier $out/bin/oa-verifier
          '';
          
          meta = with pkgs.lib; {
            description = "OA-Verifier attestation service";
            license = licenses.agpl3Plus;
            mainProgram = "oa-verifier";
          };
        };

      in {
        packages = {
          inherit server;

          # Reproducible container image
          # NOTE: Must be built on x86_64-linux for Azure deployment
          # GitHub Actions runs on x86_64-linux, so CI builds work correctly
          container = pkgs.dockerTools.buildImage {
            name = "oa-verifier";
            tag = "latest";
            created = "2024-01-01T00:00:00Z";  # Fixed timestamp
            
            copyToRoot = pkgs.buildEnv {
              name = "image-root";
              paths = [ pkgs.cacert pkgs.tzdata server ];
              pathsToLink = [ "/bin" "/etc" ];
            };
            
            config = {
              Entrypoint = [ "/bin/oa-verifier" ];
              ExposedPorts."443/tcp" = {};
              Env = [ "SSL_CERT_FILE=/etc/ssl/certs/ca-bundle.crt" ];
              WorkingDir = "/app";
            };
          };

          default = server;
        };

        devShells.default = pkgs.mkShell {
          buildInputs = [ go pkgs.gopls pkgs.docker pkgs.azure-cli pkgs.jq ];
          
          shellHook = ''
            echo "OA-Verifier Dev Environment"
            echo "  nix build .#server    - Build Go binary"
            echo "  nix build .#container - Build Docker image (Linux only)"
          '';
        };

        apps.default = flake-utils.lib.mkApp {
          drv = server;
          name = "oa-verifier";
        };
      }
    );
}
