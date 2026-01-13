{
  description = "OA-Verifier - Zero-trust attestation service";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-24.05";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = { self, nixpkgs, flake-utils }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        pkgs = import nixpkgs { inherit system; };
        
        # Fixed timestamp for reproducibility (2024-01-01T00:00:00Z)
        SOURCE_DATE_EPOCH = "1704067200";

        # Go server binary (reproducible)
        server = pkgs.buildGoModule {
          pname = "oa-verifier";
          version = "0.1.0";
          src = ./.;
          
          subPackages = [ "cmd/verifier" ];
          vendorHash = "sha256-bC7/E9aeC2GEixomazMFe1ej93Avq8ZmFbZmqbfSihw=";
          
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
            license = licenses.mit;
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
              ExposedPorts."8443/tcp" = {};
              Env = [ "SSL_CERT_FILE=/etc/ssl/certs/ca-bundle.crt" ];
              WorkingDir = "/app";
            };
          };

          default = server;
        };

        devShells.default = pkgs.mkShell {
          buildInputs = [ pkgs.go_1_22 pkgs.gopls pkgs.docker pkgs.azure-cli pkgs.jq ];
          
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
