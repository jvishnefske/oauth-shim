{
  description = "oauth-shim: OAuth login shim (Google / Microsoft / GitHub) with SQLite sessions";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-25.05";
  };

  outputs = { self, nixpkgs }:
    let
      systems = [ "x86_64-linux" "aarch64-linux" "x86_64-darwin" "aarch64-darwin" ];
      forAllSystems = f: nixpkgs.lib.genAttrs systems (system: f system);

      # Build from the committed Cargo.lock — no cargoHash to maintain.
      mkPackage = pkgs: pkgs.rustPlatform.buildRustPackage {
        pname = "oauth-shim";
        version = "0.1.0";
        src = nixpkgs.lib.cleanSource ./.;
        cargoLock.lockFile = ./Cargo.lock;
        # rusqlite uses the bundled sqlite (cc), no system deps required.
        meta = {
          description = "OAuth login shim with SQLite-backed sessions";
          mainProgram = "oauth-shim";
        };
      };
    in
    {
      packages = forAllSystems (system:
        let
          pkgs = nixpkgs.legacyPackages.${system};
        in
        {
          default = mkPackage pkgs;
        }
        // nixpkgs.lib.optionalAttrs (pkgs.stdenv.isLinux) rec {
          # Fully static musl binary (same artifact class as the Dockerfile).
          static = mkPackage pkgs.pkgsStatic;

          # Minimal OCI image, loadable with: nix build .#image && docker load < result
          image = pkgs.dockerTools.buildLayeredImage {
            name = "oauth-shim";
            tag = "latest";
            contents = [ pkgs.dockerTools.caCertificates ]; # harmless; TLS roots are compiled in
            config = {
              Entrypoint = [ "${static}/bin/oauth-shim" ];
              Env = [ "DB_PATH=/data/shim.db" "LISTEN_ADDR=0.0.0.0:8080" ];
              ExposedPorts = { "8080/tcp" = { }; };
              Volumes = { "/data" = { }; };
              User = "65534:65534";
            };
            # Writable /data owned by nobody.
            fakeRootCommands = ''
              mkdir -p data
              chown 65534:65534 data
            '';
            enableFakechroot = false;
          };
        });

      devShells = forAllSystems (system:
        let pkgs = nixpkgs.legacyPackages.${system}; in {
          default = pkgs.mkShell {
            packages = with pkgs; [ cargo rustc rustfmt clippy rust-analyzer sqlite ];
            env.RUST_LOG = "info";
          };
        });

      checks = forAllSystems (system: {
        build = self.packages.${system}.default;
      });

      nixosModules.default = { config, lib, pkgs, ... }:
        let cfg = config.services.oauth-shim; in {
          options.services.oauth-shim = {
            enable = lib.mkEnableOption "oauth-shim login service";
            package = lib.mkOption {
              type = lib.types.package;
              default = self.packages.${pkgs.system}.default;
              description = "oauth-shim package to run.";
            };
            listenAddr = lib.mkOption {
              type = lib.types.str;
              default = "127.0.0.1:8080";
              description = "Bind address (put Traefik/nginx in front).";
            };
            baseUrl = lib.mkOption {
              type = lib.types.str;
              example = "https://auth.example.com";
              description = "Public base URL; must match registered redirect URIs.";
            };
            cookieDomain = lib.mkOption {
              type = lib.types.nullOr lib.types.str;
              default = null;
              example = "example.com";
              description = "Parent domain for cross-subdomain SSO cookies (ForwardAuth).";
            };
            adminEmails = lib.mkOption {
              type = lib.types.listOf lib.types.str;
              default = [ ];
              description = "Emails granted admin on login.";
            };
            verifyRequireAdmin = lib.mkOption {
              type = lib.types.bool;
              default = true;
              description = "Whether /auth/verify requires is_admin.";
            };
            environmentFile = lib.mkOption {
              type = lib.types.path;
              description = ''
                EnvironmentFile holding secrets:
                GOOGLE_/MICROSOFT_/GITHUB_CLIENT_ID and _CLIENT_SECRET.
                Keep it out of the Nix store (e.g. agenix/sops-nix or /run/secrets).
              '';
            };
          };

          config = lib.mkIf cfg.enable {
            systemd.services.oauth-shim = {
              description = "oauth-shim OAuth login service";
              wantedBy = [ "multi-user.target" ];
              after = [ "network-online.target" ];
              wants = [ "network-online.target" ];
              environment = {
                LISTEN_ADDR = cfg.listenAddr;
                BASE_URL = cfg.baseUrl;
                DB_PATH = "/var/lib/oauth-shim/shim.db";
                ADMIN_EMAILS = lib.concatStringsSep "," cfg.adminEmails;
                VERIFY_REQUIRE_ADMIN = lib.boolToString cfg.verifyRequireAdmin;
              } // lib.optionalAttrs (cfg.cookieDomain != null) {
                COOKIE_DOMAIN = cfg.cookieDomain;
              };
              serviceConfig = {
                ExecStart = lib.getExe cfg.package;
                EnvironmentFile = cfg.environmentFile;
                DynamicUser = true;
                StateDirectory = "oauth-shim";
                StateDirectoryMode = "0700";
                Restart = "on-failure";
                # Hardening
                NoNewPrivileges = true;
                ProtectSystem = "strict";
                ProtectHome = true;
                PrivateTmp = true;
                PrivateDevices = true;
                ProtectKernelTunables = true;
                ProtectKernelModules = true;
                ProtectControlGroups = true;
                RestrictAddressFamilies = [ "AF_INET" "AF_INET6" ];
                RestrictNamespaces = true;
                LockPersonality = true;
                MemoryDenyWriteExecute = true;
                CapabilityBoundingSet = "";
                AmbientCapabilities = "";
                SystemCallArchitectures = "native";
                SystemCallFilter = [ "@system-service" "~@privileged" ];
              };
            };
          };
        };
    };
}
