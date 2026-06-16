# oauth-shim

[![CI](https://github.com/jvishnefske/oauth-shim/actions/workflows/ci.yml/badge.svg)](https://github.com/jvishnefske/oauth-shim/actions/workflows/ci.yml)
[![Docker image](https://github.com/jvishnefske/oauth-shim/actions/workflows/docker.yml/badge.svg)](https://github.com/jvishnefske/oauth-shim/actions/workflows/docker.yml)

A small, containerized login shim written in safe Rust (`#![forbid(unsafe_code)]`-clean dependencies aside, the project code itself contains no `unsafe`). It authenticates users via **Google, Microsoft, or GitHub** OAuth, stores users and sessions in **SQLite**, and gates an `/admin` route behind an email allowlist.

Intended use: sit in front of (or beside) an internal tool that needs "log in as admin" without running a full identity stack.

## Endpoints

| Route | Purpose |
|---|---|
| `GET /` | Login page (buttons for each configured provider) |
| `GET /auth/{provider}/login` | Starts the OAuth flow (`google`, `microsoft`, `github`) |
| `GET /auth/{provider}/callback` | OAuth redirect URI |
| `GET /admin` | Admin-only page (303 to `/` if unauthenticated, 403 if not admin) |
| `POST /logout` | Destroys the session |
| `GET /healthz` | Liveness check |

> **Deploying for real?** See [DEPLOYMENT.md](./DEPLOYMENT.md) for copy-paste
> recipes (standalone Caddy/HTTPS, reverse-proxy SSO, NixOS systemd) and a
> pre-flight checklist. A prebuilt image is published at
> `ghcr.io/jvishnefske/oauth-shim`.

## Quick start

1. Register an OAuth app with each provider you want, using redirect URI
   `${BASE_URL}/auth/{provider}/callback`:
   - **Google**: Google Cloud Console → APIs & Services → Credentials → OAuth client ID (Web)
   - **Microsoft**: Entra ID → App registrations (Web platform; "common" tenant endpoint is used)
   - **GitHub**: Settings → Developer settings → OAuth Apps
2. `cp .env.example .env` and fill in client IDs/secrets and `ADMIN_EMAILS`.
3. `docker compose up --build`
4. Open http://localhost:8080 and sign in. Accounts whose verified email is in
   `ADMIN_EMAILS` get `is_admin = 1` and can open `/admin`.

## Configuration (env vars)

- `BASE_URL` — public URL; must match registered redirect URIs. `https://` ⇒ `Secure` cookies.
- `ADMIN_EMAILS` — comma-separated, case-insensitive.
- `GOOGLE_/MICROSOFT_/GITHUB_CLIENT_ID` + `_CLIENT_SECRET` — a provider is enabled only when both are set.
- `DB_PATH` (default `/data/shim.db`), `LISTEN_ADDR` (default `0.0.0.0:8080`), `RUST_LOG`.

## Security properties

- **Authorization-code flow with PKCE (S256)** on every provider.
- **CSRF protection**: random `state` is stored server-side with a 10-minute TTL and consumed once.
- **Opaque sessions**: 256-bit random token in an `HttpOnly`, `SameSite=Lax` (and `Secure` under HTTPS) cookie; only the SHA-256 hash is stored in SQLite. 8-hour TTL; expired rows are purged opportunistically.
- **No tokens persisted**: provider access tokens are used once to fetch identity and discarded.
- **GitHub email**: falls back to the *verified primary* address from `/user/emails`; unverified addresses never grant admin.
- **Container hardening**: static musl binary in a `scratch` image, non-root (`65534`), `read_only` rootfs, all capabilities dropped; TLS roots are compiled in (webpki), so no system CA store is needed.
- SQLite runs in WAL mode with foreign keys on; all queries are parameterized.

Limitations to know about: the pending-state map is in-memory, so run a single replica (or add sticky sessions); admin status is recomputed from `ADMIN_EMAILS` at each login; if you front this with a proxy, terminate TLS there and set `BASE_URL` to the https URL.

## Building / verifying without Docker

```sh
cargo check          # type-checks (verified on Rust 1.75+)
cargo build --release
DB_PATH=/tmp/shim.db BASE_URL=http://localhost:8080 \
  GOOGLE_CLIENT_ID=... GOOGLE_CLIENT_SECRET=... \
  ADMIN_EMAILS=you@example.com ./target/release/oauth-shim
```

`Cargo.lock` is committed and pins a dependency set that also builds on older toolchains (1.75); `--locked` in the Dockerfile keeps image builds reproducible.

## Nix

The flake provides:

```sh
nix build .              # dynamically linked binary
nix build .#static       # static musl binary (Linux)
nix build .#image        # OCI image: docker load < result
nix develop              # dev shell (cargo, clippy, rust-analyzer, sqlite)
```

It builds straight from the committed `Cargo.lock` (`cargoLock.lockFile`), so
there is no `cargoHash` to update. A NixOS module is included:

```nix
{
  inputs.oauth-shim.url = "github:you/oauth-shim";
  # in your system config:
  imports = [ oauth-shim.nixosModules.default ];
  services.oauth-shim = {
    enable = true;
    baseUrl = "https://auth.example.com";
    cookieDomain = "example.com";
    adminEmails = [ "you@example.com" ];
    environmentFile = "/run/secrets/oauth-shim.env"; # client IDs/secrets
  };
}
```

The unit runs with `DynamicUser`, a private `/var/lib/oauth-shim` state dir,
and a strict systemd sandbox (no capabilities, syscall filter, read-only
system). Bind it to `127.0.0.1` and route through Traefik/nginx as before.

## Traefik ForwardAuth (Jenkins, Gerrit, ...)

`GET /auth/verify` implements the ForwardAuth contract: `200` plus
`X-Auth-User` / `X-Auth-Name` / `X-Auth-Provider` headers when the session is
valid, `403` if logged in but not permitted, otherwise a redirect to the login
page that returns the user to the original URL afterwards (rebuilt from
`X-Forwarded-Proto/Host/Uri`; validated against `COOKIE_DOMAIN` so the shim
cannot be used as an open redirector).

Requirements for cross-service SSO:
- All services and the shim share a parent domain (`auth.example.com`,
  `jenkins.example.com`, ...). Set `COOKIE_DOMAIN=example.com` so the session
  cookie is sent to every subdomain.
- `BASE_URL=https://auth.example.com` (Traefik terminates TLS; cookies become
  `Secure`).
- `VERIFY_REQUIRE_ADMIN=false` if non-admin users should also pass ForwardAuth.

See `docker-compose.traefik-example.yml` for a full stack. Downstream apps
consume the identity header: Jenkins via the *Reverse Proxy Auth* plugin
(header `X-Auth-User`), Gerrit via `auth.type = HTTP` with
`auth.httpHeader = X-Auth-User`. Make sure the apps are only reachable through
Traefik (no published ports), otherwise the header could be spoofed.

## Extending the shim

To protect another app, either (a) put this service behind the same domain and have your app trust the `shim_session` cookie by querying the `sessions`/`users` tables, or (b) add a `/whoami` JSON endpoint and use your reverse proxy's auth-request feature (nginx `auth_request`, Traefik ForwardAuth) — the handler structure in `src/main.rs` (`current_user`) makes that a few lines.
