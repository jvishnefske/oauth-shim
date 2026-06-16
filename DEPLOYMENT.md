# Deployment

Practical recipes for the most common ways to run `oauth-shim`. All of them
need the same three things: a **public HTTPS URL**, **OAuth credentials** whose
redirect URIs match that URL, and an **`ADMIN_EMAILS`** allowlist.

> The shim speaks plain HTTP and expects something else to terminate TLS
> (Caddy, nginx, Traefik, a cloud load balancer). Set `BASE_URL` to the public
> `https://` URL so cookies are issued with the `Secure` flag.

## Prebuilt image

CI publishes a static-musl `scratch` image to the GitHub Container Registry on
every push to `main` and every `vX.Y.Z` tag:

```sh
docker pull ghcr.io/jvishnefske/oauth-shim:latest   # or :v1.0.0, :main
```

Use that in place of `build: .` in any compose file below.

---

## Scenario 1 — Single host, standalone login portal (Caddy, automatic HTTPS)

The simplest real deployment: one VPS, a DNS record for `auth.example.com`, and
Caddy fetching a Let's Encrypt cert for you. Good when the shim *is* the thing
you're protecting (e.g. it fronts one internal app on the same box).

`compose.yml`:

```yaml
services:
  oauth-shim:
    image: ghcr.io/jvishnefske/oauth-shim:latest
    env_file: .env
    expose: ["8080"]            # internal only; Caddy reaches it over the compose network
    volumes: [shim-data:/data]
    restart: unless-stopped
    read_only: true
    cap_drop: [ALL]
    security_opt: ["no-new-privileges:true"]

  caddy:
    image: caddy:2
    ports: ["80:80", "443:443"]
    volumes:
      - ./Caddyfile:/etc/caddy/Caddyfile:ro
      - caddy-data:/data
      - caddy-config:/config
    restart: unless-stopped

volumes: { shim-data: {}, caddy-data: {}, caddy-config: {} }
```

`Caddyfile`:

```
auth.example.com {
    reverse_proxy oauth-shim:8080
}
```

`.env` (see `.env.example` for the full list):

```sh
BASE_URL=https://auth.example.com
ADMIN_EMAILS=you@example.com
GOOGLE_CLIENT_ID=...
GOOGLE_CLIENT_SECRET=...
```

Register the redirect URI `https://auth.example.com/auth/google/callback` with
the provider, then `docker compose up -d`.

---

## Scenario 2 — Protect existing apps via reverse-proxy auth (SSO)

Put the shim beside your apps under a shared parent domain and have the proxy
ask it "is this request allowed?" before forwarding. The shim implements the
**ForwardAuth** contract at `GET /auth/verify` and returns `X-Auth-User` /
`X-Auth-Name` / `X-Auth-Provider` headers on success.

- **Traefik**: full worked example in
  [`docker-compose.traefik-example.yml`](./docker-compose.traefik-example.yml)
  and the *Traefik ForwardAuth* section of the [README](./README.md).
- **nginx**: use `auth_request /auth/verify;` and copy the `X-Auth-*` response
  headers onto the upstream request.

Key settings for cross-service SSO:

```sh
BASE_URL=https://auth.example.com
COOKIE_DOMAIN=example.com          # so the session cookie is sent to *.example.com
VERIFY_REQUIRE_ADMIN=false         # allow any logged-in user, not just admins
```

Make sure downstream apps are reachable **only** through the proxy — otherwise
the `X-Auth-User` header can be spoofed.

---

## Scenario 3 — systemd on NixOS (no Docker)

The included [`flake.nix`](./flake.nix) ships a NixOS module that runs the shim
under `DynamicUser` with a strict sandbox. Bind it to `127.0.0.1` and route
through your existing reverse proxy:

```nix
{
  inputs.oauth-shim.url = "github:jvishnefske/oauth-shim";
  # in your system config:
  imports = [ oauth-shim.nixosModules.default ];
  services.oauth-shim = {
    enable = true;
    baseUrl = "https://auth.example.com";
    cookieDomain = "example.com";
    adminEmails = [ "you@example.com" ];
    environmentFile = "/run/secrets/oauth-shim.env";  # client IDs/secrets
  };
}
```

---

## Operational notes

- **Single replica.** Pending OAuth `state` is held in memory, so run one
  instance or enable sticky sessions at the proxy.
- **Secrets.** Keep client secrets out of the image — use `.env` /
  `environmentFile` / your orchestrator's secret store. Never commit `.env`.
- **Persistence.** The SQLite DB at `DB_PATH` (default `/data/shim.db`) holds
  users and sessions. Back up the `/data` volume; losing it just logs everyone
  out. No provider tokens are stored.
- **Health checks.** Point your orchestrator's liveness probe at `GET /healthz`.
- **Admin changes.** `is_admin` is recomputed from `ADMIN_EMAILS` at each login,
  so updating the list takes effect when the user next signs in.

## Pre-flight checklist

- [ ] DNS record points at the host
- [ ] `BASE_URL` is the public `https://` URL
- [ ] Redirect URIs registered for every enabled provider:
      `${BASE_URL}/auth/{google,microsoft,github}/callback`
- [ ] `ADMIN_EMAILS` set; the address is **verified** at the provider
- [ ] TLS terminated by the proxy; shim itself not published on a public port
- [ ] `/data` volume is persistent and backed up
