# Multi-tenant OAuth2 OP demo

Two independent PocketBase apps in one process, each acting as its own OAuth 2.1 Authorization Server. Demonstrates:

- Per-`core.App` isolation: distinct signing keys, client registries, session storage, even though both run in the same `go` process
- The opt-in `RequireScope` middleware on a custom `/api/widgets` route
- At-rest envelope encryption when `OAUTH2_MASTER_KEY` is set
- RFC 9207 `iss` parameter in authorization responses

## Files

| File | Purpose |
|---|---|
| `main.go` | Runnable two-tenant server (ports 8090 + 8091) |
| `integration_test.go` | In-process end-to-end test driving the full OAuth code+PKCE flow on both tenants |

## Run the live demo

```bash
# Generate a per-process master key for at-rest encryption (optional)
export OAUTH2_MASTER_KEY=$(openssl rand -base64 32)

go run ./examples/multitenant
```

Tenant A boots at `http://127.0.0.1:8090` (data: `./pb_data_tenant_a/`).
Tenant B boots at `http://127.0.0.1:8091` (data: `./pb_data_tenant_b/`).

Each tenant exposes:

- `GET /.well-known/openid-configuration` — discovery (per-tenant issuer + jwks)
- `GET /.well-known/jwks.json` — signing keys (different RSA keypair per tenant)
- `POST /oauth2/register` — RFC 7591 dynamic client registration
- `GET|POST /oauth2/auth` — authorization endpoint
- `POST /oauth2/token` — token endpoint
- `GET|POST /oauth2/userinfo` — OIDC userinfo
- `POST /oauth2/revoke`, `POST /oauth2/introspect`
- `GET /api/widgets` — demo resource gated by `RequireScope("widgets:read")`
- `POST /api/widgets` — demo resource gated by `RequireScope("widgets:write")`

Quick sanity check:

```bash
# Each tenant has its own jwks_uri and its own signing keys
curl -s http://127.0.0.1:8090/.well-known/openid-configuration | jq .jwks_uri
curl -s http://127.0.0.1:8091/.well-known/openid-configuration | jq .jwks_uri

curl -s http://127.0.0.1:8090/.well-known/jwks.json | jq '.keys[0].kid'
curl -s http://127.0.0.1:8091/.well-known/jwks.json | jq '.keys[0].kid'
# -> different kid values, even though both processes share OAUTH2_MASTER_KEY
```

## Automated end-to-end test

```bash
go test ./examples/multitenant/ -v
```

`TestMultiTenant_EndToEnd_CodePKCE` drives:

1. PKCE pair generation (S256)
2. Seed a user + client per tenant
3. `GET /oauth2/auth` with `pb_token` shortcut → extract `code` and `iss` from redirect
4. `POST /oauth2/token` with `code_verifier` + `client_secret` → extract `access_token`
5. `GET /api/widgets` on tenant A with token → 200
6. `GET /api/widgets` on tenant B with tenant A's token → non-200 (isolation)
7. `POST /api/widgets` on tenant A with read-only token → 403 with `insufficient_scope`

`TestMultiTenant_DiscoveryIsolation` asserts:

- `authorization_response_iss_parameter_supported: true` (RFC 9207)
- `response_modes_supported` contains `form_post`

## Multi-tenant deployment patterns

`main.go` uses port-per-tenant routing because it's the simplest topology. Other valid options:

- **Host-based routing.** Run a single reverse proxy (Caddy / Traefik / nginx) that maps `tenant-a.example.com` → process holding tenant A's `core.App` and `tenant-b.example.com` → tenant B. Each `core.App` still binds the same `PathPrefix=/oauth2`; the proxy disambiguates.
- **Path-based routing within one core.App.** Not supported by this fork — the well-known routes (`/.well-known/openid-configuration`, etc.) mount on the router root, so two tenants on one router collide. Use port- or host-based instead.

## Cleanup

The demo writes to `./pb_data_tenant_a/` and `./pb_data_tenant_b/`. Delete those directories to reset.
