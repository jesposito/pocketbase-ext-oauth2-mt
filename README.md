# PocketBase OAuth2 Provider Plugin (Multi-Tenant Fork)

A fork of [`pocketbase-ext-oauth2`](https://github.com/benjamesfleming/pocketbase-ext-oauth2) that makes all OAuth2 provider state **per-`core.App` instance** instead of package-level globals. This enables safe use in multi-tenant deployments where multiple PocketBase apps run in the same process.

Turn any [PocketBase](https://pocketbase.io) instance into a fully compliant **OAuth 2.1 Authorization Server** with OpenID Connect support. Built on top of [ory/fosite](https://github.com/ory/fosite).

## Why this fork?

The upstream plugin stores OAuth2 state (config, Fosite provider, RSA keys, metadata) in package-level variables. If you create multiple `core.App` instances in the same process — for example, in a multi-tenant pool — each `Register()` call overwrites the previous app's state. Tokens, clients, and signing keys leak across tenant boundaries.

This fork replaces all globals with an `Instance` struct stored per-app. Each PocketBase app gets its own isolated OAuth2 provider, key pair, and client registry.

### Changes from upstream

- **Multi-tenant safe**: All state is scoped to `core.App` via `app.Store()`
- **OAuth 2.1 aligned**: PKCE required by default; implicit and hybrid flows removed; discovery metadata updated
- **Duplicate registration guard**: Calling `Register()` twice on the same app returns an error
- **Config isolation**: Each registration clones the provided `*Config` so per-app secrets don't leak
- **Breaking API**: `GetOAuth2Config()`, `GetOAuth2Store()`, `IsRegistered()`, and `RegisterProtectedResourceMetadata()` now require `app core.App`

---

## Requirements

- Go 1.25+
- PocketBase v0.36+

## Installation

```bash
go get github.com/jesposito/pocketbase-ext-oauth2-mt
```

```go
package main

import (
	"log"
	"os"
	"time"

	oauth2 "github.com/jesposito/pocketbase-ext-oauth2-mt"
	"github.com/pocketbase/pocketbase"
)

func main() {
	app := pocketbase.New()
	app.RootCmd.ParseFlags(os.Args[1:])

	oauth2.MustRegister(app, &oauth2.Config{
		BaseConfig: &oauth2.BaseConfig{
			AccessTokenLifespan:   time.Hour,
			AuthorizeCodeLifespan: time.Minute * 15,
			RefreshTokenScopes:    []string{}, // allow all scopes for refresh tokens
		},
		PathPrefix:                             "/oauth2",
		UserCollection:                         "users",
		EnableRFC7591DynamicClientRegistration: true,
		EnableRFC9728ProtectedResourceMetadata: true,
	})

	if err := app.Start(); err != nil {
		log.Fatal(err)
	}
}
```

The plugin will automatically run its database migrations on first boot, creating the required system collections.

### Multi-tenant usage

Because all state is per-app, you can safely register multiple apps in the same process:

```go
app1 := pocketbase.NewWithConfig(pocketbase.Config{DefaultDataDir: "./tenant_a"})
app2 := pocketbase.NewWithConfig(pocketbase.Config{DefaultDataDir: "./tenant_b"})

oauth2.MustRegister(app1, &oauth2.Config{...})
oauth2.MustRegister(app2, &oauth2.Config{...})
```

Each app has its own signing keys, client registry, and session store.

### Multiple OPs on the same app

A single `core.App` can host more than one OAuth2 provider by calling `Register()` with distinct `PathPrefix` values. This is useful when a tenant needs separate OPs for different audiences (e.g. admin tooling vs end-customer logins) that authenticate against different PocketBase auth collections:

```go
// Admin OP — authenticates against the `users` collection.
oauth2.MustRegister(app, &oauth2.Config{
    BaseConfig:     baseCfg,
    PathPrefix:     "/oauth2/admin",
    UserCollection: "users",
})

// Members OP — same app, different prefix, different user collection.
oauth2.MustRegister(app, &oauth2.Config{
    BaseConfig:     baseCfg,
    PathPrefix:     "/oauth2/members",
    UserCollection: "members",
})
```

Each prefix gets its own `Instance` (config, fosite provider, RSA key reference), but the underlying session collections (`_oauth2Clients`, `_oauth2Access`, …) are shared across prefixes on the same app. Lookup helpers have prefix-aware variants:

- `GetOAuth2ConfigAt(app, prefix)`
- `GetOAuth2StoreAt(app, prefix)`
- `IsRegisteredAt(app, prefix)`
- `RegisterProtectedResourceMetadataAt(app, prefix, md)`
- `RequireScopeAt(app, prefix, scopes...)`
- `DeregisterAt(app, prefix)`

The zero-suffix versions (`GetOAuth2Config(app)`, `RequireScope(app, …)`, etc.) remain unchanged and continue to resolve the OP at the default `/oauth2` prefix, so existing single-OP integrations keep working.

---

## Endpoints

All OAuth2 endpoints are served under the configured `PathPrefix` (default `/oauth2`).

| Method | Path | Description |
|---|---|---|
| GET/POST | `/oauth2/auth` | Authorization endpoint |
| GET/POST | `/oauth2/token` | Token endpoint |
| POST | `/oauth2/revoke` | Token revocation |
| POST | `/oauth2/introspect` | Token introspection |
| GET/POST | `/oauth2/userinfo` | OpenID Connect UserInfo |
| POST | `/oauth2/register` | Dynamic client registration (RFC 7591, optional) |
| GET/POST | `/oauth2/login` | Built-in login/consent UI |
| GET | `/oauth2/runtime-attestation?nonce=<32-byte-base64url>` | Optional constrained runtime attestation (when `RuntimeAttestationSnapshot` is configured) |

### Constrained runtime attestation

`Config.RuntimeAttestationSnapshot` is a typed callback for applications that
must bind deployment evidence to the provider's existing OIDC trust root. The
plugin, not the callback, owns `GET <PathPrefix>/runtime-attestation`, the exact
claim schema (including the configured `UserCollection`), RS256 key selection,
protected header, audience `urn:facetcloud:oauth-runtime-attestation:v1`, type
`facet-oauth-runtime-attestation+jwt`, 60-second lifetime, nonce validation,
no-store response, and a 120-request-per-minute budget owned by each provider
instance/prefix. The budget deliberately has no IP or forwarded-header identity,
so callers sharing Caddy, Traefik, NAT, or another ingress are not collapsed into
a six-request bucket and forged proxy headers cannot create new buckets.
The callback can supply only tenant, release/source SHA, source/boot identity,
and a public auth-configuration digest. It cannot sign arbitrary bytes, choose
a key, add JOSE headers, change expiry, or obtain a private key/JWK.

There is intentionally no package-global mutable limiter: `core.App` tenants and
provider prefixes cannot exhaust one another's in-process budget. A host that
needs a process-wide CPU ceiling must enforce it outside the plugin (for example
with worker/container limits or an ingress-wide request budget). That boundary
does not expose signing authority or key material to the host.

Multi-provider applications must request and verify one attestation from every
required prefix against independently enrolled `(origin, issuer, prefix, kid,
RFC 7638 thumbprint)` pins. Never accept a key merely because it appears in the
same target's current JWKS response; fail closed on unknown or rotated keys.

### Discovery & Metadata

| Method | Path | Description |
|---|---|---|
| GET | `/.well-known/oauth-authorization-server` | Authorization Server Metadata (RFC 8414) |
| GET | `/.well-known/openid-configuration` | OpenID Connect Discovery |
| GET | `/.well-known/jwks.json` | JSON Web Key Set |
| GET | `/.well-known/oauth-protected-resource/{resource}` | Protected Resource Metadata (RFC 9728, optional) |

---

## How It Works

### Access Tokens

Access tokens issued by this plugin are **native PocketBase auth tokens**. This means any PocketBase endpoint or middleware that accepts a standard auth token will work out of the box with OAuth2-issued access tokens — no additional configuration needed.

### Key Management

On first bootstrap the plugin generates an **RSA (RS256)** signing key pair and a **global HMAC secret**, both stored in PocketBase's internal `_params` table. These persist across restarts and are used for signing ID tokens, authorization codes, and refresh tokens respectively. In multi-tenant mode, each tenant gets its own independent key pair.

#### Envelope encryption at rest

If `OAUTH2_MASTER_KEY` is set (raw 32-byte, base64, or hex), all OAuth signing key material in `_params` is sealed with AES-256-GCM, keyed off a per-(param, app) DEK derived via HKDF. Each tenant gets its own stable HKDF context (a UUID persisted at `oauth2_envelope_ctx_id` in `_params`) so moving or renaming the PocketBase data directory does NOT invalidate existing envelopes.

#### Rotating the master key

Set both env vars at the same time during the rotation window:

```sh
export OAUTH2_MASTER_KEY=<new-active-key>
export OAUTH2_MASTER_KEY_OLD=<old-key>[,<older-key>...]
```

On the next load of each `_params` row the plugin:

1. Decrypts using whichever master matches the envelope's `kid` (consulting both the active key and any keys listed in `OAUTH2_MASTER_KEY_OLD`).
2. Lazily re-encrypts the row under the active key (compare-and-swap on the row value, so concurrent loaders cannot last-writer-wins each other).
3. Updates the fingerprint sentinel to the active key.

Once every encrypted row has been touched once after the rotation, `OAUTH2_MASTER_KEY_OLD` can be removed. Until then, the old key is still required to read any row that has not yet been rewrapped.

### Session Storage

OAuth2 session data (authorization codes, access tokens, refresh tokens, PKCE challenges, and OpenID Connect sessions) is stored in dedicated system collections that are automatically created by the plugin's migration. A cron job runs every hour to clean up expired sessions.

The plugin creates the following **system** collections automatically:

| Collection | Purpose |
|---|---|
| `_oauth2Clients` | Registered OAuth2 client applications |
| `_oauth2AuthCode` | Authorization code sessions |
| `_oauth2Access` | Access token sessions |
| `_oauth2Refresh` | Refresh token sessions |
| `_oauth2PKCE` | PKCE challenge data |
| `_oauth2OpenID` | OpenID Connect sessions |
| `_oauth2JTI` | JWT Token Identifiers (for replay protection) |

### Custom UserInfo Claims

By default the `/userinfo` endpoint attempts a best-effort extraction of default OpenID claims from the authenticated user's PocketBase auth record. If you have non-standard column names or other requirements, you can customize the claim response by implementing the `UserInfoClaimStrategy` interface and returning any struct or map — it will be JSON-encoded in the `/userinfo` response.

```go
type MyCustomClaims struct {
    Sub   string `json:"sub"`
    Email string `json:"email"`
}

type MyClaimStrategy struct{}

func (s *MyClaimStrategy) GetUserInfoClaims(e *core.RequestEvent, scopes []string) (interface{}, error) {
	return &MyCustomClaims{
        Sub:   e.Auth.ID,
        Email: e.Auth.GetString("email"),
	}, nil
}

oauth2.MustRegister(app, &oauth2.Config{
	// ...
	UserInfoClaimStrategy: &MyClaimStrategy{},
})
```

### Protected Resource Metadata (RFC 9728)

You can register additional protected resources so clients can discover your resource server metadata. Because this fork is app-scoped, you must pass the app:

```go
oauth2.RegisterProtectedResourceMetadata(app,
	&rfc9728.ProtectedResourceMetadata{
		Resource:               "https://api.example.com/data",
		AuthorizationServers:   []string{"https://auth.example.com"},
		BearerMethodsSupported: []string{"header"},
		ScopesSupported:        []string{"read", "write"},
	},
)
```

The metadata will be available at `/.well-known/oauth-protected-resource/data`.

---

## Scope & Roadmap

### What is in scope

- **OAuth 2.1** authorization code flow with PKCE (PKCE required by default)
- **OpenID Connect** Core 1.0 (authorization code flow + ID tokens, RS256)
- **Discovery** via RFC 8414 (OAuth Authorization Server Metadata) and OpenID Connect Discovery 1.0
- **Dynamic Client Registration** (RFC 7591, optional)
- **Protected Resource Metadata** (RFC 9728, optional)
- **Token revocation** (RFC 7009) and **introspection** (RFC 7662)
- **RFC 9207** Authorization Response Issuer Identification (`iss` on success and error redirects)
- **Refresh-token rotation with reuse detection** (refresh-token family tracking)
- **Envelope encryption at rest** (AES-256-GCM) for OAuth signing key material in `_params`, keyed off `OAUTH2_MASTER_KEY`

### What is deliberately out of scope (v1)

- **Pushed Authorization Requests (PAR, RFC 9126)** — not required by OAuth 2.1 baseline. PAR is a FAPI / high-assurance profile feature. Adding PAR would require a fosite PAR factory, a `/oauth2/par` endpoint, PARStorage, and `pushed_authorization_request_endpoint` discovery metadata. Revisit if FAPI conformance becomes a goal.
- **DPoP sender-constrained tokens (RFC 9449)** — out of scope for the same reason. DPoP is a FAPI / mobile-app-protected-resource feature. Revisit if FAPI conformance becomes a goal.
- **mTLS-bound tokens (RFC 8705)** — same reasoning.

These decisions are recorded here so reviewers don't re-raise them. The plugin tracks OAuth 2.1 baseline + commonly-deployed extensions; FAPI work is a separate epic.

---

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.
