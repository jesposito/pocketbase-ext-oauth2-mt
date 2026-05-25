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
