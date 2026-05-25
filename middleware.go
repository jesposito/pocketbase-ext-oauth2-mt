package oauth2

import (
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strings"

	"github.com/ory/fosite"
	"github.com/pocketbase/pocketbase/apis"
	"github.com/pocketbase/pocketbase/core"
	"github.com/pocketbase/pocketbase/tools/hook"
)

// ScopeContextKey is the key under which RequireScope stores the granted
// scopes slice on the RequestEvent for downstream handlers to read via
// e.Get(ScopeContextKey).
const ScopeContextKey = "oauth_granted_scopes"

// RequireScope returns a router middleware that asserts the bearer token in
// the Authorization header has been granted ALL of the listed scopes. On
// success it sets the granted-scopes slice on e.Set(ScopeContextKey) for
// downstream handlers and calls Next. On failure it returns an RFC 6750
// "insufficient_scope" 403 with the missing scopes listed in the
// WWW-Authenticate header.
//
// Header-only by design: the token is read from "Authorization: Bearer
// <token>" only. Form-body and URL-query token parameters are deliberately
// rejected because URL-query tokens leak into access logs, browser history,
// and Referer headers (RFC 6750 §5.3 SHOULD-NOT) and form-body tokens
// trigger CORS preflight in browser clients. If you need form/query token
// support, use fosite.AccessTokenFromRequest directly in your own middleware.
//
// This is opt-in: by default OAuth-issued access tokens are valid PocketBase
// auth tokens with no scope check on PB-native endpoints. Attach
// RequireScope to your own resource routes when you want OAuth scope to
// actually gate access. Example:
//
//	se.Router.GET("/api/widgets", listWidgetsHandler).
//	    Bind(oauth2.RequireScope(app, "widgets:read"))
func RequireScope(app core.App, requiredScopes ...string) *hook.Handler[*core.RequestEvent] {
	return RequireScopeAt(app, DefaultPathPrefix, requiredScopes...)
}

// RequireScopeAt is the prefix-aware variant of RequireScope. Use it on
// resource routes that should be gated by an OP registered at a non-
// default path prefix (e.g. /oauth2/members).
func RequireScopeAt(app core.App, prefix string, requiredScopes ...string) *hook.Handler[*core.RequestEvent] {
	return &hook.Handler[*core.RequestEvent]{
		Func: func(e *core.RequestEvent) error {
			token := bearerTokenFromHeader(e.Request.Header.Get("Authorization"))
			if token == "" {
				writeWWWAuthenticate(e, http.StatusUnauthorized,
					`Bearer realm="OAuth", error="invalid_token", error_description="The access token is missing or malformed."`)
				return nil
			}

			inst, ok := getInstanceAt(app, prefix)
			if !ok || inst == nil {
				// Plugin not registered - cannot validate scopes. Treat as
				// invalid_token so callers don't accidentally pass-through.
				writeWWWAuthenticate(e, http.StatusUnauthorized,
					`Bearer realm="OAuth", error="invalid_token", error_description="OAuth2 plugin not initialized."`)
				return nil
			}

			ctx := e.Request.Context()
			sess := NewSession(app, "", "")
			// fosite.Fosite.IntrospectToken does NOT honor the hint as a hard
			// filter: even with hint=AccessToken it falls back to refresh-token
			// introspection on access-token miss (see fosite v0.49
			// handler/oauth2/introspector.go CoreValidator.IntrospectToken).
			// So an active refresh-token would otherwise pass this middleware
			// as long as its granted scopes match. Check the returned token
			// use and reject anything that is not a bearer access token.
			tu, ar, ierr := inst.provider.IntrospectToken(ctx, token, fosite.AccessToken, sess)
			if ierr != nil || ar == nil || tu != fosite.AccessToken {
				desc := "The access token provided is expired, revoked, malformed, or invalid for other reasons."
				if ierr != nil {
					// %q already escapes embedded quotes + control chars
					// safely for an RFC 7230 quoted-string parameter value.
					desc = ierr.Error()
				} else if ar != nil && tu != fosite.AccessToken {
					desc = "The presented token is not an access token."
				}
				writeWWWAuthenticate(e, http.StatusUnauthorized,
					fmt.Sprintf(`Bearer realm="OAuth", error="invalid_token", error_description=%q`, desc))
				return nil
			}

			granted := ar.GetGrantedScopes()
			var missing []string
			for _, req := range requiredScopes {
				if !slices.Contains(granted, req) {
					missing = append(missing, req)
				}
			}
			if len(missing) > 0 {
				// RFC 6750 sec 3.1: scope param lists the scopes required to
				// access the protected resource (space-separated).
				writeWWWAuthenticate(e, http.StatusForbidden,
					fmt.Sprintf(`Bearer realm="OAuth", error="insufficient_scope", error_description="The request requires higher privileges than provided by the access token.", scope=%q`,
						strings.Join(requiredScopes, " ")))
				return nil
			}

			// Normalize to []string so downstream handlers can type-assert
			// against the standard type rather than fosite.Arguments.
			e.Set(ScopeContextKey, []string(granted))
			return e.Next()
		},
		// Run after the default LoadAuthToken middleware so e.Auth (if any)
		// is populated, mirroring the rfc9728 middleware shape.
		Priority: apis.DefaultLoadAuthTokenMiddlewarePriority + 10,
	}
}

// writeWWWAuthenticate sets the RFC 6750 challenge header and writes the
// status code with no body. Mirrors the rfc9728 middleware's response shape.
func writeWWWAuthenticate(e *core.RequestEvent, status int, challenge string) {
	e.Response.Header().Set("WWW-Authenticate", challenge)
	e.Response.WriteHeader(status)
}

// RevokedTokenGuard returns a router middleware that rejects bearer
// tokens which have no corresponding _oauth2Access row — i.e. tokens
// that were revoked via /oauth2/revoke or expired by the cleanup cron.
//
// PocketBase native auth tokens are stateless JWTs validated against the
// PB signing secret; a revoked OAuth2 access token remains a syntactically
// valid PB token until its natural exp. Routes using apis.RequireAuth()
// alone will accept revoked tokens. Bind RevokedTokenGuard wherever you
// need OAuth-side revocation to take effect on a PB-native route:
//
//	se.Router.GET("/api/private", privateHandler).
//	    Bind(apis.RequireAuth("users")).
//	    Bind(oauth2.RevokedTokenGuard(app))
//
// Tokens issued outside the OAuth flow (e.g. PB built-in auth via
// /api/collections/users/auth-with-password) have no _oauth2Access row
// and would also be rejected by this middleware — by design. Use it only
// on routes that should accept ONLY OAuth-issued tokens.
func RevokedTokenGuard(app core.App) *hook.Handler[*core.RequestEvent] {
	return &hook.Handler[*core.RequestEvent]{
		Func: func(e *core.RequestEvent) error {
			token := bearerTokenFromHeader(e.Request.Header.Get("Authorization"))
			if token == "" {
				writeWWWAuthenticate(e, http.StatusUnauthorized,
					`Bearer realm="OAuth", error="invalid_token", error_description="The access token is missing or malformed."`)
				return nil
			}
			parts := strings.Split(token, ".")
			if len(parts) != 3 {
				writeWWWAuthenticate(e, http.StatusUnauthorized,
					`Bearer realm="OAuth", error="invalid_token", error_description="The presented token is not an OAuth access token."`)
				return nil
			}
			signature := parts[2]
			if _, err := findSessionModelBySignature(app, &AccessTokenModel{}, signature); err != nil {
				if errors.Is(err, fosite.ErrNotFound) {
					writeWWWAuthenticate(e, http.StatusUnauthorized,
						`Bearer realm="OAuth", error="invalid_token", error_description="The access token has been revoked or expired."`)
					return nil
				}
				writeWWWAuthenticate(e, http.StatusUnauthorized,
					`Bearer realm="OAuth", error="invalid_token", error_description="Failed to validate access token."`)
				return nil
			}
			return e.Next()
		},
		Priority: apis.DefaultLoadAuthTokenMiddlewarePriority + 10,
	}
}

// bearerTokenFromHeader extracts a bearer token from an Authorization header
// value per RFC 6750 §2.1. The scheme match is case-insensitive ("Bearer",
// "bearer", "BEARER"); the token itself is returned verbatim. Returns "" if
// the header is missing, malformed, or uses a different scheme.
func bearerTokenFromHeader(authz string) string {
	const prefix = "bearer "
	if len(authz) <= len(prefix) {
		return ""
	}
	if !strings.EqualFold(authz[:len(prefix)], prefix) {
		return ""
	}
	return strings.TrimSpace(authz[len(prefix):])
}
