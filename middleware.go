package oauth2

import (
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
// This is opt-in: by default OAuth-issued access tokens are valid PocketBase
// auth tokens with no scope check on PB-native endpoints. Attach
// RequireScope to your own resource routes when you want OAuth scope to
// actually gate access. Example:
//
//	se.Router.GET("/api/widgets", listWidgetsHandler).
//	    Bind(oauth2.RequireScope(app, "widgets:read"))
func RequireScope(app core.App, requiredScopes ...string) *hook.Handler[*core.RequestEvent] {
	return &hook.Handler[*core.RequestEvent]{
		Func: func(e *core.RequestEvent) error {
			token := fosite.AccessTokenFromRequest(e.Request)
			if token == "" {
				writeWWWAuthenticate(e, http.StatusUnauthorized,
					`Bearer realm="OAuth", error="invalid_token", error_description="The access token is missing or malformed."`)
				return nil
			}

			inst, ok := getInstance(app)
			if !ok || inst == nil {
				// Plugin not registered - cannot validate scopes. Treat as
				// invalid_token so callers don't accidentally pass-through.
				writeWWWAuthenticate(e, http.StatusUnauthorized,
					`Bearer realm="OAuth", error="invalid_token", error_description="OAuth2 plugin not initialized."`)
				return nil
			}

			ctx := e.Request.Context()
			sess := NewSession(app, "", "")
			_, ar, ierr := inst.provider.IntrospectToken(ctx, token, fosite.AccessToken, sess)
			if ierr != nil || ar == nil {
				desc := "The access token provided is expired, revoked, malformed, or invalid for other reasons."
				if ierr != nil {
					desc = sanitizeHeaderValue(ierr.Error())
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

// sanitizeHeaderValue strips CR/LF and double-quote characters so the value
// can be safely embedded in a quoted-string header parameter.
func sanitizeHeaderValue(v string) string {
	r := strings.NewReplacer("\r", " ", "\n", " ", `"`, "'")
	return r.Replace(v)
}
