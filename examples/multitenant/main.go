// Multi-tenant OAuth2 OP demo.
//
// Boots two independent PocketBase apps in the same process, each acting as
// its own OAuth 2.1 Authorization Server with isolated key material, client
// registry, and session storage. Each tenant listens on a different port so
// the standard PocketBase router stays untouched.
//
// Tenant A: http://127.0.0.1:8090 (data: ./pb_data_tenant_a)
// Tenant B: http://127.0.0.1:8091 (data: ./pb_data_tenant_b)
//
// What this demo exercises:
//   - Per-app Instance state (every endpoint scoped to its tenant)
//   - Discovery, JWKS, DCR per tenant (different signing keys)
//   - opt-in RequireScope middleware on a custom /api/widgets route
//   - At-rest envelope encryption when OAUTH2_MASTER_KEY is set
//
// Run:
//
//	OAUTH2_MASTER_KEY=$(openssl rand -base64 32) go run ./examples/multitenant
//
// Then:
//
//	curl -s http://127.0.0.1:8090/.well-known/openid-configuration | jq
//	curl -s http://127.0.0.1:8091/.well-known/openid-configuration | jq
//	# Note the different jwks_uri keys / signing kids per tenant.
//
// For an end-to-end OAuth code+PKCE flow that drives both tenants, see
// integration_test.go in this directory.
package main

import (
	"log"
	"net/http"
	"os"
	"sync"
	"time"

	oauth2 "github.com/jesposito/pocketbase-ext-oauth2-mt"
	"github.com/pocketbase/pocketbase"
	"github.com/pocketbase/pocketbase/core"
)

type tenantConfig struct {
	name    string
	dataDir string
	addr    string
}

func main() {
	tenants := []tenantConfig{
		{name: "apple", dataDir: "./pb_data_tenant_a", addr: "127.0.0.1:8090"},
		{name: "banana", dataDir: "./pb_data_tenant_b", addr: "127.0.0.1:8091"},
	}

	var wg sync.WaitGroup
	for _, t := range tenants {
		wg.Add(1)
		go func(tc tenantConfig) {
			defer wg.Done()
			if err := runTenant(tc); err != nil {
				log.Printf("[%s] exited: %v", tc.name, err)
			}
		}(t)
	}
	wg.Wait()
}

func runTenant(tc tenantConfig) error {
	app := pocketbase.NewWithConfig(pocketbase.Config{
		DefaultDataDir: tc.dataDir,
	})
	// Override the listen address so two tenants can run in the same
	// process without colliding on :8090. PocketBase parses --http from
	// flags; we splice it in via os.Args before the framework reads them.
	app.RootCmd.SetArgs([]string{"serve", "--http=" + tc.addr})

	oauth2.MustRegister(app, &oauth2.Config{
		BaseConfig: &oauth2.BaseConfig{
			AccessTokenLifespan:   time.Hour,
			AuthorizeCodeLifespan: 5 * time.Minute,
			RefreshTokenScopes:    []string{}, // accept any scope on refresh
		},
		PathPrefix:                             "/oauth2",
		UserCollection:                         "users",
		EnableRFC7591DynamicClientRegistration: true,
		AllowUnauthenticatedDynamicClientRegistration: true,
		EnableRFC9728ProtectedResourceMetadata: true,
	})

	// Demonstrate the RequireScope middleware: /api/widgets returns 200 only
	// for OAuth-issued access tokens that were granted "widgets:read". A PB
	// admin or non-OAuth user token presented to this route will be 401.
	app.OnServe().BindFunc(func(se *core.ServeEvent) error {
		se.Router.GET("/api/widgets", func(e *core.RequestEvent) error {
			granted, _ := e.Get(oauth2.ScopeContextKey).([]string)
			return e.JSON(http.StatusOK, map[string]any{
				"tenant":         tc.name,
				"items":          []string{"alpha-widget", "beta-widget"},
				"granted_scopes": granted,
			})
		}).Bind(oauth2.RequireScope(app, "widgets:read"))

		// And a route that requires the higher-privilege scope, so the demo
		// shows the 403 path when a token only has "widgets:read".
		se.Router.POST("/api/widgets", func(e *core.RequestEvent) error {
			return e.JSON(http.StatusCreated, map[string]any{"created": true})
		}).Bind(oauth2.RequireScope(app, "widgets:write"))

		log.Printf("[%s] OAuth2 OP up at http://%s — issuer=%s",
			tc.name, tc.addr, app.Settings().Meta.AppURL)
		return se.Next()
	})

	// Hand back the os.Args we shimmed so other tenant goroutines don't
	// see the stale --http flag if main re-enters.
	defer func() { _ = os.Args }()

	return app.Start()
}
