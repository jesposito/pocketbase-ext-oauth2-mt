package oauth2

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/go-jose/go-jose/v3"
	"github.com/ory/fosite"
	"github.com/ory/fosite/compose"
	"github.com/pkg/errors"

	"github.com/jesposito/pocketbase-ext-oauth2-mt/consts"
	_ "github.com/jesposito/pocketbase-ext-oauth2-mt/migrations"
	"github.com/jesposito/pocketbase-ext-oauth2-mt/openid"
	"github.com/jesposito/pocketbase-ext-oauth2-mt/rfc8414"
	"github.com/jesposito/pocketbase-ext-oauth2-mt/rfc9728"
	"github.com/jesposito/pocketbase-ext-oauth2-mt/ui"
	"github.com/pocketbase/dbx"
	"github.com/pocketbase/pocketbase/core"
	"github.com/pocketbase/pocketbase/tools/router"
)

type BaseConfig = fosite.Config

type Config struct {
	*BaseConfig

	PathPrefix                             string
	UserCollection                         string
	UserInfoClaimStrategy                  UserInfoClaimStrategy
	EnableRFC7591DynamicClientRegistration bool
	EnableRFC9728ProtectedResourceMetadata bool
}

func GetOAuth2Config(app core.App) *Config {
	return mustGetInstance(app).cfg
}

func GetOAuth2Store(app core.App) *OAuth2Store {
	return mustGetInstance(app).store
}

func IsRegistered(app core.App) bool {
	if app == nil {
		return false
	}
	_, ok := getInstance(app)
	return ok
}

//

func MustRegister(app core.App, config *Config) {
	if err := Register(app, config); err != nil {
		panic(fmt.Sprintf("[Plugin/OAuth2] Failed to register OAuth2 plugin: %v", err))
	}
}

// cloneConfig creates a deep copy of the provided Config so that per-app
// mutations (defaults, secrets) do not leak across registrations.
func cloneConfig(src *Config) *Config {
	// Shallow copy the struct
	cfg := *src
	// Deep copy the embedded BaseConfig (fosite.Config)
	if src.BaseConfig != nil {
		base := *src.BaseConfig
		cfg.BaseConfig = &base
	}
	return &cfg
}

func Register(app core.App, config *Config) error {
	if _, ok := app.Store().Get(registeringKey).(bool); ok {
		return errors.New("[Plugin/OAuth2] already registered for this app")
	}

	// Mark registration in progress so duplicate calls (even pre-bootstrap)
	// are rejected before hooks are bound.
	app.Store().Set(registeringKey, true)

	// Clone config so per-app secrets and defaults are isolated.
	config = cloneConfig(config)

	// Normalize defaults
	if config.PathPrefix == "" {
		config.PathPrefix = "/oauth2"
	}
	if config.UserInfoClaimStrategy == nil {
		config.UserInfoClaimStrategy = &DefaultUserInfoClaimStrategy{}
	}
	// OAuth 2.1 alignment: PKCE is required for all clients by default.
	if !config.EnforcePKCE && !config.EnforcePKCEForPublicClients {
		config.EnforcePKCE = true
	}

	inst := &Instance{
		cfg:       config,
		protected: map[string]*rfc9728.ProtectedResourceMetadata{},
	}

	// Store the instance immediately so public helpers like
	// RegisterProtectedResourceMetadata work even before bootstrap.
	app.Store().Set(storeKey, inst)

	// Attach bootstrap handler
	loadParams := func(app core.App) (err error) {
		inst.privateKey, err = loadPrivateKeyFromAppStorage(app)
		if err != nil {
			return fmt.Errorf("Plugin/OAuth2: Failed to load or generate private key: %w", err)
		}
		inst.cfg.GlobalSecret, err = loadGlobalSecretFromAppStorage(app)
		if err != nil {
			return fmt.Errorf("Plugin/OAuth2: Failed to load or generate global secret: %w", err)
		}

		inst.store = NewOAuth2Store(app)
		inst.provider = compose.Compose(
			inst.cfg.BaseConfig,
			inst.store,
			compose.CommonStrategy{
				CoreStrategy: NewPocketBaseStrategy(app, inst.cfg),
				OpenIDConnectTokenStrategy: compose.NewOpenIDConnectStrategy(
					func(ctx context.Context) (interface{}, error) {
						if inst.privateKey == nil {
							panic("[Plugin/OAuth2] Private key is not initialized!! This should never happen because we load it during app bootstrap.")
						}
						return inst.privateKey, nil
					},
					inst.cfg,
				),
			},

			compose.OAuth2AuthorizeExplicitFactory,
			compose.OAuth2RefreshTokenGrantFactory,
			compose.OAuth2TokenIntrospectionFactory,
			compose.OAuth2TokenRevocationFactory,
			compose.OAuth2PKCEFactory,

			compose.OpenIDConnectExplicitFactory,
			compose.OpenIDConnectRefreshFactory,
		)

		inst.metadata = buildProviderMetadata(app, inst.cfg)
		return nil
	}

	if app.IsBootstrapped() {
		if err := loadParams(app); err != nil {
			return err
		}
	} else {
		app.OnBootstrap().BindFunc(func(e *core.BootstrapEvent) error {
			if err := e.Next(); err != nil {
				return err
			}
			return loadParams(e.App)
		})
	}

	// Attach HTTP handlers
	app.OnServe().BindFunc(func(se *core.ServeEvent) error {
		bindOAuth2Handlers(inst, se.Router)
		bindOAuth2WellKnownHandlers(inst, se.Router)
		// rfc9728 middleware for protected resource endpoints
		inst.RegisterProtectedResourceMetadata(
			&rfc9728.ProtectedResourceMetadata{
				Resource: app.Settings().Meta.AppURL + config.PathPrefix + "/userinfo",
				AuthorizationServers: []string{
					app.Settings().Meta.AppURL,
				},
				BearerMethodsSupported: []string{"header"},
				ScopesSupported:        []string{"openid", "profile", "email"},
			},
		)
		return se.Next()
	})

	// Attach event listeners
	app.OnRecordCreate(consts.ClientCollectionName).
		BindFunc(func(e *core.RecordEvent) error {
			e.App.Logger().Info(
				"[Plugin/OAuth2] New client registered",
				slog.Any("client_id", e.Record.GetString("client_id")),
				slog.Any("client_name", e.Record.GetString("client_name")),
			)

			h, _ := inst.cfg.GetSecretsHasher(context.Background()).Hash(
				e.Context,
				[]byte(e.Record.GetString("client_secret")),
			)
			e.Record.Set("client_secret", string(h))
			return e.Next()
		})

	// Attach cron jobs
	app.Cron().MustAdd(consts.CleanupExpiredSessionsJobName, "0 * * * *", func() {
		for _, collection := range []string{
			consts.AuthCodeCollectionName,
			consts.AccessCollectionName,
			consts.RefreshCollectionName,
			consts.PKCECollectionName,
			consts.OpenIDConnectCollectionName,
			consts.JTICollectionName,
		} {
			records, err := app.FindAllRecords(
				collection,
				dbx.NewExp("expires_at < {:now}", dbx.Params{"now": time.Now().Unix()}),
			)
			if err != nil {
				app.Logger().Error(
					"[Plugin/OAuth2] Failed to query expired sessions for cleanup",
					slog.Any("collection", collection),
					slog.Any("error", err),
				)
				continue
			}
			for _, record := range records {
				if err := app.Delete(record); err != nil {
					app.Logger().Error(
						"[Plugin/OAuth2] Failed to delete expired session during cleanup",
						slog.Any("collection", collection),
						slog.Any("record_id", record.Id),
						slog.Any("error", err),
					)
				}
			}
		}
	})

	return nil
}

//

// buildProviderMetadata constructs the OIDC/OAuth2 discovery metadata.
// Aligned with OAuth 2.1: implicit grant and hybrid flows are removed.
func buildProviderMetadata(app core.App, cfg *Config) *openid.OpenIDProviderMetadata {
	return &openid.OpenIDProviderMetadata{
		AuthorizationServerMetadata: rfc8414.AuthorizationServerMetadata{
			Issuer:                app.Settings().Meta.AppURL,
			RegistrationEndpoint:  app.Settings().Meta.AppURL + cfg.PathPrefix + "/register",
			AuthzEndpoint:         app.Settings().Meta.AppURL + cfg.PathPrefix + "/auth",
			TokenEndpoint:         app.Settings().Meta.AppURL + cfg.PathPrefix + "/token",
			RevocationEndpoint:    app.Settings().Meta.AppURL + cfg.PathPrefix + "/revoke",
			IntrospectionEndpoint: app.Settings().Meta.AppURL + cfg.PathPrefix + "/introspect",

			TokenEndpointAuthMethodsSupported:         []string{"client_secret_basic", "client_secret_post"},
			RevocationEndpointAuthMethodsSupported:    []string{"client_secret_basic", "client_secret_post"},
			IntrospectionEndpointAuthMethodsSupported: []string{"client_secret_basic", "client_secret_post"},

			JwksURI: app.Settings().Meta.AppURL + "/.well-known/jwks.json",

			ScopesSupported: []string{
				"openid",
				"profile",
				"email",
				"address",
				"phone",
			},
			// OAuth 2.1 alignment: only "code" is advertised.
			// "token" (implicit), "id_token", and hybrid response types are removed.
			ResponseTypesSupported: []string{
				"code",
			},
			ResponseModesSupported: []string{
				"query",
				"fragment",
			},
			// OAuth 2.1 alignment: "implicit" grant type removed.
			GrantTypesSupported: []string{
				"authorization_code",
				"refresh_token",
			},
			CodeChallengeMethodsSupported: []string{
				"S256",
			},
		},
		UserInfoEndpoint: app.Settings().Meta.AppURL + cfg.PathPrefix + "/userinfo",
		AcrValuesSupported: []string{
			"loa1",
			"loa2",
		},
		SubjectTypesSupported: []string{
			"public",
		},
		IDTokenSigningAlgValuesSupported: []string{
			"RS256",
		},
		UserInfoSigningAlgValuesSupported: []string{
			"none",
		},
		RequestObjectSigningAlgValuesSupported: []string{
			"none",
		},
		DisplayValuesSupported: []string{
			"page",
		},
		ClaimTypesSupported: []string{
			"normal",
		},
		ClaimsSupported: []string{
			"amr",
			"aud",
			"azp",
			"client_id",
			"exp",
			"iat",
			"iss",
			"jti",
			"rat",
			"sub",
			"name",
			"given_name",
			"family_name",
			"middle_name",
			"nickname",
			"preferred_username",
			"profile",
			"picture",
			"website",
			"email",
			"email_verified",
			"gender",
			"birthdate",
			"zoneinfo",
			"locale",
			"phone_number",
			"phone_number_verified",
			"address",
			"updated_at",
		},
		ClaimsParameterSupported:      false,
		RequestParameterSupported:     true,
		RequestURIParameterSupported:  true,
		RequireRequestURIRegistration: true,
	}
}

//

// ResetGlobalStateForTests is deprecated and no-op.
// State is now per-app; use ResetStateForTests(app) instead.
func ResetGlobalStateForTests() {}

// ResetStateForTests removes the OAuth2 instance from the app's store.
// Use this in tests that need a clean slate.
func ResetStateForTests(app core.App) {
	app.Store().Remove(storeKey)
}

//

func bindOAuth2Handlers(inst *Instance, r *router.Router[*core.RequestEvent]) {
	rg := r.Group(inst.cfg.PathPrefix)
	rg.GET("/auth", func(e *core.RequestEvent) error { return api_OAuth2Authorize(e, inst) })
	rg.POST("/auth", func(e *core.RequestEvent) error { return api_OAuth2Authorize(e, inst) })
	rg.GET("/token", func(e *core.RequestEvent) error { return api_OAuth2Token(e, inst) })
	rg.POST("/token", func(e *core.RequestEvent) error { return api_OAuth2Token(e, inst) })
	rg.POST("/revoke", func(e *core.RequestEvent) error { return api_OAuth2Revoke(e, inst) })
	rg.POST("/introspect", func(e *core.RequestEvent) error { return api_OAuth2Introspect(e, inst) })
	rg.GET("/userinfo", func(e *core.RequestEvent) error { return api_OAuth2UserInfo(e, inst) }).Bind(rfc9728.RequireAuthRFC9728WWWAuthenticateResponse())
	rg.POST("/userinfo", func(e *core.RequestEvent) error { return api_OAuth2UserInfo(e, inst) }).Bind(rfc9728.RequireAuthRFC9728WWWAuthenticateResponse())
	// rfc7591
	// Dynamic Client Registration
	// @ref https://datatracker.ietf.org/doc/html/rfc7591
	if inst.cfg.EnableRFC7591DynamicClientRegistration {
		rg.POST("/register", func(e *core.RequestEvent) error { return api_OAuth2Register(e, inst) })
	}
	// ui
	uiHandler := func(e *core.RequestEvent) error {
		return e.FileFS(ui.DistDirFS, "login.html")
	}
	r.GET("/oauth2/login", uiHandler)
	r.POST("/oauth2/login", uiHandler)
}

func bindOAuth2WellKnownHandlers(inst *Instance, r *router.Router[*core.RequestEvent]) {
	// rfc8414
	// Authorization Server Metadata
	// @ref https://datatracker.ietf.org/doc/html/rfc8414
	// @ref https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderMetadata
	handleJSON(r, "/.well-known/oauth-authorization-server", func(_ *core.RequestEvent) (interface{}, error) {
		inst.mu.RLock()
		defer inst.mu.RUnlock()
		return inst.metadata.AuthorizationServerMetadata, nil
	})
	handleJSON(r, "/.well-known/openid-configuration", func(_ *core.RequestEvent) (interface{}, error) {
		inst.mu.RLock()
		defer inst.mu.RUnlock()
		return inst.metadata, nil
	})

	// rfc7517
	// JSON Web Key (JWK)
	// @ref https://datatracker.ietf.org/doc/html/rfc7517
	rfc7517KeySet := &jose.JSONWebKeySet{
		Keys: []jose.JSONWebKey{inst.privateKey.Public()},
	}
	handleJSON(r, "/.well-known/jwks.json", func(_ *core.RequestEvent) (interface{}, error) {
		return rfc7517KeySet, nil
	})

	// rfc9728
	// Protected Resource Metadata
	// @ref https://datatracker.ietf.org/doc/html/rfc9728
	if inst.cfg.EnableRFC9728ProtectedResourceMetadata {
		handleJSON(r, "/.well-known/oauth-protected-resource/{resource}", func(e *core.RequestEvent) (interface{}, error) {
			inst.mu.RLock()
			defer inst.mu.RUnlock()

			// The resource identifier is expected to be in the path. For example, if the
			// resource is "https://api.example.com/resource", the client would request
			// "https://api.example.com/.well-known/oauth-protected-resource/resource".
			key := strings.Trim(e.Request.PathValue("resource"), "/")

			if md, ok := inst.protected[key]; ok {
				return md, nil
			}
			return nil, e.NotFoundError("", nil)
		})
	}
}

func handleJSON(r *router.Router[*core.RequestEvent], path string, getter func(e *core.RequestEvent) (interface{}, error)) {
	h := func(e *core.RequestEvent) error {
		req := e.Request
		w := e.Response
		// Set CORS headers for cross-origin client discovery.
		// OAuth metadata is public information, so allowing any origin is safe.
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
		// Handle CORS preflight requests
		if req.Method == http.MethodOptions {
			return e.NoContent(http.StatusNoContent)
		}
		// Only GET allowed for metadata retrieval
		if req.Method != http.MethodGet {
			return e.Error(http.StatusMethodNotAllowed, "", nil)
		}
		data, err := getter(e)
		if err != nil {
			var apiErr *router.ApiError
			if errors.As(err, &apiErr) {
				return err
			}
			return e.InternalServerError("", err)
		}
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(data); err != nil {
			return e.InternalServerError("", err)
		}
		return nil
	}

	r.OPTIONS(path, h)
	r.GET(path, h)
	r.POST(path, h)
}
