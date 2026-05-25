package oauth2

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/go-jose/go-jose/v3"
	"github.com/ory/fosite"
	"github.com/ory/fosite/compose"
	"errors"

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

// registrationGuard tracks which *core.App values have an in-flight or
// completed Register() call. LoadOrStore is atomic, which makes concurrent
// Register() invocations on the same app race-free (in contrast to the
// previous Get/Set sequence on app.Store(), which had a TOCTOU window
// where both racers could pass the duplicate check and double-bind hooks).
var registrationGuard sync.Map // key: core.App, value: struct{}{}

type BaseConfig = fosite.Config

type Config struct {
	*BaseConfig

	PathPrefix                             string
	UserCollection                         string
	UserInfoClaimStrategy                  UserInfoClaimStrategy
	EnableRFC7591DynamicClientRegistration bool
	EnableRFC9728ProtectedResourceMetadata bool

	// MasterKeyProvider supplies the at-rest encryption master key for
	// envelope-encrypting OAuth2 key material in _params. If nil, the
	// DefaultMasterKeyProvider (reads OAUTH2_MASTER_KEY env) is used.
	// When the provider returns a nil master, encryption is disabled
	// and values are stored in legacy plaintext form (dev / back-compat).
	MasterKeyProvider MasterKeyProvider

	// DynamicClientRegistrationInitialAccessTokens, when EnableRFC7591…
	// is true, gates the /oauth2/register endpoint behind RFC 7591 §3
	// Initial Access Tokens. Each entry is a bearer token operators must
	// hand out to legitimate registration callers. Requests without an
	// Authorization: Bearer <token> header matching one of these values
	// are rejected with 401.
	//
	// Nil OR empty disables the gate, BUT the plugin then refuses to
	// register the /register route at all unless
	// AllowUnauthenticatedDynamicClientRegistration is also set (a loud
	// opt-in for development environments where rate-limit + network
	// boundary already gate the endpoint).
	DynamicClientRegistrationInitialAccessTokens []string

	// AllowUnauthenticatedDynamicClientRegistration acknowledges that DCR
	// is intentionally exposed with no Initial Access Token requirement.
	// REQUIRED when EnableRFC7591DynamicClientRegistration is true and
	// DynamicClientRegistrationInitialAccessTokens is empty; otherwise
	// the /register route is silently NOT bound.
	//
	// Use only in development or in environments where the registration
	// endpoint is reachable solely from a trusted network segment. Public
	// deployments should always populate InitialAccessTokens instead.
	AllowUnauthenticatedDynamicClientRegistration bool
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

// cloneConfig produces a per-app copy of Config so per-tenant state never
// leaks across Register() calls.
//
// What gets deep-copied: the embedded fosite.Config struct, plus the
// slice-typed fields where fosite (or the plugin) writes per-app state —
// GlobalSecret, RotatedGlobalSecrets, AllowedPromptValues,
// RefreshTokenScopes, SanitationWhiteList, and the handler-registry
// slices that fosite mutates when a getter populates defaults.
//
// What stays shared (by design): function and interface fields
// (ScopeStrategy, AudienceMatchingStrategy, JWKSFetcherStrategy,
// ClientAuthenticationStrategy, ResponseModeHandlerExtension,
// MessageCatalog, ClientSecretsHasher, HTTPClient, FormPostHTMLTemplate,
// RedirectSecureChecker, HMACHasher). These are expected to be stateless
// (or owned by the caller). After Register() the plugin treats them as
// read-only — callers MUST NOT mutate any field of a Config passed to
// Register() after the call returns.
func cloneConfig(src *Config) *Config {
	// Shallow copy the outer Config struct.
	cfg := *src

	// Deep copy the embedded fosite.Config.
	if src.BaseConfig != nil {
		base := *src.BaseConfig

		// Byte/string slices — fosite reads these in hot paths and the
		// plugin overwrites GlobalSecret during loadParams. Aliasing
		// would let one tenant's secret leak into another.
		base.GlobalSecret = cloneBytes(src.BaseConfig.GlobalSecret)
		base.RotatedGlobalSecrets = cloneByteSlices(src.BaseConfig.RotatedGlobalSecrets)
		base.AllowedPromptValues = cloneStrings(src.BaseConfig.AllowedPromptValues)
		base.RefreshTokenScopes = cloneStrings(src.BaseConfig.RefreshTokenScopes)
		base.SanitationWhiteList = cloneStrings(src.BaseConfig.SanitationWhiteList)

		// Handler registries — fosite's GetXEndpointHandlers append
		// default handlers to the receiver-config slice on first call,
		// which would otherwise be observable across tenants.
		base.AuthorizeEndpointHandlers = slices.Clone(src.BaseConfig.AuthorizeEndpointHandlers)
		base.TokenEndpointHandlers = slices.Clone(src.BaseConfig.TokenEndpointHandlers)
		base.TokenIntrospectionHandlers = slices.Clone(src.BaseConfig.TokenIntrospectionHandlers)
		base.RevocationHandlers = slices.Clone(src.BaseConfig.RevocationHandlers)
		base.PushedAuthorizeEndpointHandlers = slices.Clone(src.BaseConfig.PushedAuthorizeEndpointHandlers)

		cfg.BaseConfig = &base
	}
	return &cfg
}

func cloneBytes(in []byte) []byte {
	if in == nil {
		return nil
	}
	out := make([]byte, len(in))
	copy(out, in)
	return out
}

func cloneByteSlices(in [][]byte) [][]byte {
	if in == nil {
		return nil
	}
	out := make([][]byte, len(in))
	for i, v := range in {
		out[i] = cloneBytes(v)
	}
	return out
}

func cloneStrings(in []string) []string {
	if in == nil {
		return nil
	}
	return slices.Clone(in)
}

func Register(app core.App, config *Config) error {
	// Atomic claim — sync.Map.LoadOrStore is race-free, unlike the prior
	// Get-then-Set on app.Store(). Concurrent Register() calls on the
	// same app collapse to one winner; losers see loaded == true and
	// return the duplicate error without binding any hooks.
	if _, loaded := registrationGuard.LoadOrStore(app, struct{}{}); loaded {
		return errors.New("[Plugin/OAuth2] already registered for this app")
	}

	// Keep the legacy sentinel in app.Store() too; this is observable by
	// any external code that already inspected it.
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

	// RFC 7591 DCR safety gate: refuse to register when DCR is enabled
	// but neither Initial Access Tokens nor the explicit
	// AllowUnauthenticatedDynamicClientRegistration opt-in is set. Fail
	// closed; the alternative is exposing /oauth2/register to the world.
	if config.EnableRFC7591DynamicClientRegistration &&
		len(config.DynamicClientRegistrationInitialAccessTokens) == 0 &&
		!config.AllowUnauthenticatedDynamicClientRegistration {
		// Roll back the registrationGuard claim so a corrected config
		// can re-attempt registration without restarting the process.
		registrationGuard.Delete(app)
		app.Store().Remove(registeringKey)
		return errors.New("[Plugin/OAuth2] EnableRFC7591DynamicClientRegistration is on but no Initial Access Tokens are configured and AllowUnauthenticatedDynamicClientRegistration is false — refusing to expose an unauthenticated /register endpoint")
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
					func(ctx context.Context) (any, error) {
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

		metadata := buildProviderMetadata(app, inst.cfg)
		// Merge any pre-bootstrap protected-resource scope registrations
		// that arrived before inst.metadata existed.
		inst.mu.Lock()
		inst.metadata = metadata
		for _, md := range inst.protected {
			mergeProtectedScopes(inst.metadata, md.ScopesSupported)
		}
		inst.mu.Unlock()
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

			// Hash the plaintext client_secret on the way in. A hash
			// failure (e.g., misconfigured bcrypt cost) MUST abort the
			// create — silently writing the unhashed secret would leave
			// it readable in _oauth2Clients.client_secret and break
			// client_secret_basic / client_secret_post auth at the token
			// endpoint.
			h, herr := inst.cfg.GetSecretsHasher(context.Background()).Hash(
				e.Context,
				[]byte(e.Record.GetString("client_secret")),
			)
			if herr != nil {
				return fmt.Errorf("[Plugin/OAuth2] failed to hash client_secret: %w", herr)
			}
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
			consts.InteractionCollectionName,
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
			// Client.GetResponseModes (client/client.go) allows
			// default/fragment/form_post/query. Keep discovery aligned
			// with what the client actually accepts.
			ResponseModesSupported: []string{
				"query",
				"fragment",
				"form_post",
			},
			// OAuth 2.1 alignment: "implicit" grant type removed.
			GrantTypesSupported: []string{
				"authorization_code",
				"refresh_token",
			},
			CodeChallengeMethodsSupported: []string{
				"S256",
			},
			// RFC 9207: api_OAuth2Authorize adds "iss" to every
			// authorization response so RPs can detect mix-up attacks.
			AuthorizationResponseIssParameterSupported: true,
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
	Deregister(app)
}

// Deregister removes the plugin's per-app state from the given core.App
// and clears the registrationGuard entry. Use this in long-running
// processes that create and destroy tenant apps dynamically — otherwise
// registrationGuard accumulates stale interface-value entries for the
// lifetime of the process.
//
// After Deregister, Register may be called again on the same app value.
// HTTP handlers and cron jobs already bound to the app remain bound; this
// only releases the plugin's bookkeeping state. For full teardown, drop
// the core.App itself.
func Deregister(app core.App) {
	if app == nil {
		return
	}
	app.Store().Remove(storeKey)
	app.Store().Remove(registeringKey)
	registrationGuard.Delete(app)
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
	//
	// Route binding is gated AT REGISTRATION TIME (see Register) so a
	// misconfigured deployment fails to boot rather than silently
	// exposing an unauthenticated /register endpoint. By the time we
	// reach this code we already know the configuration is safe.
	if inst.cfg.EnableRFC7591DynamicClientRegistration {
		rg.POST("/register", func(e *core.RequestEvent) error { return api_OAuth2Register(e, inst) })
	}
	// ui
	uiHandler := func(e *core.RequestEvent) error {
		return e.FileFS(ui.DistDirFS, "login.html")
	}
	// Bind login under the configured PathPrefix so the redirect built in
	// api_OAuth2Authorize (PathPrefix + "/login") resolves for non-default
	// prefixes as well.
	rg.GET("/login", uiHandler)
	rg.POST("/login", uiHandler)

	// lr7 + mci: server-owned interaction store. /login/state gives the
	// UI metadata for a pending interaction (no browser-controlled state
	// blob), /login/complete consumes the pending interaction and runs
	// the actual fosite authorize handshake using server-stored params.
	rg.GET("/login/state", func(e *core.RequestEvent) error { return api_OAuth2LoginState(e, inst) })
	rg.OPTIONS("/login/state", func(e *core.RequestEvent) error { return api_OAuth2LoginState(e, inst) })
	rg.POST("/login/complete", func(e *core.RequestEvent) error { return api_OAuth2LoginComplete(e, inst) })
	rg.OPTIONS("/login/complete", func(e *core.RequestEvent) error { return api_OAuth2LoginComplete(e, inst) })
}

func bindOAuth2WellKnownHandlers(inst *Instance, r *router.Router[*core.RequestEvent]) {
	// rfc8414
	// Authorization Server Metadata
	// @ref https://datatracker.ietf.org/doc/html/rfc8414
	// @ref https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderMetadata
	handleJSON(r, "/.well-known/oauth-authorization-server", func(_ *core.RequestEvent) (any, error) {
		inst.mu.RLock()
		defer inst.mu.RUnlock()
		return inst.metadata.AuthorizationServerMetadata, nil
	})
	handleJSON(r, "/.well-known/openid-configuration", func(_ *core.RequestEvent) (any, error) {
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
	handleJSON(r, "/.well-known/jwks.json", func(_ *core.RequestEvent) (any, error) {
		return rfc7517KeySet, nil
	})

	// rfc9728
	// Protected Resource Metadata
	// @ref https://datatracker.ietf.org/doc/html/rfc9728
	if inst.cfg.EnableRFC9728ProtectedResourceMetadata {
		handleJSON(r, "/.well-known/oauth-protected-resource/{resource}", func(e *core.RequestEvent) (any, error) {
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

func handleJSON(r *router.Router[*core.RequestEvent], path string, getter func(e *core.RequestEvent) (any, error)) {
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
