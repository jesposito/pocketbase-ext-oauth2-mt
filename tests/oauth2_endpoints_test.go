package oauth2

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"slices"
	"strings"
	"testing"
	"time"

	oauth2 "github.com/jesposito/pocketbase-ext-oauth2-mt"
	"github.com/jesposito/pocketbase-ext-oauth2-mt/consts"
	"github.com/ory/fosite"
	"github.com/pocketbase/pocketbase/apis"
	"github.com/pocketbase/pocketbase/core"
	"github.com/pocketbase/pocketbase/tests"
)

func TestTokenEndpoint_MissingGrantType(t *testing.T) {
	scenario := tests.ApiScenario{
		Name:   "token - missing grant_type",
		Method: http.MethodPost,
		URL:    "/oauth2/token",
		Body:   strings.NewReader(""),
		Headers: map[string]string{
			"Content-Type": "application/x-www-form-urlencoded",
		},
		ExpectedStatus:  400,
		ExpectedContent: []string{"invalid_request"},
		TestAppFactory: func(t testing.TB) *tests.TestApp {
			return setupTestAppForScenario(t)
		},
	}
	scenario.Test(t)
}

func TestTokenEndpoint_InvalidClientCredentials(t *testing.T) {
	scenario := tests.ApiScenario{
		Name:   "token - invalid client credentials",
		Method: http.MethodPost,
		URL:    "/oauth2/token",
		Body:   strings.NewReader("grant_type=authorization_code&code=fakecode&client_id=bad-client&client_secret=bad-secret&redirect_uri=http://localhost/callback"),
		Headers: map[string]string{
			"Content-Type": "application/x-www-form-urlencoded",
		},
		ExpectedStatus:  401,
		ExpectedContent: []string{"invalid_client"},
		TestAppFactory: func(t testing.TB) *tests.TestApp {
			app := setupTestAppForScenario(t)
			return app
		},
		BeforeTestFunc: func(t testing.TB, app *tests.TestApp, e *core.ServeEvent) {
			seedUsersCollection(t, app)
			seedTestUser(t, app)
			seedTestClient(t, app)
		},
	}
	scenario.Test(t)
}

func TestTokenEndpoint_InvalidCode(t *testing.T) {
	scenario := tests.ApiScenario{
		Name:   "token - authorization_code grant with invalid code",
		Method: http.MethodPost,
		URL:    "/oauth2/token",
		Body: strings.NewReader(
			"grant_type=authorization_code&code=invalid-code&client_id=" + testClientID +
				"&client_secret=" + testClientSecret +
				"&redirect_uri=" + testRedirectURI,
		),
		Headers: map[string]string{
			"Content-Type": "application/x-www-form-urlencoded",
		},
		ExpectedStatus:  401,
		ExpectedContent: []string{"invalid_client"},
		TestAppFactory: func(t testing.TB) *tests.TestApp {
			return setupTestAppForScenario(t)
		},
		BeforeTestFunc: func(t testing.TB, app *tests.TestApp, e *core.ServeEvent) {
			seedUsersCollection(t, app)
			seedTestUser(t, app)
			seedTestClient(t, app)
		},
	}
	scenario.Test(t)
}

func TestRevokeEndpoint_MissingToken(t *testing.T) {
	scenario := tests.ApiScenario{
		Name:   "revoke - missing token param",
		Method: http.MethodPost,
		URL:    "/oauth2/revoke",
		Body:   strings.NewReader(""),
		Headers: map[string]string{
			"Content-Type": "application/x-www-form-urlencoded",
		},
		ExpectedStatus:  400,
		ExpectedContent: []string{"invalid_request"},
		TestAppFactory: func(t testing.TB) *tests.TestApp {
			return setupTestAppForScenario(t)
		},
	}
	scenario.Test(t)
}

func TestRevokeEndpoint_InvalidToken(t *testing.T) {
	scenario := tests.ApiScenario{
		Name:   "revoke - invalid token",
		Method: http.MethodPost,
		URL:    "/oauth2/revoke",
		Body:   strings.NewReader("token=invalid-token-value"),
		Headers: map[string]string{
			"Content-Type": "application/x-www-form-urlencoded",
		},
		ExpectedStatus:  400,
		ExpectedContent: []string{"invalid_request"},
		TestAppFactory: func(t testing.TB) *tests.TestApp {
			return setupTestAppForScenario(t)
		},
	}
	scenario.Test(t)
}

func TestIntrospectEndpoint_MissingToken(t *testing.T) {
	scenario := tests.ApiScenario{
		Name:   "introspect - missing token param",
		Method: http.MethodPost,
		URL:    "/oauth2/introspect",
		Body:   strings.NewReader(""),
		Headers: map[string]string{
			"Content-Type": "application/x-www-form-urlencoded",
		},
		ExpectedStatus:  400,
		ExpectedContent: []string{"invalid_request"},
		TestAppFactory: func(t testing.TB) *tests.TestApp {
			return setupTestAppForScenario(t)
		},
	}
	scenario.Test(t)
}

func TestIntrospectEndpoint_InvalidToken(t *testing.T) {
	scenario := tests.ApiScenario{
		Name:   "introspect - expired/invalid token returns inactive",
		Method: http.MethodPost,
		URL:    "/oauth2/introspect",
		Body:   strings.NewReader("token=expired-or-invalid-token"),
		Headers: map[string]string{
			"Content-Type": "application/x-www-form-urlencoded",
		},
		ExpectedStatus:  401,
		ExpectedContent: []string{"request_unauthorized"},
		TestAppFactory: func(t testing.TB) *tests.TestApp {
			return setupTestAppForScenario(t)
		},
	}
	scenario.Test(t)
}

func TestUserInfoEndpoint_NoAuth(t *testing.T) {
	scenario := tests.ApiScenario{
		Name:           "userinfo - no auth returns 401 with WWW-Authenticate",
		Method:         http.MethodGet,
		URL:            "/oauth2/userinfo",
		ExpectedStatus: 401,
		TestAppFactory: func(t testing.TB) *tests.TestApp {
			return setupTestAppForScenario(t)
		},
		AfterTestFunc: func(t testing.TB, app *tests.TestApp, res *http.Response) {
			wwwAuth := res.Header.Get("WWW-Authenticate")
			if wwwAuth == "" {
				t.Error("expected WWW-Authenticate header to be set")
			}
			if !strings.Contains(wwwAuth, "Bearer") {
				t.Errorf("expected WWW-Authenticate to contain 'Bearer', got %q", wwwAuth)
			}
			if !strings.Contains(wwwAuth, "resource_metadata") {
				t.Errorf("expected WWW-Authenticate to contain 'resource_metadata', got %q", wwwAuth)
			}
		},
	}
	scenario.Test(t)
}

func TestUserInfoEndpoint_WithAuth(t *testing.T) {
	scenario := tests.ApiScenario{
		Name:            "userinfo - authenticated returns user info",
		Method:          http.MethodGet,
		URL:             "/oauth2/userinfo",
		ExpectedStatus:  200,
		ExpectedContent: []string{`"sub"`},
		TestAppFactory: func(t testing.TB) *tests.TestApp {
			return setupTestAppForScenario(t)
		},
		BeforeTestFunc: func(t testing.TB, app *tests.TestApp, e *core.ServeEvent) {
			seedUsersCollection(t, app)
			seedTestUser(t, app)
		},
		Headers: map[string]string{
			// Token will be set dynamically but we need BeforeTestFunc to seed data first.
			// We'll use a different approach — set the token in AfterTestFunc or use a wrapper.
		},
	}

	// We need to generate the token after seeding, so we'll use a custom approach.
	// Override with a closure that captures the token.
	scenario.BeforeTestFunc = func(t testing.TB, app *tests.TestApp, e *core.ServeEvent) {
		seedUsersCollection(t, app)
		user := seedTestUser(t, app)
		token, err := user.NewAuthToken()
		if err != nil {
			t.Fatalf("failed to generate auth token: %v", err)
		}
		scenario.Headers = map[string]string{
			"Authorization": token,
		}
	}

	scenario.Test(t)
}

func TestRegisterEndpoint_ValidMetadata(t *testing.T) {
	scenario := tests.ApiScenario{
		Name:   "register - valid client metadata (RFC 7591)",
		Method: http.MethodPost,
		URL:    "/oauth2/register",
		Body: strings.NewReader(`{
			"client_name": "New Dynamic Client",
			"redirect_uris": ["http://localhost:3000/callback"]
		}`),
		Headers: map[string]string{
			"Content-Type": "application/json",
		},
		ExpectedStatus:  201,
		ExpectedContent: []string{`"client_id"`, `"client_secret"`},
		TestAppFactory: func(t testing.TB) *tests.TestApp {
			return setupTestAppForScenario(t)
		},
	}
	scenario.Test(t)
}

func TestRegisterEndpoint_MissingRedirectURIs(t *testing.T) {
	scenario := tests.ApiScenario{
		Name:   "register - missing redirect_uris",
		Method: http.MethodPost,
		URL:    "/oauth2/register",
		Body: strings.NewReader(`{
			"client_name": "Bad Client"
		}`),
		Headers: map[string]string{
			"Content-Type": "application/json",
		},
		ExpectedStatus:  400,
		ExpectedContent: []string{"Redirect_uris is required"},
		TestAppFactory: func(t testing.TB) *tests.TestApp {
			return setupTestAppForScenario(t)
		},
	}
	scenario.Test(t)
}

func TestAuthEndpoint_UnauthenticatedRedirects(t *testing.T) {
	scenario := tests.ApiScenario{
		Name:           "auth - unauthenticated redirects to login",
		Method:         http.MethodGet,
		URL:            "/oauth2/auth?response_type=code&client_id=" + testClientID + "&redirect_uri=" + testRedirectURI + "&scope=openid&state=teststate",
		ExpectedStatus: 307,
		TestAppFactory: func(t testing.TB) *tests.TestApp {
			return setupTestAppForScenario(t)
		},
		BeforeTestFunc: func(t testing.TB, app *tests.TestApp, e *core.ServeEvent) {
			seedUsersCollection(t, app)
			seedTestClient(t, app)
		},
		AfterTestFunc: func(t testing.TB, app *tests.TestApp, res *http.Response) {
			location := res.Header.Get("Location")
			if location == "" {
				t.Error("expected Location header for redirect")
			}
			if !strings.Contains(location, "oauth2/login") {
				t.Errorf("expected redirect to contain 'oauth2/login', got %q", location)
			}
		},
	}
	scenario.Test(t)
}

// TestAuthEndpoint_AccessDeniedRedirect verifies that when the consent UI
// posts ?error=access_denied (user clicked "Decline"), the OP redirects to
// the client with error=access_denied (not server_error) AND includes the
// RFC 9207 iss parameter. Covers beads pb-oauth2-mt-5sf and pb-oauth2-mt-iad.
func TestAuthEndpoint_AccessDeniedRedirect(t *testing.T) {
	scenario := tests.ApiScenario{
		Name:   "auth - access_denied carries error+iss back to client",
		Method: http.MethodGet,
		URL: "/oauth2/auth?response_type=code&client_id=" + testClientID +
			"&redirect_uri=" + testRedirectURI +
			"&scope=openid&state=teststate&code_challenge=abcdefghijklmnopqrstuvwxyz0123456789ABCDEFG" +
			"&code_challenge_method=S256&error=access_denied",
		ExpectedStatus: http.StatusSeeOther,
		TestAppFactory: func(t testing.TB) *tests.TestApp {
			return setupTestAppForScenario(t)
		},
		BeforeTestFunc: func(t testing.TB, app *tests.TestApp, e *core.ServeEvent) {
			seedUsersCollection(t, app)
			seedTestClient(t, app)
		},
		AfterTestFunc: func(t testing.TB, app *tests.TestApp, res *http.Response) {
			loc := res.Header.Get("Location")
			if loc == "" {
				t.Fatal("expected Location header for error redirect")
			}
			if !strings.HasPrefix(loc, testRedirectURI) {
				t.Errorf("redirect not back to client redirect_uri: %s", loc)
			}
			if !strings.Contains(loc, "error=access_denied") {
				t.Errorf("expected error=access_denied in redirect, got %s", loc)
			}
			if strings.Contains(loc, "error=server_error") {
				t.Errorf("expected access_denied, got server_error in %s", loc)
			}
			if !strings.Contains(loc, "iss=") {
				t.Errorf("expected RFC 9207 iss= in error redirect, got %s", loc)
			}
			if !strings.Contains(loc, "state=teststate") {
				t.Errorf("expected state echo in redirect, got %s", loc)
			}
		},
	}
	scenario.Test(t)
}

// TestAuthEndpoint_LoginRequiredHasIss verifies that login_required (a
// non-access_denied error already in the switch) also carries iss in its
// error redirect. Companion to TestAuthEndpoint_AccessDeniedRedirect for iad.
func TestAuthEndpoint_LoginRequiredHasIss(t *testing.T) {
	scenario := tests.ApiScenario{
		Name:   "auth - login_required error includes iss",
		Method: http.MethodGet,
		URL: "/oauth2/auth?response_type=code&client_id=" + testClientID +
			"&redirect_uri=" + testRedirectURI +
			"&scope=openid&state=teststate&code_challenge=abcdefghijklmnopqrstuvwxyz0123456789ABCDEFG" +
			"&code_challenge_method=S256&error=login_required",
		ExpectedStatus: http.StatusSeeOther,
		TestAppFactory: func(t testing.TB) *tests.TestApp {
			return setupTestAppForScenario(t)
		},
		BeforeTestFunc: func(t testing.TB, app *tests.TestApp, e *core.ServeEvent) {
			seedUsersCollection(t, app)
			seedTestClient(t, app)
		},
		AfterTestFunc: func(t testing.TB, app *tests.TestApp, res *http.Response) {
			loc := res.Header.Get("Location")
			if !strings.Contains(loc, "error=login_required") {
				t.Errorf("expected error=login_required in %s", loc)
			}
			if !strings.Contains(loc, "iss=") {
				t.Errorf("expected iss= in %s", loc)
			}
		},
	}
	scenario.Test(t)
}

func TestAuthEndpoint_MissingClientID(t *testing.T) {
	scenario := tests.ApiScenario{
		Name:            "auth - missing client_id",
		Method:          http.MethodGet,
		URL:             "/oauth2/auth?response_type=code&redirect_uri=" + testRedirectURI + "&scope=openid",
		ExpectedStatus:  401,
		ExpectedContent: []string{""},
		TestAppFactory: func(t testing.TB) *tests.TestApp {
			return setupTestAppForScenario(t)
		},
	}
	scenario.Test(t)
}

// TestRegister_RequiresIAT_When_Configured locks in the 3nl gate: when
// Config.DynamicClientRegistrationInitialAccessTokens is set, /register
// rejects requests missing or carrying a wrong bearer token with 401.
func TestRegister_RequiresIAT_When_Configured(t *testing.T) {
	const iat = "test-initial-access-token-xyz"

	setupApp := func(t testing.TB) *tests.TestApp {
		t.Helper()
		tempDir, err := os.MkdirTemp("", "pb_oauth2_iat_*")
		if err != nil {
			t.Fatal(err)
		}
		testApp, err := tests.NewTestApp(tempDir)
		if err != nil {
			os.RemoveAll(tempDir)
			t.Fatal(err)
		}
		if err := oauth2.Register(testApp, &oauth2.Config{
			BaseConfig: &fosite.Config{
				ScopeStrategy:            fosite.ExactScopeStrategy,
				AudienceMatchingStrategy: fosite.DefaultAudienceMatchingStrategy,
			},
			PathPrefix:                                   "/oauth2",
			UserCollection:                               testUserCollection,
			EnableRFC7591DynamicClientRegistration:       true,
			DynamicClientRegistrationInitialAccessTokens: []string{iat},
		}); err != nil {
			testApp.Cleanup()
			t.Fatal(err)
		}
		return testApp
	}

	t.Run("no_token_returns_401", func(t *testing.T) {
		scenario := tests.ApiScenario{
			Name:            "register without IAT is 401",
			Method:          http.MethodPost,
			URL:             "/oauth2/register",
			Body:            strings.NewReader(`{"redirect_uris":["https://rp.example.com/cb"]}`),
			Headers:         map[string]string{"Content-Type": "application/json"},
			ExpectedStatus:  http.StatusUnauthorized,
			ExpectedContent: []string{"Invalid_token"},
			TestAppFactory:  setupApp,
		}
		scenario.Test(t)
	})

	t.Run("wrong_token_returns_401", func(t *testing.T) {
		scenario := tests.ApiScenario{
			Name:   "register with wrong IAT is 401",
			Method: http.MethodPost,
			URL:    "/oauth2/register",
			Body:   strings.NewReader(`{"redirect_uris":["https://rp.example.com/cb"]}`),
			Headers: map[string]string{
				"Content-Type":  "application/json",
				"Authorization": "Bearer not-the-right-token",
			},
			ExpectedStatus:  http.StatusUnauthorized,
			ExpectedContent: []string{"Invalid_token"},
			TestAppFactory:  setupApp,
		}
		scenario.Test(t)
	})

	t.Run("valid_token_allows_registration", func(t *testing.T) {
		scenario := tests.ApiScenario{
			Name:   "register with valid IAT succeeds",
			Method: http.MethodPost,
			URL:    "/oauth2/register",
			Body:   strings.NewReader(`{"redirect_uris":["https://rp.example.com/cb"],"client_name":"iat-test","grant_types":["authorization_code"],"response_types":["code"],"token_endpoint_auth_method":"client_secret_post"}`),
			Headers: map[string]string{
				"Content-Type":  "application/json",
				"Authorization": "Bearer " + iat,
			},
			ExpectedStatus:  http.StatusCreated,
			ExpectedContent: []string{"client_id"},
			BeforeTestFunc: func(t testing.TB, app *tests.TestApp, e *core.ServeEvent) {
				seedUsersCollection(t, app)
			},
			TestAppFactory: setupApp,
		}
		scenario.Test(t)
	})
}

// TestRegister_RejectsUnsafeRedirectURIs locks in the redirect-URI policy.
func TestRegister_RejectsUnsafeRedirectURIs(t *testing.T) {
	cases := []struct {
		name       string
		uri        string
		ok         bool
		bodyMatch  string
	}{
		{"https_ok", "https://rp.example.com/cb", true, "client_id"},
		{"loopback_http_ok", "http://localhost:8080/cb", true, "client_id"},
		{"loopback_ipv4_ok", "http://127.0.0.1:8080/cb", true, "client_id"},
		{"plain_http_rejected", "http://rp.example.com/cb", false, "must use https"},
		{"with_fragment_rejected", "https://rp.example.com/cb#x", false, "must not contain a fragment"},
		{"non_absolute_rejected", "/cb", false, "must be an absolute URI"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			body := `{"redirect_uris":["` + tc.uri + `"],"client_name":"x","grant_types":["authorization_code"],"response_types":["code"],"token_endpoint_auth_method":"client_secret_post"}`
			want := http.StatusCreated
			if !tc.ok {
				want = http.StatusBadRequest
			}
			scenario := tests.ApiScenario{
				Method:          http.MethodPost,
				URL:             "/oauth2/register",
				Body:            strings.NewReader(body),
				Headers:         map[string]string{"Content-Type": "application/json"},
				ExpectedStatus:  want,
				ExpectedContent: []string{tc.bodyMatch},
				BeforeTestFunc: func(t testing.TB, app *tests.TestApp, e *core.ServeEvent) {
					seedUsersCollection(t, app)
				},
				TestAppFactory: setupTestAppForScenario,
			}
			scenario.Test(t)
		})
	}
}

// TestFullAuthCodeFlow_EndToEnd_PKCE drives the full RFC 6749 §4.1 +
// PKCE flow against a single tenant: /auth -> /login/complete -> /token
// -> /userinfo (RequireScope-gated). Also verifies that after /revoke
// the same access token can no longer hit a RequireScope-protected
// resource (closes the wg6 audit loop end-to-end).
//
// This is the headline integration test for mjh: it exercises the full
// happy path AND the revocation contract in one place.
func TestFullAuthCodeFlow_EndToEnd_PKCE(t *testing.T) {
	app := setupTestApp(t)
	defer app.Cleanup()
	seedTestUser(t, app)

	// Seed a client using the plaintext-then-hook-hashes pattern so the
	// OnRecordCreate hook produces a bcrypt hash fosite can verify
	// against testClientSecret. (The shared seedTestClient pre-hashes,
	// which double-bcrypts and breaks /token auth.)
	clientsCol, err := app.FindCollectionByNameOrId(consts.ClientCollectionName)
	if err != nil {
		t.Fatal(err)
	}
	clientRec := core.NewRecord(clientsCol)
	clientRec.Set("client_id", testClientID)
	clientRec.Set("client_name", testClientName)
	clientRec.Set("client_secret", testClientSecret)
	clientRec.Set("client_secret_expires_at", 0)
	clientRec.Set("redirect_uris", []string{testRedirectURI})
	clientRec.Set("grant_types", []string{"authorization_code", "refresh_token"})
	clientRec.Set("response_types", []string{"code"})
	clientRec.Set("scope", "openid profile email")
	clientRec.Set("audience", []string{})
	clientRec.Set("token_endpoint_auth_method", "client_secret_post")
	clientRec.Set("subject_type", "public")
	clientRec.Set("access_token_strategy", "opaque")
	for _, f := range []string{"contacts", "allowed_cors_origins", "request_uris"} {
		clientRec.Set(f, []string{})
	}
	if err := app.Save(clientRec); err != nil {
		t.Fatalf("save client: %v", err)
	}

	user, err := app.FindAuthRecordByEmail(testUserCollection, testUserEmail)
	if err != nil {
		t.Fatal(err)
	}
	pbToken, err := user.NewStaticAuthToken(time.Hour)
	if err != nil {
		t.Fatal(err)
	}

	// PKCE pair (S256). RFC 7636 requires verifier >=43 chars.
	verifier := "test-verifier-0123456789abcdefghijklmnopqrstuvwxyz"
	h := sha256.Sum256([]byte(verifier))
	challenge := base64.RawURLEncoding.EncodeToString(h[:])

	authForm := url.Values{}
	authForm.Set("response_type", "code")
	authForm.Set("client_id", testClientID)
	authForm.Set("redirect_uri", testRedirectURI)
	authForm.Set("scope", "openid profile")
	authForm.Set("code_challenge", challenge)
	authForm.Set("code_challenge_method", "S256")
	authForm.Set("state", "e2e-state")

	// Bind /api/widgets so we have a RequireScope-protected resource to
	// exercise after the token exchange + revocation.
	app.OnServe().BindFunc(func(se *core.ServeEvent) error {
		se.Router.GET("/api/widgets", func(e *core.RequestEvent) error {
			return e.JSON(http.StatusOK, map[string]any{"ok": true})
		}).Bind(oauth2.RequireScope(app, "openid"))
		return se.Next()
	})

	// Step 1: /auth -> /login?interaction_id
	authReq := httptest.NewRequest(http.MethodGet, "/oauth2/auth?"+authForm.Encode(), nil)
	authRec := httptest.NewRecorder()
	dispatchRequest(t, app, authRec, authReq)
	if authRec.Code < 300 || authRec.Code >= 400 {
		t.Fatalf("/auth = %d: %s", authRec.Code, authRec.Body.String())
	}
	loc, _ := url.Parse(authRec.Header().Get("Location"))
	interactionID := loc.Query().Get("interaction_id")
	if interactionID == "" {
		t.Fatalf("no interaction_id in /auth redirect")
	}

	// Step 2: /login/complete approve -> code redirect
	completeBody, _ := json.Marshal(map[string]any{
		"interaction_id":   interactionID,
		"pb_token":         pbToken,
		"pb_token_iat":     time.Now().Unix(),
		"decision":         "approve",
		"consented_scopes": []string{"openid", "profile"},
	})
	cReq := httptest.NewRequest(http.MethodPost, "/oauth2/login/complete", bytes.NewReader(completeBody))
	cReq.Header.Set("Content-Type", "application/json")
	cRec := httptest.NewRecorder()
	dispatchRequest(t, app, cRec, cReq)
	if cRec.Code != http.StatusOK {
		t.Fatalf("/login/complete = %d: %s", cRec.Code, cRec.Body.String())
	}
	var cResp struct {
		RedirectURI string `json:"redirect_uri"`
	}
	_ = json.NewDecoder(cRec.Body).Decode(&cResp)
	final, _ := url.Parse(cResp.RedirectURI)
	code := final.Query().Get("code")
	if code == "" {
		t.Fatalf("no code in final redirect: %s", cResp.RedirectURI)
	}
	if final.Query().Get("iss") == "" {
		t.Error("RFC 9207 iss missing in success redirect")
	}
	if final.Query().Get("state") != "e2e-state" {
		t.Errorf("state echo missing: %s", cResp.RedirectURI)
	}

	// Step 3: /token exchange (PKCE verifier).
	tokenForm := url.Values{}
	tokenForm.Set("grant_type", "authorization_code")
	tokenForm.Set("code", code)
	tokenForm.Set("redirect_uri", testRedirectURI)
	tokenForm.Set("client_id", testClientID)
	tokenForm.Set("client_secret", testClientSecret)
	tokenForm.Set("code_verifier", verifier)
	tReq := httptest.NewRequest(http.MethodPost, "/oauth2/token", strings.NewReader(tokenForm.Encode()))
	tReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	tRec := httptest.NewRecorder()
	dispatchRequest(t, app, tRec, tReq)
	if tRec.Code != http.StatusOK {
		t.Fatalf("/token = %d: %s", tRec.Code, tRec.Body.String())
	}
	var tokenResp struct {
		AccessToken string `json:"access_token"`
		TokenType   string `json:"token_type"`
		IDToken     string `json:"id_token"`
	}
	_ = json.NewDecoder(tRec.Body).Decode(&tokenResp)
	if tokenResp.AccessToken == "" {
		t.Fatalf("empty access_token: %s", tRec.Body.String())
	}
	if tokenResp.IDToken == "" {
		t.Error("missing id_token for openid scope")
	}

	// Step 4: hit /api/widgets — should pass with the granted openid scope.
	wReq := httptest.NewRequest(http.MethodGet, "/api/widgets", nil)
	wReq.Header.Set("Authorization", "Bearer "+tokenResp.AccessToken)
	wRec := httptest.NewRecorder()
	dispatchRequest(t, app, wRec, wReq)
	if wRec.Code != http.StatusOK {
		t.Fatalf("/api/widgets pre-revoke = %d: %s", wRec.Code, wRec.Body.String())
	}

	// Step 5: revoke the access token.
	rForm := url.Values{}
	rForm.Set("token", tokenResp.AccessToken)
	rForm.Set("token_type_hint", "access_token")
	rForm.Set("client_id", testClientID)
	rForm.Set("client_secret", testClientSecret)
	rReq := httptest.NewRequest(http.MethodPost, "/oauth2/revoke", strings.NewReader(rForm.Encode()))
	rReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rRec := httptest.NewRecorder()
	dispatchRequest(t, app, rRec, rReq)
	if rRec.Code != http.StatusOK {
		t.Fatalf("/revoke = %d: %s", rRec.Code, rRec.Body.String())
	}

	// Step 6: hit /api/widgets again — RequireScope must now reject.
	// This is the wg6 contract end-to-end: revocation actually blocks.
	w2Req := httptest.NewRequest(http.MethodGet, "/api/widgets", nil)
	w2Req.Header.Set("Authorization", "Bearer "+tokenResp.AccessToken)
	w2Rec := httptest.NewRecorder()
	dispatchRequest(t, app, w2Rec, w2Req)
	if w2Rec.Code != http.StatusUnauthorized {
		t.Fatalf("/api/widgets post-revoke = %d, want 401 (revocation should block RequireScope)", w2Rec.Code)
	}
}

// dispatchRequest mirrors examples/multitenant integration_test.go: build
// a fresh router via apis.NewRouter, trigger OnServe so plugin routes
// register, then BuildMux + ServeHTTP. This is how PocketBase recommends
// driving the in-process router from tests.
func dispatchRequest(t *testing.T, app *tests.TestApp, rec *httptest.ResponseRecorder, req *http.Request) {
	t.Helper()
	r, err := apis.NewRouter(app)
	if err != nil {
		t.Fatalf("apis.NewRouter: %v", err)
	}
	ev := &core.ServeEvent{App: app, Router: r}
	if err := app.OnServe().Trigger(ev, func(e *core.ServeEvent) error {
		mux, err := e.Router.BuildMux()
		if err != nil {
			return err
		}
		mux.ServeHTTP(rec, req)
		return nil
	}); err != nil {
		t.Fatalf("dispatch: %v", err)
	}
}

// TestLoginInteractionFlow covers the lr7 + mci redesign end-to-end:
//
//   1. /auth (unauth) redirects to /login?interaction_id=X
//   2. /login/state returns the interaction metadata
//   3. /login/complete decision=deny → access_denied + iss to CLIENT
//      redirect_uri (NOT a browser-supplied URI)
//   4. /login/complete approve + missing consent → consent_required
//   5. /login/complete approve + full consent → code in CLIENT redirect
//   6. interaction row is consumed (replay returns 404)
func TestLoginInteractionFlow(t *testing.T) {
	app := setupTestApp(t)
	defer app.Cleanup()
	seedTestUser(t, app)
	seedTestClient(t, app)

	user, err := app.FindAuthRecordByEmail(testUserCollection, testUserEmail)
	if err != nil {
		t.Fatal(err)
	}
	pbToken, err := user.NewStaticAuthToken(time.Hour)
	if err != nil {
		t.Fatal(err)
	}

	authForm := url.Values{}
	authForm.Set("response_type", "code")
	authForm.Set("client_id", testClientID)
	authForm.Set("redirect_uri", testRedirectURI)
	authForm.Set("scope", "openid profile")
	authForm.Set("code_challenge", "abcdefghijklmnopqrstuvwxyz0123456789ABCDEFG")
	authForm.Set("code_challenge_method", "S256")
	authForm.Set("state", "state-xyz")

	freshInteraction := func() string {
		t.Helper()
		req := httptest.NewRequest(http.MethodGet, "/oauth2/auth?"+authForm.Encode(), nil)
		rec := httptest.NewRecorder()
		dispatchRequest(t, app, rec, req)
		if rec.Code < 300 || rec.Code >= 400 {
			t.Fatalf("/auth = %d: %s", rec.Code, rec.Body.String())
		}
		loc, _ := url.Parse(rec.Header().Get("Location"))
		id := loc.Query().Get("interaction_id")
		if id == "" {
			t.Fatalf("expected interaction_id in /auth redirect, got %s", loc.String())
		}
		return id
	}

	t.Run("login_state_returns_metadata", func(t *testing.T) {
		id := freshInteraction()
		req := httptest.NewRequest(http.MethodGet, "/oauth2/login/state?id="+id, nil)
		rec := httptest.NewRecorder()
		dispatchRequest(t, app, rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("/login/state = %d: %s", rec.Code, rec.Body.String())
		}
		var resp struct {
			ClientID        string   `json:"client_id"`
			RequestedScopes []string `json:"requested_scopes"`
		}
		_ = json.NewDecoder(rec.Body).Decode(&resp)
		if resp.ClientID != testClientID {
			t.Errorf("client_id = %q, want %q", resp.ClientID, testClientID)
		}
		if !slices.Contains(resp.RequestedScopes, "openid") {
			t.Errorf("requested_scopes missing openid: %v", resp.RequestedScopes)
		}
	})

	postComplete := func(t *testing.T, body map[string]any) *httptest.ResponseRecorder {
		t.Helper()
		b, _ := json.Marshal(body)
		req := httptest.NewRequest(http.MethodPost, "/oauth2/login/complete", bytes.NewReader(b))
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()
		dispatchRequest(t, app, rec, req)
		return rec
	}

	t.Run("deny_returns_access_denied_to_client_uri", func(t *testing.T) {
		id := freshInteraction()
		rec := postComplete(t, map[string]any{
			"interaction_id": id,
			"pb_token":       pbToken,
			"pb_token_iat":   time.Now().Unix(),
			"decision":       "deny",
		})
		if rec.Code != http.StatusOK {
			t.Fatalf("/login/complete = %d: %s", rec.Code, rec.Body.String())
		}
		var resp struct {
			RedirectURI string `json:"redirect_uri"`
		}
		_ = json.NewDecoder(rec.Body).Decode(&resp)
		if !strings.HasPrefix(resp.RedirectURI, testRedirectURI) {
			t.Errorf("deny redirect must target client redirect_uri, got %s", resp.RedirectURI)
		}
		if !strings.Contains(resp.RedirectURI, "error=access_denied") {
			t.Errorf("missing error=access_denied: %s", resp.RedirectURI)
		}
		if !strings.Contains(resp.RedirectURI, "iss=") {
			t.Errorf("missing RFC 9207 iss: %s", resp.RedirectURI)
		}
	})

	t.Run("approve_without_consent_returns_consent_required", func(t *testing.T) {
		id := freshInteraction()
		rec := postComplete(t, map[string]any{
			"interaction_id":   id,
			"pb_token":         pbToken,
			"pb_token_iat":     time.Now().Unix(),
			"decision":         "approve",
			"consented_scopes": []string{},
		})
		if rec.Code != http.StatusOK {
			t.Fatalf("status %d: %s", rec.Code, rec.Body.String())
		}
		var resp struct {
			RedirectURI string `json:"redirect_uri"`
		}
		_ = json.NewDecoder(rec.Body).Decode(&resp)
		if !strings.Contains(resp.RedirectURI, "consent_required") {
			t.Errorf("expected consent_required redirect, got %s", resp.RedirectURI)
		}
	})

	var consumedID string
	t.Run("approve_with_consent_returns_code", func(t *testing.T) {
		consumedID = freshInteraction()
		rec := postComplete(t, map[string]any{
			"interaction_id":   consumedID,
			"pb_token":         pbToken,
			"pb_token_iat":     time.Now().Unix(),
			"decision":         "approve",
			"consented_scopes": []string{"openid", "profile"},
		})
		if rec.Code != http.StatusOK {
			t.Fatalf("status %d: %s", rec.Code, rec.Body.String())
		}
		var resp struct {
			RedirectURI string `json:"redirect_uri"`
		}
		_ = json.NewDecoder(rec.Body).Decode(&resp)
		final, _ := url.Parse(resp.RedirectURI)
		if final.Query().Get("code") == "" {
			t.Fatalf("expected code in redirect, got %s", resp.RedirectURI)
		}
		if final.Query().Get("iss") == "" {
			t.Errorf("RFC 9207 iss missing in success redirect")
		}
	})

	t.Run("replay_consumed_interaction_returns_404", func(t *testing.T) {
		if consumedID == "" {
			t.Skip("requires prior subtest to have produced a consumed id")
		}
		rec := postComplete(t, map[string]any{
			"interaction_id":   consumedID,
			"pb_token":         pbToken,
			"pb_token_iat":     time.Now().Unix(),
			"decision":         "approve",
			"consented_scopes": []string{"openid", "profile"},
		})
		if rec.Code != http.StatusNotFound {
			t.Errorf("expected 404 on replay, got %d", rec.Code)
		}
	})
}

func TestLoginUI_Served(t *testing.T) {
	scenario := tests.ApiScenario{
		Name:            "login UI - serves HTML",
		Method:          http.MethodGet,
		URL:             "/oauth2/login",
		ExpectedStatus:  200,
		ExpectedContent: []string{"<!doctype html>"},
		TestAppFactory: func(t testing.TB) *tests.TestApp {
			return setupTestAppForScenario(t)
		},
	}
	scenario.Test(t)
}
