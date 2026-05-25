package oauth2

import (
	"net/http"
	"os"
	"strings"
	"testing"

	oauth2 "github.com/jesposito/pocketbase-ext-oauth2-mt"
	"github.com/ory/fosite"
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
