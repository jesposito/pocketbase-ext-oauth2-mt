package oauth2

import (
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	oauth2 "github.com/jesposito/pocketbase-ext-oauth2-mt"
	"github.com/ory/fosite"
	"github.com/pocketbase/pocketbase/apis"
	"github.com/pocketbase/pocketbase/core"
	"github.com/pocketbase/pocketbase/tests"
)

// setupTestAppWithLoginRedirect mirrors setupTestApp but pipes a custom
// LoginRedirectURL through Config so the GET/POST /oauth2/login handler
// 302's to it instead of serving the bundled UI.
func setupTestAppWithLoginRedirect(t *testing.T, redirectURL string) *tests.TestApp {
	t.Helper()
	tempDir, err := os.MkdirTemp("", "pb_oauth2_login_redirect_*")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(tempDir) })

	testApp, err := tests.NewTestApp(tempDir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(testApp.Cleanup)

	err = oauth2.Register(testApp, &oauth2.Config{
		BaseConfig: &fosite.Config{
			ScopeStrategy:            fosite.ExactScopeStrategy,
			AudienceMatchingStrategy: fosite.DefaultAudienceMatchingStrategy,
		},
		PathPrefix:                                    "/oauth2",
		UserCollection:                                testUserCollection,
		EnableRFC7591DynamicClientRegistration:        true,
		AllowUnauthenticatedDynamicClientRegistration: true,
		EnableRFC9728ProtectedResourceMetadata:        true,
		LoginRedirectURL:                              redirectURL,
	})
	if err != nil {
		t.Fatal(err)
	}
	return testApp
}

func dispatchOnce(t *testing.T, app *tests.TestApp, req *http.Request) *httptest.ResponseRecorder {
	t.Helper()
	router, err := apis.NewRouter(app)
	if err != nil {
		t.Fatalf("apis.NewRouter: %v", err)
	}
	rec := httptest.NewRecorder()
	se := &core.ServeEvent{App: app, Router: router}
	if err := app.OnServe().Trigger(se, func(e *core.ServeEvent) error {
		mux, err := e.Router.BuildMux()
		if err != nil {
			return err
		}
		mux.ServeHTTP(rec, req)
		return nil
	}); err != nil {
		t.Fatalf("dispatch: %v", err)
	}
	return rec
}

// TestLoginRedirectURL_Empty_ServesBundledUI — sanity: when the field is
// empty (zero value, default), the plugin serves its own login.html as
// before.
func TestLoginRedirectURL_Empty_ServesBundledUI(t *testing.T) {
	app := setupTestAppWithLoginRedirect(t, "")
	req := httptest.NewRequest(http.MethodGet, "/oauth2/login?interaction_id=abc123", nil)
	rec := dispatchOnce(t, app, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("/oauth2/login = %d, want 200 (bundled UI): %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "<!DOCTYPE") &&
		!strings.Contains(rec.Body.String(), "<!doctype") {
		t.Errorf("expected HTML doctype in response body, got %.200s", rec.Body.String())
	}
}

// TestLoginRedirectURL_SetRelative_Redirects302WithQuery — happy path:
// LoginRedirectURL points at a relative path (the integration case for
// tenants sharing the same origin), incoming query string is preserved.
func TestLoginRedirectURL_SetRelative_Redirects302WithQuery(t *testing.T) {
	app := setupTestAppWithLoginRedirect(t, "/members/login")
	req := httptest.NewRequest(http.MethodGet, "/oauth2/login?interaction_id=abc123&prompt=consent", nil)
	rec := dispatchOnce(t, app, req)
	if rec.Code != http.StatusFound {
		t.Fatalf("/oauth2/login = %d, want 302: %s", rec.Code, rec.Body.String())
	}
	loc := rec.Header().Get("Location")
	if !strings.HasPrefix(loc, "/members/login?") {
		t.Errorf("Location = %q, want prefix /members/login?", loc)
	}
	if !strings.Contains(loc, "interaction_id=abc123") {
		t.Errorf("Location = %q, missing interaction_id", loc)
	}
	if !strings.Contains(loc, "prompt=consent") {
		t.Errorf("Location = %q, missing prompt query param", loc)
	}
}

// TestLoginRedirectURL_DestinationHasExistingQuery_Appended — when the
// configured URL already has a query string ("/members/login?theme=dark"),
// the plugin appends with & not ? so both query strings survive.
func TestLoginRedirectURL_DestinationHasExistingQuery_Appended(t *testing.T) {
	app := setupTestAppWithLoginRedirect(t, "/members/login?theme=dark")
	req := httptest.NewRequest(http.MethodGet, "/oauth2/login?interaction_id=xyz", nil)
	rec := dispatchOnce(t, app, req)
	if rec.Code != http.StatusFound {
		t.Fatalf("/oauth2/login = %d, want 302", rec.Code)
	}
	loc := rec.Header().Get("Location")
	if !strings.HasPrefix(loc, "/members/login?theme=dark&") {
		t.Errorf("Location = %q, want prefix /members/login?theme=dark&", loc)
	}
	if !strings.Contains(loc, "interaction_id=xyz") {
		t.Errorf("Location = %q, missing interaction_id", loc)
	}
}

// TestLoginRedirectURL_POSTAlsoRedirects — both GET and POST /oauth2/login
// hit the same uiHandler so POST should also redirect (some browsers
// follow form submissions to the same path).
func TestLoginRedirectURL_POSTAlsoRedirects(t *testing.T) {
	app := setupTestAppWithLoginRedirect(t, "/admin/login")
	req := httptest.NewRequest(http.MethodPost, "/oauth2/login?interaction_id=zzz", nil)
	rec := dispatchOnce(t, app, req)
	if rec.Code != http.StatusFound {
		t.Fatalf("POST /oauth2/login = %d, want 302", rec.Code)
	}
	if !strings.Contains(rec.Header().Get("Location"), "interaction_id=zzz") {
		t.Errorf("Location missing interaction_id: %s", rec.Header().Get("Location"))
	}
}

// TestLoginRedirectURL_NoQueryString — when the original request has no
// query string, the redirect is to the bare URL with no trailing ?.
func TestLoginRedirectURL_NoQueryString(t *testing.T) {
	app := setupTestAppWithLoginRedirect(t, "/members/login")
	req := httptest.NewRequest(http.MethodGet, "/oauth2/login", nil)
	rec := dispatchOnce(t, app, req)
	if rec.Code != http.StatusFound {
		t.Fatalf("/oauth2/login = %d, want 302", rec.Code)
	}
	if loc := rec.Header().Get("Location"); loc != "/members/login" {
		t.Errorf("Location = %q, want exactly /members/login (no trailing ?)", loc)
	}
}
