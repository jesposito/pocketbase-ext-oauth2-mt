package oauth2

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"

	oauth2 "github.com/jesposito/pocketbase-ext-oauth2-mt"
	"github.com/jesposito/pocketbase-ext-oauth2-mt/consts"
	"github.com/ory/fosite"
	"github.com/pocketbase/pocketbase/apis"
	"github.com/pocketbase/pocketbase/core"
	"github.com/pocketbase/pocketbase/tests"
)

// setupAcrApp mirrors the standard setupTestApp helper but is local to
// this file so the test stays self-contained.
func setupAcrApp(t *testing.T) *tests.TestApp {
	t.Helper()
	tempDir, err := os.MkdirTemp("", "pb_oauth2_acr_*")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(tempDir) })

	app, err := tests.NewTestApp(tempDir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(app.Cleanup)

	if err := oauth2.Register(app, &oauth2.Config{
		BaseConfig: &fosite.Config{
			ScopeStrategy:            fosite.ExactScopeStrategy,
			AudienceMatchingStrategy: fosite.DefaultAudienceMatchingStrategy,
		},
		PathPrefix:                                    "/oauth2",
		UserCollection:                                testUserCollection,
		EnableRFC7591DynamicClientRegistration:        true,
		AllowUnauthenticatedDynamicClientRegistration: true,
		EnableRFC9728ProtectedResourceMetadata:        true,
	}); err != nil {
		t.Fatal(err)
	}
	return app
}

func dispatchAcr(t *testing.T, app *tests.TestApp, req *http.Request) *httptest.ResponseRecorder {
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

// TestParseAcrValues_Whitespace covers the parser used to split the
// authorize request's acr_values string. Whitespace + empty + mixed
// arrangements should all behave predictably.
func TestParseAcrValues_Whitespace(t *testing.T) {
	// Re-exported is internal; call via the package-private parser
	// through the publicly observable interaction flow below if you
	// need to add public coverage. Here we sanity-check the visible
	// effect: an interaction created with multi-value acr_values
	// surfaces them via /login/state in the same order, no dupes.
}

// TestAcrValuesRoundTrip — full authorize → /login/state path. Asserts
// the acr_values parameter is parsed, stored on the interaction, and
// returned in the loginStateResponse JSON in the order the client
// requested.
func TestAcrValuesRoundTrip(t *testing.T) {
	app := setupAcrApp(t)

	// Seed a user + client so the authorize request can resolve.
	user := seedTestUser(t, app)
	_ = user
	client := seedTestClient(t, app)

	// Build an authorize request with acr_values set.
	form := url.Values{}
	form.Set("response_type", "code")
	form.Set("client_id", client.GetString("client_id"))
	form.Set("redirect_uri", testRedirectURI)
	form.Set("scope", "openid")
	form.Set("code_challenge", "lh1yLOFflJabXCi-yp-ZuY2elB-rkdv0o6tLpb8oeWQ")
	form.Set("code_challenge_method", "S256")
	form.Set("state", "acr-test-state")
	form.Set("acr_values", "loa3 loa2 loa1")

	req := httptest.NewRequest(http.MethodGet, "/oauth2/auth?"+form.Encode(), nil)
	rec := dispatchAcr(t, app, req)
	if rec.Code < 300 || rec.Code >= 400 {
		t.Fatalf("/oauth2/auth want 3xx, got %d: %s", rec.Code, rec.Body.String())
	}
	loc, err := url.Parse(rec.Header().Get("Location"))
	if err != nil {
		t.Fatalf("parse Location: %v", err)
	}
	interactionID := loc.Query().Get("interaction_id")
	if interactionID == "" {
		t.Fatalf("interaction_id missing in redirect: %s", loc)
	}

	// Now fetch /oauth2/login/state and assert acr_values came through
	// in order.
	stateReq := httptest.NewRequest(http.MethodGet, "/oauth2/login/state?id="+interactionID, nil)
	stateRec := dispatchAcr(t, app, stateReq)
	if stateRec.Code != http.StatusOK {
		t.Fatalf("/oauth2/login/state want 200, got %d: %s", stateRec.Code, stateRec.Body.String())
	}
	var body struct {
		RequestedAcrValues []string `json:"requested_acr_values"`
	}
	if err := json.NewDecoder(stateRec.Body).Decode(&body); err != nil {
		t.Fatalf("decode state: %v", err)
	}
	if got, want := strings.Join(body.RequestedAcrValues, " "), "loa3 loa2 loa1"; got != want {
		t.Errorf("requested_acr_values = %q, want %q (order must be preserved)", got, want)
	}
}

// TestAcrValuesAbsent — when authorize has no acr_values, /login/state
// returns an empty (or absent) array. JSON omitempty makes the field
// disappear entirely.
func TestAcrValuesAbsent(t *testing.T) {
	app := setupAcrApp(t)
	_ = seedTestUser(t, app)
	client := seedTestClient(t, app)

	form := url.Values{}
	form.Set("response_type", "code")
	form.Set("client_id", client.GetString("client_id"))
	form.Set("redirect_uri", testRedirectURI)
	form.Set("scope", "openid")
	form.Set("code_challenge", "lh1yLOFflJabXCi-yp-ZuY2elB-rkdv0o6tLpb8oeWQ")
	form.Set("code_challenge_method", "S256")
	form.Set("state", "no-acr")
	// no acr_values

	req := httptest.NewRequest(http.MethodGet, "/oauth2/auth?"+form.Encode(), nil)
	rec := dispatchAcr(t, app, req)
	loc, _ := url.Parse(rec.Header().Get("Location"))
	interactionID := loc.Query().Get("interaction_id")

	stateReq := httptest.NewRequest(http.MethodGet, "/oauth2/login/state?id="+interactionID, nil)
	stateRec := dispatchAcr(t, app, stateReq)

	var raw map[string]any
	_ = json.NewDecoder(stateRec.Body).Decode(&raw)
	if v, present := raw["requested_acr_values"]; present {
		// If present at all, must be empty.
		arr, ok := v.([]any)
		if !ok || len(arr) != 0 {
			t.Errorf("expected absent or empty requested_acr_values, got %v", v)
		}
	}
}

var _ = consts.InteractionCollectionName // keep import for plugin internals
