package oauth2

import (
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
	"time"

	oauth2 "github.com/jesposito/pocketbase-ext-oauth2-mt"
	"github.com/jesposito/pocketbase-ext-oauth2-mt/consts"
	"github.com/pocketbase/pocketbase/core"
)

// seedAccessTokenRow inserts an access-token session row keyed by the
// signature derived from the supplied PB auth token (last "." segment).
// granted is the pipe-joined granted_scopes string ("openid|widgets:read").
func seedAccessTokenRow(t testing.TB, app core.App, token, granted string) {
	t.Helper()
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		t.Fatalf("expected JWT-style token with 3 segments, got %d", len(parts))
	}
	signature := parts[2]

	c, err := app.FindCollectionByNameOrId(consts.AccessCollectionName)
	if err != nil {
		t.Fatalf("find access collection: %v", err)
	}
	rec := core.NewRecord(c)
	rec.Set("signature", signature)
	rec.Set("client_id", testClientID)
	rec.Set("request_id", "test-req-"+signature[:8])
	rec.Set("requested_at", time.Now().Unix())
	rec.Set("expires_at", time.Now().Add(time.Hour).Unix())
	rec.Set("scopes", granted)
	rec.Set("granted_scopes", granted)
	rec.Set("requested_audience", "")
	rec.Set("granted_audience", "")
	rec.Set("form_data", "")
	// Minimal valid JSON so ToRequest's json.Unmarshal succeeds.
	rec.Set("session_data", "{}")
	rec.Set("subject", "")

	if err := app.SaveNoValidate(rec); err != nil {
		t.Fatalf("save access token row: %v", err)
	}
}

// mintBearerForUser mints a PB static auth token for the test user.
func mintBearerForUser(t testing.TB, app core.App) string {
	t.Helper()
	record, err := app.FindAuthRecordByEmail(testUserCollection, testUserEmail)
	if err != nil {
		t.Fatalf("find test user: %v", err)
	}
	token, err := record.NewStaticAuthToken(time.Hour)
	if err != nil {
		t.Fatalf("mint static auth token: %v", err)
	}
	return token
}

// invokeMiddleware runs the middleware handler against a fresh
// httptest.ResponseRecorder + Request and returns the recorder for the
// caller to inspect. downstream, when non-nil, is invoked as the route
// handler in place of Next(); the middleware's Next() call walks back up
// and triggers it.
func invokeMiddleware(t testing.TB, app core.App, scopes []string, bearer string, downstream func(e *core.RequestEvent) error) *httptest.ResponseRecorder {
	t.Helper()
	mw := oauth2.RequireScope(app, scopes...)

	req := httptest.NewRequest(http.MethodGet, "/test/protected", nil)
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	rec := httptest.NewRecorder()

	// Build a RequestEvent and run the middleware. The RequestEvent's
	// Next chain isn't trivially available outside the router, so we
	// invoke the middleware Func directly. The middleware calls e.Next()
	// on success, which without a registered chain returns nil; we
	// separately invoke the downstream after the fact if the middleware
	// returned nil AND did not write a status (pass-through case).
	e := &core.RequestEvent{App: app}
	e.Request = req
	e.Response = rec

	if err := mw.Func(e); err != nil {
		t.Fatalf("middleware returned err: %v", err)
	}
	// If middleware passed through (no status written), simulate the
	// downstream handler so callers can verify context propagation.
	if rec.Code == 200 && rec.Body.Len() == 0 && downstream != nil {
		if err := downstream(e); err != nil {
			t.Fatalf("downstream returned err: %v", err)
		}
	}
	return rec
}

func TestRequireScope_NoBearer_Returns401(t *testing.T) {
	app := setupTestApp(t)
	defer app.Cleanup()

	rec := invokeMiddleware(t, app, []string{"widgets:read"}, "", nil)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", rec.Code)
	}
	wa := rec.Header().Get("WWW-Authenticate")
	if !strings.Contains(wa, `error="invalid_token"`) {
		t.Fatalf(`expected WWW-Authenticate to contain error="invalid_token", got %q`, wa)
	}
}

func TestRequireScope_InsufficientScope_Returns403(t *testing.T) {
	app := setupTestApp(t)
	defer app.Cleanup()
	seedTestUser(t, app)
	seedTestClient(t, app)

	bearer := mintBearerForUser(t, app)
	seedAccessTokenRow(t, app, bearer, "openid")

	rec := invokeMiddleware(t, app, []string{"widgets:read"}, bearer, nil)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d (body=%s)", rec.Code, rec.Body.String())
	}
	wa := rec.Header().Get("WWW-Authenticate")
	if !strings.Contains(wa, `error="insufficient_scope"`) {
		t.Fatalf(`expected WWW-Authenticate to contain error="insufficient_scope", got %q`, wa)
	}
	if !strings.Contains(wa, `scope="widgets:read"`) {
		t.Fatalf(`expected WWW-Authenticate to contain scope="widgets:read", got %q`, wa)
	}
}

func TestRequireScope_QueryStringToken_Rejected(t *testing.T) {
	// Header-only by design: a token presented via ?access_token=... must NOT
	// be accepted, even when a valid access-token row exists. This guards
	// against URL-query token leakage (RFC 6750 §5.3).
	app := setupTestApp(t)
	defer app.Cleanup()
	seedTestUser(t, app)
	seedTestClient(t, app)

	bearer := mintBearerForUser(t, app)
	seedAccessTokenRow(t, app, bearer, "widgets:read")

	mw := oauth2.RequireScope(app, "widgets:read")
	req := httptest.NewRequest(http.MethodGet, "/test/protected?access_token="+bearer, nil)
	rec := httptest.NewRecorder()
	e := &core.RequestEvent{App: app}
	e.Request = req
	e.Response = rec

	if err := mw.Func(e); err != nil {
		t.Fatalf("middleware returned err: %v", err)
	}
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 for query-string token, got %d", rec.Code)
	}
}

func TestRequireScope_FormBodyToken_Rejected(t *testing.T) {
	app := setupTestApp(t)
	defer app.Cleanup()
	seedTestUser(t, app)
	seedTestClient(t, app)

	bearer := mintBearerForUser(t, app)
	seedAccessTokenRow(t, app, bearer, "widgets:read")

	mw := oauth2.RequireScope(app, "widgets:read")
	body := "access_token=" + bearer
	req := httptest.NewRequest(http.MethodPost, "/test/protected", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	e := &core.RequestEvent{App: app}
	e.Request = req
	e.Response = rec

	if err := mw.Func(e); err != nil {
		t.Fatalf("middleware returned err: %v", err)
	}
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 for form-body token, got %d", rec.Code)
	}
}

func TestRequireScope_AllScopesGranted_PassesThrough(t *testing.T) {
	app := setupTestApp(t)
	defer app.Cleanup()
	seedTestUser(t, app)
	seedTestClient(t, app)

	bearer := mintBearerForUser(t, app)
	seedAccessTokenRow(t, app, bearer, "widgets:read|widgets:write")

	var sawScopes []string
	rec := invokeMiddleware(t, app, []string{"widgets:read"}, bearer,
		func(e *core.RequestEvent) error {
			v := e.Get(oauth2.ScopeContextKey)
			if v == nil {
				t.Fatalf("downstream expected %s in context, got nil", oauth2.ScopeContextKey)
			}
			scopes, ok := v.([]string)
			if !ok {
				t.Fatalf("expected []string in context, got %T", v)
			}
			sawScopes = scopes
			return nil
		})

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 (no status write on pass-through), got %d (body=%s, hdr=%v)",
			rec.Code, rec.Body.String(), rec.Header())
	}
	if len(sawScopes) == 0 {
		t.Fatalf("downstream handler did not see granted scopes in context")
	}
	// Sanity check: required scope must be present in the granted set.
	if !slices.Contains(sawScopes, "widgets:read") {
		t.Fatalf("expected widgets:read in granted scopes, got %v", sawScopes)
	}
}
