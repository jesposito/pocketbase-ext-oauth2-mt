package oauth2

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v3"
	"github.com/ory/fosite"
	"github.com/pocketbase/pocketbase/core"
	pbtests "github.com/pocketbase/pocketbase/tests"
)

func runtimeSnapshot() RuntimeAttestationSnapshot {
	return RuntimeAttestationSnapshot{
		Tenant: "tenant", ReleaseSHA: strings.Repeat("a", 40),
		SourceSHA: strings.Repeat("b", 40), SourceID: "source-1",
		BootID: "boot-1", AuthConfigSHA256: strings.Repeat("c", 64),
	}
}

func newRuntimeAttestationApp(t *testing.T, dual bool) *pbtests.TestApp {
	t.Helper()
	dir, err := os.MkdirTemp("", "oauth2-runtime-attestation-*")
	if err != nil {
		t.Fatal(err)
	}
	app, err := pbtests.NewTestApp(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { Deregister(app); app.Cleanup(); _ = os.RemoveAll(dir) })
	app.Settings().Meta.AppURL = "https://tenant.example"
	register := func(prefix, collection string) {
		err := Register(app, &Config{
			BaseConfig: &fosite.Config{ClientSecretsHasher: &countingHasher{}}, PathPrefix: prefix, UserCollection: collection,
			RuntimeAttestationSnapshot: func(_ context.Context) (RuntimeAttestationSnapshot, error) { return runtimeSnapshot(), nil },
		})
		if err != nil {
			t.Fatalf("register %s: %v", prefix, err)
		}
	}
	register("/oauth2", "members")
	if dual {
		register("/oauth2/admin", "users")
	}
	return app
}

func requestRuntimeAttestation(t *testing.T, app *pbtests.TestApp, path string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, path, nil)
	req.RemoteAddr = "192.0.2.10:1234"
	return dispatchPrefixRequest(t, app, req)
}

func decodeRuntimeToken(t *testing.T, app *pbtests.TestApp, prefix, compact string) (jose.Header, runtimeAttestationClaims) {
	t.Helper()
	parsed, err := jose.ParseSigned(compact)
	if err != nil {
		t.Fatalf("parse token: %v", err)
	}
	if len(parsed.Signatures) != 1 {
		t.Fatalf("signatures=%d want 1", len(parsed.Signatures))
	}
	inst, _ := getInstanceAt(app, prefix)
	payload, err := parsed.Verify(inst.privateKey.Public().Key)
	if err != nil {
		t.Fatalf("verify token: %v", err)
	}
	var claims runtimeAttestationClaims
	if err := json.Unmarshal(payload, &claims); err != nil {
		t.Fatal(err)
	}
	return parsed.Signatures[0].Header, claims
}

func TestRuntimeAttestationEndpointOwnsConstrainedToken(t *testing.T) {
	app := newRuntimeAttestationApp(t, true)
	nonce := base64.RawURLEncoding.EncodeToString([]byte(strings.Repeat("n", 32)))
	for _, tc := range []struct{ prefix, issuer, collection string }{
		{"/oauth2", "https://tenant.example", "members"},
		{"/oauth2/admin", "https://tenant.example/oauth2/admin", "users"},
	} {
		rec := requestRuntimeAttestation(t, app, tc.prefix+"/runtime-attestation?nonce="+nonce)
		if rec.Code != http.StatusOK {
			t.Fatalf("%s status=%d body=%s", tc.prefix, rec.Code, rec.Body.String())
		}
		if rec.Header().Get("Cache-Control") != "no-store" || rec.Header().Get("Pragma") != "no-cache" {
			t.Fatalf("missing no-store headers: %v", rec.Header())
		}
		var body runtimeAttestationResponse
		if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
			t.Fatal(err)
		}
		parts := strings.Split(body.Attestation, ".")
		if len(parts) != 3 {
			t.Fatalf("compact JWS parts=%d", len(parts))
		}
		rawHeader, err := base64.RawURLEncoding.DecodeString(parts[0])
		if err != nil {
			t.Fatal(err)
		}
		var headerFields map[string]any
		if err := json.Unmarshal(rawHeader, &headerFields); err != nil {
			t.Fatal(err)
		}
		if len(headerFields) != 3 || headerFields["alg"] != "RS256" || headerFields["typ"] != runtimeAttestationType || headerFields["kid"] == "" {
			t.Fatalf("non-exact protected header: %v", headerFields)
		}
		header, claims := decodeRuntimeToken(t, app, tc.prefix, body.Attestation)
		if header.Algorithm != string(jose.RS256) || header.ExtraHeaders[jose.HeaderKey("typ")] != runtimeAttestationType || header.KeyID == "" {
			t.Fatalf("unsafe JOSE header: %+v", header)
		}
		now := time.Now().Unix()
		if claims.AttestationVersion != 1 || claims.Audience != runtimeAttestationAudience || claims.Nonce != nonce || claims.Origin != "https://tenant.example" || claims.Issuer != tc.issuer || claims.Prefix != tc.prefix || claims.UserCollection != tc.collection {
			t.Fatalf("wrong constrained claims: %+v", claims)
		}
		if claims.ExpiresAt-claims.IssuedAt != 60 || claims.IssuedAt < now-2 || claims.ExpiresAt > now+62 {
			t.Fatalf("unsafe lifetime: iat=%d exp=%d now=%d", claims.IssuedAt, claims.ExpiresAt, now)
		}
		snapshot := runtimeSnapshot()
		if claims.Tenant != snapshot.Tenant || claims.ReleaseSHA != snapshot.ReleaseSHA || claims.SourceSHA != snapshot.SourceSHA || claims.SourceID != snapshot.SourceID || claims.BootID != snapshot.BootID || claims.AuthConfigSHA256 != snapshot.AuthConfigSHA256 {
			t.Fatalf("snapshot drift: %+v", claims)
		}
	}
}

func TestRuntimeAttestationLimiterDoesNotCollapseSharedProxyCallers(t *testing.T) {
	app := newRuntimeAttestationApp(t, false)
	nonce := base64.RawURLEncoding.EncodeToString([]byte(strings.Repeat("n", 32)))
	for i := 0; i < 7; i++ {
		req := httptest.NewRequest(http.MethodGet, "/oauth2/runtime-attestation?nonce="+nonce, nil)
		req.RemoteAddr = "192.0.2.10:1234"
		req.Header.Set("X-Forwarded-For", fmt.Sprintf("198.51.100.%d", i+1))
		if rec := dispatchPrefixRequest(t, app, req); rec.Code != http.StatusOK {
			t.Fatalf("shared proxy request %d status=%d body=%s", i, rec.Code, rec.Body.String())
		}
	}
}

func TestRuntimeAttestationLimiterIsBoundedResettableAndInstanceIsolated(t *testing.T) {
	app := newRuntimeAttestationApp(t, true)
	members, ok := getInstanceAt(app, "/oauth2")
	if !ok {
		t.Fatal("members provider instance is missing")
	}
	admin, ok := getInstanceAt(app, "/oauth2/admin")
	if !ok {
		t.Fatal("admin provider instance is missing")
	}
	otherApp := newRuntimeAttestationApp(t, false)
	otherTenant, ok := getInstanceAt(otherApp, "/oauth2")
	if !ok {
		t.Fatal("second tenant provider instance is missing")
	}
	now := time.Unix(1_787_788_800, 0)
	for i := 0; i < runtimeAttestationInstanceLimit; i++ {
		if !members.attestationLimiter.allow(now) {
			t.Fatalf("instance request %d rejected before cap", i)
		}
	}
	if members.attestationLimiter.allow(now) {
		t.Fatal("instance signer cap accepted request 121")
	}
	if !admin.attestationLimiter.allow(now) {
		t.Fatal("one provider prefix exhausted another instance's budget")
	}
	if !otherTenant.attestationLimiter.allow(now) {
		t.Fatal("one core.App tenant exhausted another instance's budget")
	}
	if !members.attestationLimiter.allow(now.Add(runtimeAttestationWindow)) {
		t.Fatal("instance signer cap did not reset after its fixed window")
	}
}

func TestRuntimeAttestationLimiterIgnoresForwardedHeaderIdentity(t *testing.T) {
	app := newRuntimeAttestationApp(t, false)
	inst, ok := getInstanceAt(app, "/oauth2")
	if !ok {
		t.Fatal("provider instance is missing")
	}
	inst.attestationLimiter.mu.Lock()
	inst.attestationLimiter.state = runtimeAttestationWindowState{
		started: time.Now().UTC(),
		count:   runtimeAttestationInstanceLimit - 1,
	}
	inst.attestationLimiter.mu.Unlock()
	nonce := base64.RawURLEncoding.EncodeToString([]byte(strings.Repeat("n", 32)))
	request := func(forwarded string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodGet, "/oauth2/runtime-attestation?nonce="+nonce, nil)
		req.RemoteAddr = "192.0.2.10:1234"
		req.Header.Set("X-Forwarded-For", forwarded)
		req.Header.Set("CF-Connecting-IP", forwarded)
		return dispatchPrefixRequest(t, app, req)
	}
	if rec := request("198.51.100.10"); rec.Code != http.StatusOK {
		t.Fatalf("last in-budget status=%d body=%s", rec.Code, rec.Body.String())
	}
	if rec := request("203.0.113.250"); rec.Code != http.StatusTooManyRequests {
		t.Fatalf("forwarded-header evasion status=%d want 429", rec.Code)
	}
}

func TestRuntimeAttestationCannotBeUsedAsOAuthBearerToken(t *testing.T) {
	app := newRuntimeAttestationApp(t, false)
	savePrefixClient(t, app, DefaultPathPrefix, "attestation-isolation", "isolation-secret")
	app.OnServe().BindFunc(func(se *core.ServeEvent) error {
		se.Router.GET("/api/attestation-isolation", func(e *core.RequestEvent) error {
			return e.JSON(http.StatusOK, map[string]bool{"ok": true})
		}).Bind(RequireScopeAt(app, DefaultPathPrefix, "openid"))
		return se.Next()
	})

	nonce := base64.RawURLEncoding.EncodeToString([]byte(strings.Repeat("n", 32)))
	rec := requestRuntimeAttestation(t, app, "/oauth2/runtime-attestation?nonce="+nonce)
	if rec.Code != http.StatusOK {
		t.Fatalf("attestation status=%d body=%s", rec.Code, rec.Body.String())
	}
	var body runtimeAttestationResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}

	form := url.Values{"token": {body.Attestation}}
	req := httptest.NewRequest(http.MethodPost, "/oauth2/introspect", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth("attestation-isolation", "isolation-secret")
	got := dispatchPrefixRequest(t, app, req)
	var introspection map[string]any
	if got.Code != http.StatusOK || json.Unmarshal(got.Body.Bytes(), &introspection) != nil || introspection["active"] == true {
		t.Fatalf("introspection accepted attestation: status=%d body=%s", got.Code, got.Body.String())
	}

	for _, path := range []string{"/oauth2/userinfo", "/api/attestation-isolation"} {
		req = httptest.NewRequest(http.MethodGet, path, nil)
		req.Header.Set("Authorization", "Bearer "+body.Attestation)
		if response := dispatchPrefixRequest(t, app, req); response.Code != http.StatusUnauthorized {
			t.Fatalf("%s accepted attestation: status=%d body=%s", path, response.Code, response.Body.String())
		}
	}
}

func TestRuntimeAttestationEndpointRejectsNonceAndRateLimits(t *testing.T) {
	app := newRuntimeAttestationApp(t, false)
	for _, path := range []string{
		"/oauth2/runtime-attestation", "/oauth2/runtime-attestation?nonce=short",
		"/oauth2/runtime-attestation?nonce=a&nonce=b",
	} {
		if rec := requestRuntimeAttestation(t, app, path); rec.Code != http.StatusBadRequest {
			t.Fatalf("%s status=%d want 400", path, rec.Code)
		}
	}
	// Invalid requests consume the same strict budget so malformed input cannot
	// bypass signing-endpoint abuse controls.
	nonce := base64.RawURLEncoding.EncodeToString([]byte(strings.Repeat("n", 32)))
	inst, ok := getInstanceAt(app, "/oauth2")
	if !ok {
		t.Fatal("provider instance is missing")
	}
	inst.attestationLimiter.mu.Lock()
	if inst.attestationLimiter.state.count != 3 {
		t.Fatalf("invalid requests consumed %d slots, want 3", inst.attestationLimiter.state.count)
	}
	inst.attestationLimiter.state.count = runtimeAttestationInstanceLimit - 1
	inst.attestationLimiter.mu.Unlock()
	if rec := requestRuntimeAttestation(t, app, "/oauth2/runtime-attestation?nonce="+nonce); rec.Code != http.StatusOK {
		t.Fatalf("last in-budget status=%d", rec.Code)
	}
	if rec := requestRuntimeAttestation(t, app, "/oauth2/runtime-attestation?nonce="+nonce); rec.Code != http.StatusTooManyRequests {
		t.Fatalf("over-limit status=%d want 429", rec.Code)
	}
}

func TestRuntimeAttestationRouteIsAbsentWithoutTypedCallback(t *testing.T) {
	dir, err := os.MkdirTemp("", "oauth2-runtime-attestation-off-*")
	if err != nil {
		t.Fatal(err)
	}
	app, err := pbtests.NewTestApp(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { Deregister(app); app.Cleanup(); _ = os.RemoveAll(dir) })
	if err := Register(app, &Config{BaseConfig: &fosite.Config{}, PathPrefix: "/oauth2", UserCollection: "users"}); err != nil {
		t.Fatal(err)
	}
	nonce := base64.RawURLEncoding.EncodeToString([]byte(strings.Repeat("n", 32)))
	if rec := requestRuntimeAttestation(t, app, "/oauth2/runtime-attestation?nonce="+nonce); rec.Code != http.StatusNotFound {
		t.Fatalf("status=%d want 404", rec.Code)
	}
}
