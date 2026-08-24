package oauth2

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jesposito/pocketbase-ext-oauth2-mt/consts"
	"github.com/ory/fosite"
	"github.com/pocketbase/pocketbase/apis"
	"github.com/pocketbase/pocketbase/core"
	pbtests "github.com/pocketbase/pocketbase/tests"
)

type countingHasher struct{ calls atomic.Int32 }

func (h *countingHasher) Hash(_ context.Context, data []byte) ([]byte, error) {
	h.calls.Add(1)
	return []byte("hashed:" + string(data)), nil
}

func (h *countingHasher) Compare(_ context.Context, hash, data []byte) error {
	if string(hash) != "hashed:"+string(data) {
		return errors.New("secret mismatch")
	}
	return nil
}

func newDualProviderTestApp(t *testing.T) (*pbtests.TestApp, *countingHasher) {
	t.Helper()
	dir, err := os.MkdirTemp("", "oauth2-prefix-security-*")
	if err != nil {
		t.Fatal(err)
	}
	app, err := pbtests.NewTestApp(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { Deregister(app); app.Cleanup(); _ = os.RemoveAll(dir) })
	hasher := &countingHasher{}
	for _, tc := range []struct{ prefix, collection string }{
		{DefaultPathPrefix, "users"}, {"/oauth2/admin", "members"},
	} {
		err := Register(app, &Config{BaseConfig: &fosite.Config{
			ClientSecretsHasher: hasher, AccessTokenLifespan: time.Hour,
			AuthorizeCodeLifespan: time.Minute, ScopeStrategy: fosite.ExactScopeStrategy,
			AudienceMatchingStrategy: fosite.DefaultAudienceMatchingStrategy,
		}, PathPrefix: tc.prefix, UserCollection: tc.collection})
		if err != nil {
			t.Fatalf("register %s: %v", tc.prefix, err)
		}
	}
	return app, hasher
}

func savePrefixClient(t *testing.T, app core.App, prefix, id, secret string) {
	t.Helper()
	c, err := app.FindCollectionByNameOrId(consts.ClientCollectionName)
	if err != nil {
		t.Fatal(err)
	}
	r := core.NewRecord(c)
	r.Set("provider_prefix", normalizePrefix(prefix))
	r.Set("client_id", id)
	r.Set("client_name", id)
	r.Set("client_secret", secret)
	r.Set("client_secret_expires_at", 0)
	r.Set("redirect_uris", []string{"https://client.example/cb"})
	r.Set("grant_types", []string{"authorization_code", "refresh_token"})
	r.Set("response_types", []string{"code"})
	r.Set("scope", "openid")
	r.Set("audience", []string{"http://127.0.0.1"})
	r.Set("token_endpoint_auth_method", "client_secret_post")
	r.Set("subject_type", "public")
	r.Set("access_token_strategy", "opaque")
	for _, f := range []string{"contacts", "allowed_cors_origins", "request_uris"} {
		r.Set(f, []string{})
	}
	if err := app.SaveNoValidate(r); err != nil {
		t.Fatalf("save client %s: %v", prefix, err)
	}
}

func dispatchPrefixRequest(t *testing.T, app *pbtests.TestApp, req *http.Request) *httptest.ResponseRecorder {
	t.Helper()
	r, err := apis.NewRouter(app)
	if err != nil {
		t.Fatal(err)
	}
	rec := httptest.NewRecorder()
	event := &core.ServeEvent{App: app, Router: r}
	if err := app.OnServe().Trigger(event, func(e *core.ServeEvent) error {
		mux, err := e.Router.BuildMux()
		if err != nil {
			return err
		}
		mux.ServeHTTP(rec, req)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	return rec
}

func seedAuthorityToken(t *testing.T, app core.App, prefix, clientID string) string {
	t.Helper()
	c, err := app.FindCollectionByNameOrId("users")
	if err != nil {
		c = core.NewAuthCollection("users")
		if err := app.Save(c); err != nil {
			t.Fatal(err)
		}
	}
	u := core.NewRecord(c)
	u.SetEmail("prefix@example.com")
	u.SetPassword("Prefix-test-123!")
	u.SetVerified(true)
	if err := app.Save(u); err != nil {
		t.Fatal(err)
	}
	token, err := u.NewStaticAuthToken(time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	parts := strings.Split(token, ".")
	session, _ := json.Marshal(NewSession(app, u.Id, c.Id))
	access, err := app.FindCollectionByNameOrId(consts.AccessCollectionName)
	if err != nil {
		t.Fatal(err)
	}
	r := core.NewRecord(access)
	r.Set("provider_prefix", normalizePrefix(prefix))
	r.Set("signature", parts[2])
	r.Set("client_id", clientID)
	r.Set("request_id", "authority-request")
	r.Set("requested_at", time.Now().Unix())
	r.Set("expires_at", time.Now().Add(time.Hour).Unix())
	r.Set("scopes", "openid")
	r.Set("granted_scopes", "openid")
	r.Set("form_data", "")
	r.Set("session_data", string(session))
	r.Set("subject", u.Id)
	if err := app.SaveNoValidate(r); err != nil {
		t.Fatal(err)
	}
	return token
}

func TestProviderPrefixIsolation_CryptoStorageAndSharedHashHook(t *testing.T) {
	app, hasher := newDualProviderTestApp(t)
	savePrefixClient(t, app, DefaultPathPrefix, "shared", "members-secret")
	savePrefixClient(t, app, "/oauth2/admin", "shared", "admin-secret")
	if got := hasher.calls.Load(); got != 2 {
		t.Fatalf("client secret hash calls = %d, want exactly 2", got)
	}
	memberClient, err := GetOAuth2StoreAt(app, DefaultPathPrefix).GetClient(context.Background(), "shared")
	if err != nil {
		t.Fatal(err)
	}
	adminClient, err := GetOAuth2StoreAt(app, "/oauth2/admin").GetClient(context.Background(), "shared")
	if err != nil {
		t.Fatal(err)
	}
	if string(memberClient.GetHashedSecret()) == string(adminClient.GetHashedSecret()) {
		t.Fatal("same client id resolved to one cross-prefix secret")
	}
	memberInst := mustGetInstanceAt(app, DefaultPathPrefix)
	adminInst := mustGetInstanceAt(app, "/oauth2/admin")
	if string(memberInst.cfg.GlobalSecret) == string(adminInst.cfg.GlobalSecret) {
		t.Fatal("provider HMAC secrets are not prefix-specific")
	}
	if memberInst.privateKey.KeyID == adminInst.privateKey.KeyID {
		t.Fatal("provider signing keys are not prefix-specific")
	}
	ctx := context.Background()
	adminStore := GetOAuth2StoreAt(app, "/oauth2/admin")
	memberStore := GetOAuth2StoreAt(app, DefaultPathPrefix)
	session := NewSession(app, "admin-subject", "members")
	for _, tokenType := range []fosite.TokenType{fosite.AuthorizeCode, fosite.AccessToken, fosite.RefreshToken, fosite.IDToken} {
		session.SetExpiresAt(tokenType, time.Now().Add(time.Hour))
	}
	req := &fosite.Request{ID: "admin-request", Client: adminClient, RequestedAt: time.Now(), Session: session}
	if err := adminStore.CreateAuthorizeCodeSession(ctx, "admin-code-sig", req); err != nil {
		t.Fatal(err)
	}
	if _, err := memberStore.GetAuthorizeCodeSession(ctx, "admin-code-sig", &Session{}); !errors.Is(err, fosite.ErrNotFound) {
		t.Fatalf("cross-prefix auth code lookup=%v", err)
	}
	if err := adminStore.CreateAccessTokenSession(ctx, "admin-access-sig", req); err != nil {
		t.Fatal(err)
	}
	if _, err := memberStore.GetAccessTokenSession(ctx, "admin-access-sig", &Session{}); !errors.Is(err, fosite.ErrNotFound) {
		t.Fatalf("cross-prefix access lookup=%v", err)
	}
	if err := adminStore.CreateRefreshTokenSession(ctx, "admin-refresh-sig", "admin-access-sig", req); err != nil {
		t.Fatal(err)
	}
	if _, err := memberStore.GetRefreshTokenSession(ctx, "admin-refresh-sig", &Session{}); !errors.Is(err, fosite.ErrNotFound) {
		t.Fatalf("cross-prefix refresh lookup=%v", err)
	}
	// A request id is only authoritative inside its provider prefix. An admin
	// family (including its later tombstone) must not prevent a default-plane
	// root with the same opaque request id or invalidate that root's access.
	memberSession := NewSession(app, "member-subject", "users")
	for _, tokenType := range []fosite.TokenType{fosite.AccessToken, fosite.RefreshToken} {
		memberSession.SetExpiresAt(tokenType, time.Now().Add(time.Hour))
	}
	memberReq := &fosite.Request{ID: "admin-request", Client: memberClient, RequestedAt: time.Now(), Session: memberSession}
	if err := memberStore.CreateAccessTokenSession(ctx, "member-collision-access", memberReq); err != nil {
		t.Fatal(err)
	}
	if err := memberStore.CreateRefreshTokenSession(ctx, "member-collision-refresh", "member-collision-access", memberReq); err != nil {
		t.Fatalf("cross-prefix request-id collision blocked root: %v", err)
	}
	if err := adminStore.RevokeRefreshToken(ctx, "admin-request"); err != nil {
		t.Fatal(err)
	}
	if _, err := memberStore.GetAccessTokenSession(ctx, "member-collision-access", &Session{}); err != nil {
		t.Fatalf("admin terminal family blocked member access: %v", err)
	}
	if _, err := memberStore.GetRefreshTokenSession(ctx, "member-collision-refresh", &Session{}); err != nil {
		t.Fatalf("admin terminal family blocked member refresh: %v", err)
	}
	if err := adminStore.CreatePKCERequestSession(ctx, "admin-pkce-sig", req); err != nil {
		t.Fatal(err)
	}
	if _, err := memberStore.GetPKCERequestSession(ctx, "admin-pkce-sig", &Session{}); !errors.Is(err, fosite.ErrNotFound) {
		t.Fatalf("cross-prefix PKCE lookup=%v", err)
	}
	if err := adminStore.CreateOpenIDConnectSession(ctx, "admin-oidc-sig", req); err != nil {
		t.Fatal(err)
	}
	if _, err := memberStore.GetOpenIDConnectSession(ctx, "admin-oidc-sig", req); err == nil {
		t.Fatal("default provider read admin OIDC session")
	}
	if err := adminStore.SetClientAssertionJWT(ctx, "shared-jti", time.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	if err := memberStore.ClientAssertionJWTValid(ctx, "shared-jti"); err != nil {
		t.Fatalf("admin JTI leaked into default provider: %v", err)
	}
	if err := memberStore.SetClientAssertionJWT(ctx, "shared-jti", time.Now().Add(time.Hour)); err != nil {
		t.Fatalf("same JTI could not exist independently: %v", err)
	}

	interaction := &Interaction{ID: "prefix-interaction", ClientID: "shared", RequestForm: url.Values{}, RequestedScopes: []string{"openid"}}
	if _, err := CreateInteractionAt(app, "/oauth2/admin", interaction); err != nil {
		t.Fatal(err)
	}
	if _, err := FindInteractionAt(app, DefaultPathPrefix, interaction.ID); err == nil {
		t.Fatal("default provider read admin interaction")
	}
	if _, err := UpsertConsentAt(app, "/oauth2/admin", "subject", "members", "shared", []string{"openid"}); err != nil {
		t.Fatal(err)
	}
	if consent, err := FindConsentAt(app, DefaultPathPrefix, "subject", "members", "shared"); err != nil || consent != nil {
		t.Fatalf("default provider saw admin consent: consent=%v err=%v", consent, err)
	}
}

func TestProviderPrefixIsolation_EndpointsAndAccessAuthority(t *testing.T) {
	app, _ := newDualProviderTestApp(t)
	savePrefixClient(t, app, DefaultPathPrefix, "shared", "same-secret")
	savePrefixClient(t, app, "/oauth2/admin", "shared", "same-secret")
	savePrefixClient(t, app, DefaultPathPrefix, "members-only", "members-only-secret")
	token := seedAuthorityToken(t, app, DefaultPathPrefix, "shared")
	if a, err := ValidateAccessTokenAuthorityAt(context.Background(), app, DefaultPathPrefix, token); err != nil || a.ClientID != "shared" {
		t.Fatalf("default authority failed: authority=%v err=%v", a, err)
	}
	if _, err := ValidateAccessTokenAuthorityAt(context.Background(), app, "/oauth2/admin", token); err == nil {
		t.Fatal("admin authority accepted default token")
	}

	authURL := "/oauth2/admin/auth?response_type=code&client_id=members-only&redirect_uri=" + url.QueryEscape("https://client.example/cb") + "&scope=openid&code_challenge=x&code_challenge_method=S256"
	if rec := dispatchPrefixRequest(t, app, httptest.NewRequest(http.MethodGet, authURL, nil)); rec.Code < 400 {
		t.Fatalf("admin /auth accepted default-only client: %d", rec.Code)
	}

	form := url.Values{"token": {token}}
	req := httptest.NewRequest(http.MethodPost, "/oauth2/admin/introspect", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth("shared", "same-secret")
	rec := dispatchPrefixRequest(t, app, req)
	if rec.Code != http.StatusOK || strings.Contains(rec.Body.String(), `"active":true`) {
		t.Fatalf("admin introspection accepted default token: %d %s", rec.Code, rec.Body.String())
	}

	revokeForm := url.Values{"token": {token}, "token_type_hint": {"access_token"}, "client_id": {"shared"}, "client_secret": {"same-secret"}}
	req = httptest.NewRequest(http.MethodPost, "/oauth2/admin/revoke", strings.NewReader(revokeForm.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if rec = dispatchPrefixRequest(t, app, req); rec.Code != http.StatusOK {
		t.Fatalf("admin revoke status=%d body=%s", rec.Code, rec.Body.String())
	}
	if _, err := ValidateAccessTokenAuthorityAt(context.Background(), app, DefaultPathPrefix, token); err != nil {
		t.Fatalf("cross-prefix revoke deleted default token: %v", err)
	}

	req = httptest.NewRequest(http.MethodGet, "/oauth2/admin/userinfo", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	if rec = dispatchPrefixRequest(t, app, req); rec.Code != http.StatusUnauthorized {
		t.Fatalf("admin userinfo accepted default token: %d %s", rec.Code, rec.Body.String())
	}

	client, _ := GetOAuth2StoreAt(app, DefaultPathPrefix).GetClient(context.Background(), "shared")
	session := NewSession(app, "subject", "users")
	session.SetExpiresAt(fosite.AuthorizeCode, time.Now().Add(time.Minute))
	request := &fosite.Request{ID: "code-request", Client: client, RequestedAt: time.Now(), Session: session, Form: url.Values{"redirect_uri": {"https://client.example/cb"}}}
	strategy := NewPocketBaseStrategyAt(app, GetOAuth2ConfigAt(app, DefaultPathPrefix), DefaultPathPrefix)
	code, signature, err := strategy.GenerateAuthorizeCode(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	if err := GetOAuth2StoreAt(app, DefaultPathPrefix).CreateAuthorizeCodeSession(context.Background(), signature, request); err != nil {
		t.Fatal(err)
	}
	if err := NewPocketBaseStrategyAt(app, GetOAuth2ConfigAt(app, "/oauth2/admin"), "/oauth2/admin").ValidateAuthorizeCode(context.Background(), request, code); err == nil {
		t.Fatal("admin token authority accepted default authorization code signature")
	}
	tokenForm := url.Values{"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {"https://client.example/cb"}, "client_id": {"shared"}, "client_secret": {"same-secret"}, "code_verifier": {"x"}}
	req = httptest.NewRequest(http.MethodPost, "/oauth2/admin/token", strings.NewReader(tokenForm.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if rec = dispatchPrefixRequest(t, app, req); rec.Code < 400 {
		t.Fatalf("admin token endpoint exchanged default code: %d %s", rec.Code, rec.Body.String())
	}
}

func TestAccessTokenAuthority_TerminalRefreshAuthorityDeniesSurvivingAccess(t *testing.T) {
	app, _ := newDualProviderTestApp(t)
	savePrefixClient(t, app, DefaultPathPrefix, "shared", "same-secret")
	token := seedAuthorityToken(t, app, DefaultPathPrefix, "shared")
	ctx := context.Background()
	if _, err := ValidateAccessTokenAuthorityAt(ctx, app, DefaultPathPrefix, token); err != nil {
		t.Fatalf("access should start live: %v", err)
	}
	// RevokeRefreshToken publishes terminal authority before attempting family
	// row/access cleanup. With no seed row, the access record deliberately
	// remains physically present and proves the validator does not trust mere
	// row existence after terminal authority wins.
	if err := GetOAuth2StoreAt(app, DefaultPathPrefix).RevokeRefreshToken(ctx, "authority-request"); err != nil {
		t.Fatal(err)
	}
	parts := strings.Split(token, ".")
	if _, err := findSessionModelBySignature(app, DefaultPathPrefix, &AccessTokenModel{}, parts[2]); err != nil {
		t.Fatalf("access row should survive this synthetic cleanup gap: %v", err)
	}
	if _, err := ValidateAccessTokenAuthorityAt(ctx, app, DefaultPathPrefix, token); !errors.Is(err, fosite.ErrInactiveToken) {
		t.Fatalf("terminal access authority error=%v, want ErrInactiveToken", err)
	}
}

func TestProviderPrefixIsolation_AmbiguousLegacyStateFailsClosed(t *testing.T) {
	dir, _ := os.MkdirTemp("", "oauth2-prefix-legacy-*")
	app, err := pbtests.NewTestApp(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { Deregister(app); app.Cleanup(); _ = os.RemoveAll(dir) }()
	if err := Register(app, &Config{BaseConfig: &fosite.Config{}, PathPrefix: DefaultPathPrefix}); err != nil {
		t.Fatal(err)
	}
	c, _ := app.FindCollectionByNameOrId(consts.ConsentCollectionName)
	r := core.NewRecord(c)
	r.Set("user_id", "legacy")
	r.Set("user_collection", "users")
	r.Set("client_id", "legacy")
	r.Set("granted_scopes", []string{"openid"})
	if err := app.SaveNoValidate(r); err != nil {
		t.Fatal(err)
	}
	err = Register(app, &Config{BaseConfig: &fosite.Config{}, PathPrefix: "/oauth2/admin"})
	if err == nil || !strings.Contains(err.Error(), "ambiguous legacy OAuth state") {
		t.Fatalf("second provider error = %v", err)
	}
	if IsRegisteredAt(app, "/oauth2/admin") {
		t.Fatal("failed registration left admin provider live")
	}
	if !IsRegisteredAt(app, DefaultPathPrefix) {
		t.Fatal("failed registration removed default provider")
	}
}
