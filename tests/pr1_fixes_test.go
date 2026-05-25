package oauth2

import (
	"encoding/json"
	"net/http"
	"os"
	"sync"
	"sync/atomic"
	"testing"

	oauth2 "github.com/jesposito/pocketbase-ext-oauth2-mt"
	"github.com/jesposito/pocketbase-ext-oauth2-mt/rfc9728"
	"github.com/ory/fosite"
	"github.com/pocketbase/pocketbase/core"
	"github.com/pocketbase/pocketbase/tests"
)

// TestRegister_ConcurrentSameApp_OneWinner exercises the N2 atomic guard.
// Before the fix, Get-then-Set on app.Store() had a TOCTOU window where
// concurrent racers could both pass the duplicate check and double-bind
// hooks. After the fix, exactly one goroutine wins and the rest receive
// the "already registered" error.
func TestRegister_ConcurrentSameApp_OneWinner(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "pb_oauth2_n2_*")
	if err != nil {
		t.Fatal(err)
	}
	app, err := tests.NewTestApp(tempDir)
	if err != nil {
		t.Fatal(err)
	}
	defer app.Cleanup()

	const racers = 50
	var wins, losses int32
	var wg sync.WaitGroup
	wg.Add(racers)
	start := make(chan struct{})

	for i := 0; i < racers; i++ {
		go func() {
			defer wg.Done()
			<-start
			err := oauth2.Register(app, &oauth2.Config{
				BaseConfig: &fosite.Config{
					ScopeStrategy: fosite.ExactScopeStrategy,
				},
				PathPrefix:     "/oauth2",
				UserCollection: "users",
			})
			if err == nil {
				atomic.AddInt32(&wins, 1)
			} else {
				atomic.AddInt32(&losses, 1)
			}
		}()
	}
	close(start)
	wg.Wait()

	if wins != 1 {
		t.Errorf("expected exactly 1 winning Register call, got %d (losses=%d)", wins, losses)
	}
	if losses != racers-1 {
		t.Errorf("expected %d losing Register calls, got %d", racers-1, losses)
	}
}

// TestRegisterProtectedResourceMetadata_PreBootstrap verifies the N3 fix.
// The helper used to panic when called before app bootstrap because it
// dereferenced inst.metadata (set inside loadParams). After the fix the
// registration is buffered and the scope is merged into discovery metadata
// once loadParams runs.
func TestRegisterProtectedResourceMetadata_PreBootstrap(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "pb_oauth2_n3_*")
	if err != nil {
		t.Fatal(err)
	}
	app, err := tests.NewTestApp(tempDir)
	if err != nil {
		t.Fatal(err)
	}
	defer app.Cleanup()

	if err := oauth2.Register(app, &oauth2.Config{
		BaseConfig: &fosite.Config{
			ScopeStrategy: fosite.ExactScopeStrategy,
		},
		PathPrefix:                             "/oauth2",
		UserCollection:                         "users",
		EnableRFC9728ProtectedResourceMetadata: true,
	}); err != nil {
		t.Fatalf("Register failed: %v", err)
	}

	// Defer catches any panic on the helper call.
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("RegisterProtectedResourceMetadata panicked: %v", r)
		}
	}()
	oauth2.RegisterProtectedResourceMetadata(app, &rfc9728.ProtectedResourceMetadata{
		Resource:               app.Settings().Meta.AppURL + "/api/widgets",
		AuthorizationServers:   []string{app.Settings().Meta.AppURL},
		BearerMethodsSupported: []string{"header"},
		ScopesSupported:        []string{"widgets:read"},
	})
}

// TestWellKnown_ResponseModesSupported_IncludesFormPost covers N5: the
// client allows form_post, so discovery metadata must advertise it.
func TestWellKnown_ResponseModesSupported_IncludesFormPost(t *testing.T) {
	scenario := tests.ApiScenario{
		Name:           "discovery advertises form_post",
		Method:         http.MethodGet,
		URL:            "/.well-known/openid-configuration",
		ExpectedStatus: 200,
		ExpectedContent: []string{
			`"response_modes_supported"`,
			`"form_post"`,
		},
		TestAppFactory: func(t testing.TB) *tests.TestApp {
			return setupTestAppForScenario(t)
		},
	}
	scenario.Test(t)
}

// TestDefaultUserInfoClaimStrategy_FiltersByScope covers 3a at the strategy
// layer. With only the "openid" scope, the default strategy must return
// only the "sub" claim (OIDC Core 1.0 §5.4). Pre-fix the handler ignored
// the scope set and always asked for openid+profile+address+email, leaking
// profile/email claims into the response.
func TestDefaultUserInfoClaimStrategy_FiltersByScope(t *testing.T) {
	app := setupTestApp(t)
	defer app.Cleanup()
	user := seedTestUser(t, app)

	cfg := oauth2.GetOAuth2Config(app)
	if cfg.UserInfoClaimStrategy == nil {
		t.Fatal("UserInfoClaimStrategy is nil")
	}

	cases := []struct {
		name           string
		scopes         []string
		mustContain    []string
		mustNotContain []string
	}{
		{
			name:           "openid only",
			scopes:         []string{"openid"},
			mustContain:    []string{`"sub"`},
			mustNotContain: []string{`"name"`, `"email"`, `"phone_number"`, `"address"`},
		},
		{
			name:           "openid + email",
			scopes:         []string{"openid", "email"},
			mustContain:    []string{`"sub"`, `"email"`},
			mustNotContain: []string{`"phone_number"`, `"address"`},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e := &core.RequestEvent{App: app, Auth: user}
			info, err := cfg.UserInfoClaimStrategy.GetUserInfoClaims(e, tc.scopes)
			if err != nil {
				t.Fatalf("GetUserInfoClaims: %v", err)
			}
			body, err := json.Marshal(info)
			if err != nil {
				t.Fatalf("marshal claims: %v", err)
			}
			got := string(body)
			for _, want := range tc.mustContain {
				if !contains(got, want) {
					t.Errorf("expected %s in claims, got: %s", want, got)
				}
			}
			for _, leaked := range tc.mustNotContain {
				if contains(got, leaked) {
					t.Errorf("scope-filter leaked %s for scopes %v: %s", leaked, tc.scopes, got)
				}
			}
		})
	}
}

func contains(haystack, needle string) bool {
	for i := 0; i+len(needle) <= len(haystack); i++ {
		if haystack[i:i+len(needle)] == needle {
			return true
		}
	}
	return false
}
