package oauth2

import (
	"os"
	"testing"

	oauth2 "github.com/jesposito/pocketbase-ext-oauth2-mt"
	"github.com/ory/fosite"
	"github.com/pocketbase/pocketbase/tests"
)

// TestMultiTenantIsolation verifies that two PocketBase apps in the same
// process receive fully independent OAuth2 providers, configs, and keys.
func TestMultiTenantIsolation(t *testing.T) {
	tempDir1, err := os.MkdirTemp("", "pb_oauth2_iso_1_*")
	if err != nil {
		t.Fatal(err)
	}
	tempDir2, err := os.MkdirTemp("", "pb_oauth2_iso_2_*")
	if err != nil {
		t.Fatal(err)
	}

	app1, err := tests.NewTestApp(tempDir1)
	if err != nil {
		t.Fatal(err)
	}
	defer app1.Cleanup()

	app2, err := tests.NewTestApp(tempDir2)
	if err != nil {
		t.Fatal(err)
	}
	defer app2.Cleanup()

	cfg1 := &oauth2.Config{
		BaseConfig: &fosite.Config{
			ScopeStrategy: fosite.ExactScopeStrategy,
		},
		PathPrefix:     "/oauth2",
		UserCollection: "users",
	}
	cfg2 := &oauth2.Config{
		BaseConfig: &fosite.Config{
			ScopeStrategy: fosite.HierarchicScopeStrategy,
		},
		PathPrefix:     "/oauth2",
		UserCollection: "members",
	}

	if err := oauth2.Register(app1, cfg1); err != nil {
		t.Fatalf("failed to register on app1: %v", err)
	}
	if err := oauth2.Register(app2, cfg2); err != nil {
		t.Fatalf("failed to register on app2: %v", err)
	}

	// Configs must be independent
	got1 := oauth2.GetOAuth2Config(app1)
	got2 := oauth2.GetOAuth2Config(app2)
	if got1 == got2 {
		t.Fatal("GetOAuth2Config returned the same pointer for two different apps")
	}
	// ScopeStrategy is a function; we verify the configs are independent by
	// checking other scalar fields that were different between the two configs.
	if got1.UserCollection != "users" {
		t.Errorf("app1 UserCollection = %q, want users", got1.UserCollection)
	}
	if got2.UserCollection != "members" {
		t.Errorf("app2 UserCollection = %q, want members", got2.UserCollection)
	}

	// Stores must be independent
	store1 := oauth2.GetOAuth2Store(app1)
	store2 := oauth2.GetOAuth2Store(app2)
	if store1 == store2 {
		t.Fatal("GetOAuth2Store returned the same pointer for two different apps")
	}

	// IsRegistered must be app-scoped
	if !oauth2.IsRegistered(app1) {
		t.Error("expected IsRegistered(app1) = true")
	}
	if !oauth2.IsRegistered(app2) {
		t.Error("expected IsRegistered(app2) = true")
	}

	// Duplicate registration must be rejected
	if err := oauth2.Register(app1, cfg1); err == nil {
		t.Error("expected error on duplicate registration for app1, got nil")
	}
}

// TestMultiTenantConcurrency spawns multiple goroutines that each create and
// register an app concurrently. No panics or data races should occur.
func TestMultiTenantConcurrency(t *testing.T) {
	type result struct {
		app *tests.TestApp
		err error
	}
	results := make(chan result, 10)

	for i := 0; i < 10; i++ {
		go func(idx int) {
			tempDir, err := os.MkdirTemp("", "pb_oauth2_conc_*")
			if err != nil {
				results <- result{err: err}
				return
			}
			app, err := tests.NewTestApp(tempDir)
			if err != nil {
				results <- result{err: err}
				return
			}
			cfg := &oauth2.Config{
				BaseConfig:     &fosite.Config{},
				PathPrefix:     "/oauth2",
				UserCollection: "users",
			}
			if err := oauth2.Register(app, cfg); err != nil {
				app.Cleanup()
				results <- result{err: err}
				return
			}
			results <- result{app: app}
		}(i)
	}

	var apps []*tests.TestApp
	defer func() {
		for _, a := range apps {
			a.Cleanup()
		}
	}()

	for i := 0; i < 10; i++ {
		r := <-results
		if r.err != nil {
			t.Errorf("goroutine error: %v", r.err)
			continue
		}
		apps = append(apps, r.app)
	}
}
