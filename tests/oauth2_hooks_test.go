package oauth2

import (
	"testing"
	"time"

	oauth2 "github.com/jesposito/pocketbase-ext-oauth2-mt"
	"github.com/jesposito/pocketbase-ext-oauth2-mt/consts"
	"github.com/pocketbase/dbx"
	"github.com/pocketbase/pocketbase/core"
)

func TestRegister_CreatesCollections(t *testing.T) {
	app := setupTestApp(t)
	defer app.Cleanup()

	expectedCollections := []string{
		consts.ClientCollectionName,
		consts.AuthCodeCollectionName,
		consts.AccessCollectionName,
		consts.RefreshCollectionName,
		consts.PKCECollectionName,
		consts.OpenIDConnectCollectionName,
		consts.JTICollectionName,
	}

	for _, name := range expectedCollections {
		c, err := app.FindCollectionByNameOrId(name)
		if err != nil {
			t.Errorf("collection %q not found after Register: %v", name, err)
			continue
		}
		if !c.System {
			t.Errorf("collection %q should be marked as System", name)
		}
	}
}

func TestRegister_SetsDefaults(t *testing.T) {
	app := setupTestApp(t)
	defer app.Cleanup()

	cfg := oauth2.GetOAuth2Config(app)
	if cfg.PathPrefix != "/oauth2" {
		t.Errorf("PathPrefix = %q, want %q", cfg.PathPrefix, "/oauth2")
	}
	if cfg.UserCollection != testUserCollection {
		t.Errorf("UserCollection = %q, want %q", cfg.UserCollection, testUserCollection)
	}
	if cfg.UserInfoClaimStrategy == nil {
		t.Error("expected non-nil UserInfoClaimStrategy")
	}
}

func TestIsRegistered(t *testing.T) {
	app := setupTestApp(t)
	defer app.Cleanup()

	if !oauth2.IsRegistered(app) {
		t.Error("expected IsRegistered=true after Register")
	}
}

// TestRegister_MultiplePrefixesOnSameApp verifies that a single core.App
// can host two OAuth2 OPs at distinct PathPrefixes — the M3 multi-OP-per-
// tenant capability. Without the (app, prefix) registration guard this
// second Register would fail with "already registered for this app".
func TestRegister_MultiplePrefixesOnSameApp(t *testing.T) {
	app := setupTestApp(t)
	defer app.Cleanup()

	// setupTestApp already registered at the default /oauth2 prefix.
	// Register a second OP at /oauth2/members.
	err := oauth2.Register(app, &oauth2.Config{
		BaseConfig:                             oauth2.GetOAuth2Config(app).BaseConfig,
		PathPrefix:                             "/oauth2/members",
		UserCollection:                         testUserCollection,
		EnableRFC7591DynamicClientRegistration: false,
		EnableRFC9728ProtectedResourceMetadata: true,
	})
	if err != nil {
		t.Fatalf("second Register() at /oauth2/members failed: %v", err)
	}

	if !oauth2.IsRegistered(app) {
		t.Error("default prefix lookup should still report registered")
	}
	if !oauth2.IsRegisteredAt(app, "/oauth2/members") {
		t.Error("/oauth2/members lookup should report registered")
	}
	if oauth2.IsRegisteredAt(app, "/oauth2/nonexistent") {
		t.Error("/oauth2/nonexistent should not report registered")
	}

	defaultCfg := oauth2.GetOAuth2ConfigAt(app, "/oauth2")
	membersCfg := oauth2.GetOAuth2ConfigAt(app, "/oauth2/members")
	if defaultCfg.PathPrefix != "/oauth2" {
		t.Errorf("default config PathPrefix = %q, want /oauth2", defaultCfg.PathPrefix)
	}
	if membersCfg.PathPrefix != "/oauth2/members" {
		t.Errorf("members config PathPrefix = %q, want /oauth2/members", membersCfg.PathPrefix)
	}
	if defaultCfg == membersCfg {
		t.Error("default and members configs should be distinct instances")
	}
}

// TestRegister_SameAppSamePrefix_Rejected verifies the dedup contract is
// preserved for identical (app, prefix) pairs (back-compat with the
// original sync.Map semantics).
func TestRegister_SameAppSamePrefix_Rejected(t *testing.T) {
	app := setupTestApp(t)
	defer app.Cleanup()

	err := oauth2.Register(app, &oauth2.Config{
		BaseConfig:                             oauth2.GetOAuth2Config(app).BaseConfig,
		PathPrefix:                             "/oauth2", // same as setupTestApp
		UserCollection:                         testUserCollection,
		EnableRFC7591DynamicClientRegistration: false,
		EnableRFC9728ProtectedResourceMetadata: false,
	})
	if err == nil {
		t.Fatal("expected second Register() at the same prefix to fail")
	}
}

// TestDeregisterAt_LeavesOtherPrefixIntact: Deregister-by-prefix releases
// only the named registration; sibling prefixes on the same app keep
// working.
func TestDeregisterAt_LeavesOtherPrefixIntact(t *testing.T) {
	app := setupTestApp(t)
	defer app.Cleanup()

	if err := oauth2.Register(app, &oauth2.Config{
		BaseConfig:                             oauth2.GetOAuth2Config(app).BaseConfig,
		PathPrefix:                             "/oauth2/members",
		UserCollection:                         testUserCollection,
		EnableRFC7591DynamicClientRegistration: false,
	}); err != nil {
		t.Fatalf("second Register: %v", err)
	}

	oauth2.DeregisterAt(app, "/oauth2/members")

	if oauth2.IsRegisteredAt(app, "/oauth2/members") {
		t.Error("members should be deregistered")
	}
	if !oauth2.IsRegistered(app) {
		t.Error("default prefix should remain registered")
	}

	// Full Deregister now cleans up the survivor too.
	oauth2.Deregister(app)
	if oauth2.IsRegistered(app) {
		t.Error("Deregister(app) should clear ALL prefixes")
	}
}

func TestClientSecretHashing(t *testing.T) {
	app := setupTestApp(t)
	defer app.Cleanup()

	c, err := app.FindCollectionByNameOrId(consts.ClientCollectionName)
	if err != nil {
		t.Fatalf("failed to find clients collection: %v", err)
	}

	record := core.NewRecord(c)
	record.Set("client_id", "hash-test-client")
	record.Set("client_name", "Hash Test")
	record.Set("client_secret", "plaintext-secret") // Should be hashed by OnRecordCreate hook
	record.Set("redirect_uris", []string{"http://localhost/cb"})
	record.Set("grant_types", []string{"authorization_code"})
	record.Set("response_types", []string{"code"})
	record.Set("scope", "openid")
	record.Set("audience", []string{})
	record.Set("contacts", []string{})
	record.Set("allowed_cors_origins", []string{})
	record.Set("request_uris", []string{})

	if err := app.Save(record); err != nil {
		t.Fatalf("failed to save client: %v", err)
	}

	// Reload from DB
	saved, err := app.FindRecordById(c.Id, record.Id)
	if err != nil {
		t.Fatalf("failed to reload client: %v", err)
	}

	storedSecret := saved.GetString("client_secret")
	if storedSecret == "plaintext-secret" {
		t.Error("client_secret was not hashed — still plaintext after OnRecordCreate hook")
	}
	if storedSecret == "" {
		t.Error("client_secret is empty after hashing")
	}
}

func TestCleanupExpiredSessions(t *testing.T) {
	app := setupTestApp(t)
	defer app.Cleanup()

	seedTestClient(t, app)

	// Insert expired sessions into each session collection
	expiredTime := time.Now().Add(-time.Hour).Unix()

	for _, collName := range []string{
		consts.AuthCodeCollectionName,
		consts.AccessCollectionName,
		consts.RefreshCollectionName,
		consts.PKCECollectionName,
		consts.OpenIDConnectCollectionName,
	} {
		c, err := app.FindCollectionByNameOrId(collName)
		if err != nil {
			t.Fatalf("failed to find %s: %v", collName, err)
		}

		record := core.NewRecord(c)
		record.Set("signature", "expired-"+collName)
		record.Set("client_id", testClientID)
		record.Set("request_id", "expired-req")
		record.Set("requested_at", expiredTime)
		record.Set("expires_at", expiredTime) // expired
		record.Set("scopes", "openid")
		record.Set("granted_scopes", "openid")
		record.Set("form_data", "")
		record.Set("session_data", "{}")
		record.Set("subject", "expired-user")
		record.Set("requested_audience", "")
		record.Set("granted_audience", "")

		if err := app.SaveNoValidate(record); err != nil {
			t.Fatalf("failed to insert expired session in %s: %v", collName, err)
		}
	}

	// Also insert an expired JTI
	jtiC, err := app.FindCollectionByNameOrId(consts.JTICollectionName)
	if err != nil {
		t.Fatalf("failed to find JTI collection: %v", err)
	}
	jtiRecord := core.NewRecord(jtiC)
	jtiRecord.Set("jti", "expired-jti")
	jtiRecord.Set("expires_at", expiredTime)
	if err := app.SaveNoValidate(jtiRecord); err != nil {
		t.Fatalf("failed to insert expired JTI: %v", err)
	}

	// Run the cleanup job directly
	var foundJob bool
	for _, j := range app.Cron().Jobs() {
		if j.Id() == consts.CleanupExpiredSessionsJobName {
			j.Run()
			foundJob = true
			break
		}
	}

	if !foundJob {
		t.Fatalf("cleanup job %q not found in cron jobs", consts.CleanupExpiredSessionsJobName)
	}

	// Verify expired sessions are gone
	for _, collName := range []string{
		consts.AuthCodeCollectionName,
		consts.AccessCollectionName,
		consts.RefreshCollectionName,
		consts.PKCECollectionName,
		consts.OpenIDConnectCollectionName,
	} {
		n, err := app.CountRecords(collName, dbx.HashExp{"signature": "expired-" + collName})
		if err != nil {
			t.Errorf("failed to count records in %s: %v", collName, err)
			continue
		}
		if n != 0 {
			t.Errorf("expected 0 expired records in %s, got %d", collName, n)
		}
	}

	// Verify expired JTI is gone
	n, err := app.CountRecords(consts.JTICollectionName, dbx.HashExp{"jti": "expired-jti"})
	if err != nil {
		t.Fatalf("failed to count JTI records: %v", err)
	}
	if n != 0 {
		t.Errorf("expected 0 expired JTI records, got %d", n)
	}
}
