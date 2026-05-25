package oauth2

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"

	"github.com/pocketbase/pocketbase/core"
	"github.com/pocketbase/pocketbase/tests"
)

// newCryptoTestApp builds a bare TestApp with a temp data dir. We don't
// register the OAuth2 plugin here so we can exercise loadParamFromAppStorage
// directly against the _params table without dragging in the rest of the
// bootstrap path. We also unset OAUTH2_MASTER_KEY by default and re-set per
// test to keep this hermetic.
func newCryptoTestApp(t *testing.T) *tests.TestApp {
	t.Helper()
	tempDir, err := os.MkdirTemp("", "pb_oauth2_crypto_*")
	if err != nil {
		t.Fatal(err)
	}
	app, err := tests.NewTestApp(tempDir)
	if err != nil {
		os.RemoveAll(tempDir)
		t.Fatal(err)
	}
	t.Cleanup(func() {
		app.Cleanup()
	})
	return app
}

// withMasterEnv sets OAUTH2_MASTER_KEY for the duration of the test.
func withMasterEnv(t *testing.T, master []byte) {
	t.Helper()
	orig, hadOrig := os.LookupEnv(envEnvelopeMasterKey)
	if master == nil {
		os.Unsetenv(envEnvelopeMasterKey)
	} else {
		os.Setenv(envEnvelopeMasterKey, base64.StdEncoding.EncodeToString(master))
	}
	t.Cleanup(func() {
		if hadOrig {
			os.Setenv(envEnvelopeMasterKey, orig)
		} else {
			os.Unsetenv(envEnvelopeMasterKey)
		}
	})
}

// rawParamValue reads the raw bytes stored in a _params row (no decryption).
func rawParamValue(t *testing.T, app core.App, id string) []byte {
	t.Helper()
	p := &core.Param{}
	if err := app.ModelQuery(p).Model(id, p); err != nil {
		t.Fatalf("read _params row %q: %v", id, err)
	}
	return []byte(p.Value)
}

func TestLoadParam_NoEnv_PlaintextRoundTrip(t *testing.T) {
	withMasterEnv(t, nil)
	app := newCryptoTestApp(t)

	// First call generates.
	got1, err := loadGlobalSecretFromAppStorage(app)
	if err != nil {
		t.Fatalf("first load: %v", err)
	}
	if len(got1) != 32 {
		t.Fatalf("secret len = %d, want 32", len(got1))
	}

	// Stored value should be legacy hex plaintext, not an envelope.
	raw := rawParamValue(t, app, paramsKeyOAuth2GlobalSecret)
	if _, ok := looksLikeEnvelope(raw); ok {
		t.Errorf("expected plaintext storage with env unset, got envelope: %s", raw)
	}
	// And it should hex-decode to the same bytes.
	decoded, err := hex.DecodeString(string(raw))
	if err != nil {
		t.Fatalf("expected hex plaintext, got error: %v (%s)", err, raw)
	}
	if !bytes.Equal(decoded, got1) {
		t.Error("plaintext bytes mismatch")
	}

	// Second call reloads the same value.
	got2, err := loadGlobalSecretFromAppStorage(app)
	if err != nil {
		t.Fatalf("second load: %v", err)
	}
	if !bytes.Equal(got1, got2) {
		t.Error("secret changed across loads")
	}
}

func TestLoadParam_WithEnv_EncryptsOnFirstWrite(t *testing.T) {
	withMasterEnv(t, makeKey(t))
	app := newCryptoTestApp(t)

	got, err := loadGlobalSecretFromAppStorage(app)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if len(got) != 32 {
		t.Fatalf("secret len = %d, want 32", len(got))
	}

	raw := rawParamValue(t, app, paramsKeyOAuth2GlobalSecret)
	if _, ok := looksLikeEnvelope(raw); !ok {
		t.Fatalf("expected envelope storage with env set, got: %s", raw)
	}

	// Fingerprint row should be present.
	fpRaw := rawParamValue(t, app, fingerprintParamID)
	var fpStored string
	if err := json.Unmarshal(fpRaw, &fpStored); err != nil {
		t.Fatalf("fingerprint not JSON string: %v", err)
	}
	if fpStored == "" {
		t.Error("fingerprint stored empty")
	}

	// Reload returns the same bytes.
	again, err := loadGlobalSecretFromAppStorage(app)
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	if !bytes.Equal(got, again) {
		t.Error("reload returned different bytes")
	}
}

func TestLoadParam_MigratesPlaintextToEnvelope(t *testing.T) {
	// Phase 1: store as plaintext (no env).
	withMasterEnv(t, nil)
	app := newCryptoTestApp(t)

	got1, err := loadGlobalSecretFromAppStorage(app)
	if err != nil {
		t.Fatalf("plaintext load: %v", err)
	}
	raw1 := rawParamValue(t, app, paramsKeyOAuth2GlobalSecret)
	if _, ok := looksLikeEnvelope(raw1); ok {
		t.Fatal("phase 1 should be plaintext")
	}

	// Phase 2: enable env, load again -- should return same bytes AND
	// rewrite the row as an envelope.
	master := makeKey(t)
	os.Setenv(envEnvelopeMasterKey, base64.StdEncoding.EncodeToString(master))
	t.Cleanup(func() { os.Unsetenv(envEnvelopeMasterKey) })

	got2, err := loadGlobalSecretFromAppStorage(app)
	if err != nil {
		t.Fatalf("post-migration load: %v", err)
	}
	if !bytes.Equal(got1, got2) {
		t.Errorf("migration changed value: %x vs %x", got1, got2)
	}
	raw2 := rawParamValue(t, app, paramsKeyOAuth2GlobalSecret)
	if _, ok := looksLikeEnvelope(raw2); !ok {
		t.Fatalf("expected envelope after migration, got: %s", raw2)
	}

	// Phase 3: a third load also succeeds (idempotent).
	got3, err := loadGlobalSecretFromAppStorage(app)
	if err != nil {
		t.Fatalf("third load: %v", err)
	}
	if !bytes.Equal(got1, got3) {
		t.Error("third load returned different bytes")
	}
}

func TestLoadParam_FingerprintMismatch_RefusesToDecrypt(t *testing.T) {
	// First boot with master A.
	masterA := makeKey(t)
	withMasterEnv(t, masterA)
	app := newCryptoTestApp(t)
	if _, err := loadGlobalSecretFromAppStorage(app); err != nil {
		t.Fatalf("initial load with A: %v", err)
	}

	// Switch env to master B.
	masterB := makeKey(t)
	os.Setenv(envEnvelopeMasterKey, base64.StdEncoding.EncodeToString(masterB))

	_, err := loadGlobalSecretFromAppStorage(app)
	if err == nil {
		t.Fatal("expected fingerprint mismatch error, got nil")
	}
}

func TestLoadParam_EncryptedRow_NoEnv_Errors(t *testing.T) {
	// Phase 1: write encrypted.
	master := makeKey(t)
	withMasterEnv(t, master)
	app := newCryptoTestApp(t)
	if _, err := loadGlobalSecretFromAppStorage(app); err != nil {
		t.Fatalf("encrypted write: %v", err)
	}

	// Phase 2: unset env and try to read.
	os.Unsetenv(envEnvelopeMasterKey)
	_, err := loadGlobalSecretFromAppStorage(app)
	if err == nil {
		t.Error("expected error reading encrypted row without master, got nil")
	}
}

// TestUpdateParamValueCAS_BlocksStaleWrite asserts that the compare-and-swap
// helper rejects an update whose expectedUpdated does not match the current
// row state. This is the wk3 contract: two readers cannot both blindly
// overwrite a single _params row.
func TestUpdateParamValueCAS_BlocksStaleWrite(t *testing.T) {
	withMasterEnv(t, nil)
	app := newCryptoTestApp(t)

	// Seed a plaintext row by loading the global secret once.
	if _, err := loadGlobalSecretFromAppStorage(app); err != nil {
		t.Fatalf("seed: %v", err)
	}

	// Capture the row's current value bytes — the snapshot both writers
	// will use as their CAS expected.
	p1 := &core.Param{}
	if err := app.ModelQuery(p1).Model(paramsKeyOAuth2GlobalSecret, p1); err != nil {
		t.Fatalf("read row: %v", err)
	}
	expected := []byte(p1.Value)

	// Winner: CAS succeeds, row.value flips to "first".
	ok, err := updateParamValueCAS(app, paramsKeyOAuth2GlobalSecret, []byte(`"first"`), expected)
	if err != nil {
		t.Fatalf("winner CAS: %v", err)
	}
	if !ok {
		t.Fatal("winner CAS reported no rows affected")
	}

	// Loser: CAS uses the now-stale `expected` and MUST fail (zero rows).
	ok, err = updateParamValueCAS(app, paramsKeyOAuth2GlobalSecret, []byte(`"second"`), expected)
	if err != nil {
		t.Fatalf("loser CAS: %v", err)
	}
	if ok {
		t.Fatal("loser CAS reported rows affected — stale write was applied")
	}

	// Confirm the winner's value is still in place.
	p2 := &core.Param{}
	if err := app.ModelQuery(p2).Model(paramsKeyOAuth2GlobalSecret, p2); err != nil {
		t.Fatalf("re-read row: %v", err)
	}
	if string(p2.Value) != `"first"` {
		t.Errorf("post-CAS value = %q, want %q", string(p2.Value), `"first"`)
	}
}

// TestLoadParam_KeyRotation_RewrapsOnRead verifies that when an envelope
// is sealed under master A, and the active master rotates to B with A
// kept in OAUTH2_MASTER_KEY_OLD, the next load:
//   1. successfully decrypts via the keyring (d9a),
//   2. rewraps the row under B on the same call so subsequent loads do
//      not need the old key (lazy rotation).
func TestLoadParam_KeyRotation_RewrapsOnRead(t *testing.T) {
	masterA := makeKey(t)
	masterB := makeKey(t)

	// Phase 1: boot with master A, seal a value.
	withMasterEnv(t, masterA)
	app := newCryptoTestApp(t)
	v1, err := loadGlobalSecretFromAppStorage(app)
	if err != nil {
		t.Fatalf("seal under A: %v", err)
	}

	// Phase 2: rotate. Active = B; A is in OAUTH2_MASTER_KEY_OLD.
	os.Setenv(envEnvelopeMasterKey, base64.StdEncoding.EncodeToString(masterB))
	os.Setenv(envEnvelopeMasterKeysOld, base64.StdEncoding.EncodeToString(masterA))
	t.Cleanup(func() {
		os.Unsetenv(envEnvelopeMasterKeysOld)
	})

	v2, err := loadGlobalSecretFromAppStorage(app)
	if err != nil {
		t.Fatalf("decrypt under rotation: %v", err)
	}
	if !bytes.Equal(v1, v2) {
		t.Errorf("rotated load returned different value")
	}

	// Row should now be sealed under B's fingerprint.
	raw := rawParamValue(t, app, paramsKeyOAuth2GlobalSecret)
	env, ok := looksLikeEnvelope(raw)
	if !ok {
		t.Fatalf("expected envelope, got: %s", raw)
	}
	if env.Kid != fingerprintOf(masterB) {
		t.Errorf("post-rewrap kid = %q, want %q (rewrap to active master B)", env.Kid, fingerprintOf(masterB))
	}

	// Phase 3: drop A from the env — read must still succeed.
	os.Unsetenv(envEnvelopeMasterKeysOld)
	v3, err := loadGlobalSecretFromAppStorage(app)
	if err != nil {
		t.Fatalf("post-rewrap load without A: %v", err)
	}
	if !bytes.Equal(v1, v3) {
		t.Errorf("post-rewrap load returned different value")
	}
}

// TestLoadParam_DataDirChange verifies the 15o fix: an envelope sealed
// when the HKDF info was bound to app.DataDir() can still be decrypted
// after the per-app context UUID becomes the canonical binding, and the
// row is rewrapped under (active master, ctxID) on the next read.
func TestLoadParam_DataDirChange(t *testing.T) {
	master := makeKey(t)
	withMasterEnv(t, master)
	app := newCryptoTestApp(t)

	// Seed a row through the normal path. This will use the ctxID (the
	// post-15o derivation). To simulate a "legacy" envelope from before
	// the ctxID switch we manually overwrite the row with one sealed
	// against app.DataDir() and then drop the ctxID row.
	original, err := loadGlobalSecretFromAppStorage(app)
	if err != nil {
		t.Fatal(err)
	}
	plaintext := hex.AppendEncode([]byte{}, original)
	sealed, err := sealEnvelope(master, app.DataDir(), paramsKeyOAuth2GlobalSecret, plaintext)
	if err != nil {
		t.Fatal(err)
	}
	row := &core.Param{}
	if err := app.ModelQuery(row).Model(paramsKeyOAuth2GlobalSecret, row); err != nil {
		t.Fatal(err)
	}
	if _, err := app.DB().NewQuery("UPDATE _params SET value = {:v} WHERE id = {:id}").Bind(map[string]any{
		"v":  string(sealed),
		"id": paramsKeyOAuth2GlobalSecret,
	}).Execute(); err != nil {
		t.Fatal(err)
	}
	// Drop the ctxID so the next load creates a new one (matches a real
	// deployment that predates the ctxID feature).
	if _, err := app.DB().NewQuery("DELETE FROM _params WHERE id = {:id}").Bind(map[string]any{
		"id": paramsKeyOAuth2EnvelopeCtxID,
	}).Execute(); err != nil {
		t.Fatal(err)
	}

	// Load must succeed via the DataDir-fallback path.
	loaded, err := loadGlobalSecretFromAppStorage(app)
	if err != nil {
		t.Fatalf("legacy-DataDir envelope load: %v", err)
	}
	if !bytes.Equal(loaded, original) {
		t.Error("legacy-envelope plaintext mismatch")
	}

	// And the row should now be rewrapped against the new ctxID — a
	// second load with a different DataDir would still work.
	raw := rawParamValue(t, app, paramsKeyOAuth2GlobalSecret)
	env, _ := looksLikeEnvelope(raw)
	if env == nil {
		t.Fatal("expected envelope after rewrap")
	}
}

func TestLoadPrivateKey_EncryptedRoundTrip(t *testing.T) {
	withMasterEnv(t, makeKey(t))
	app := newCryptoTestApp(t)

	k1, err := loadPrivateKeyFromAppStorage(app)
	if err != nil {
		t.Fatalf("first load: %v", err)
	}
	if k1.KeyID == "" {
		t.Error("empty KeyID")
	}

	raw := rawParamValue(t, app, paramsKeyOAuth2RSAKey)
	if _, ok := looksLikeEnvelope(raw); !ok {
		t.Fatalf("expected envelope storage, got: %s", raw)
	}

	k2, err := loadPrivateKeyFromAppStorage(app)
	if err != nil {
		t.Fatalf("second load: %v", err)
	}
	if k2.KeyID != k1.KeyID {
		t.Errorf("KeyID changed: %q vs %q", k1.KeyID, k2.KeyID)
	}
}
