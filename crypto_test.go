package oauth2

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"
)

// makeKey generates a 32-byte random master key for tests.
func makeKey(t *testing.T) []byte {
	t.Helper()
	k := make([]byte, 32)
	if _, err := rand.Read(k); err != nil {
		t.Fatal(err)
	}
	return k
}

func TestSealOpenEnvelope_RoundTrip(t *testing.T) {
	master := makeKey(t)
	plaintext := []byte(`{"hello":"world","n":42}`)

	sealed, err := sealEnvelope(master, "/tmp/data", "oauth2_rsa_key", plaintext)
	if err != nil {
		t.Fatalf("sealEnvelope: %v", err)
	}

	env, ok := looksLikeEnvelope(sealed)
	if !ok {
		t.Fatalf("sealed output is not a recognized envelope: %s", sealed)
	}
	if env.V != envelopeVersion {
		t.Errorf("V = %d, want %d", env.V, envelopeVersion)
	}
	if env.Alg != envelopeAlg {
		t.Errorf("Alg = %q, want %q", env.Alg, envelopeAlg)
	}
	if env.Kid != fingerprintOf(master) {
		t.Errorf("Kid = %q, want %q", env.Kid, fingerprintOf(master))
	}

	plain, err := openEnvelope(master, "/tmp/data", "oauth2_rsa_key", env)
	if err != nil {
		t.Fatalf("openEnvelope: %v", err)
	}
	if !bytes.Equal(plain, plaintext) {
		t.Errorf("round-trip mismatch: got %q, want %q", plain, plaintext)
	}
}

func TestOpenEnvelope_WrongInfo_Fails(t *testing.T) {
	// DEK is bound to (dataDir, paramID) via HKDF info. A different info
	// should fail GCM authentication, not silently produce garbage.
	master := makeKey(t)
	plaintext := []byte("secret material")
	sealed, err := sealEnvelope(master, "/tmp/a", "param1", plaintext)
	if err != nil {
		t.Fatal(err)
	}
	env, _ := looksLikeEnvelope(sealed)

	if _, err := openEnvelope(master, "/tmp/b", "param1", env); err == nil {
		t.Error("expected auth failure when dataDir differs, got nil")
	}
	if _, err := openEnvelope(master, "/tmp/a", "param2", env); err == nil {
		t.Error("expected auth failure when paramID differs, got nil")
	}
}

func TestOpenEnvelope_WrongMaster_Fails(t *testing.T) {
	master := makeKey(t)
	other := makeKey(t)
	sealed, err := sealEnvelope(master, "/x", "p", []byte("hi"))
	if err != nil {
		t.Fatal(err)
	}
	env, _ := looksLikeEnvelope(sealed)
	if _, err := openEnvelope(other, "/x", "p", env); err == nil {
		t.Error("expected failure with wrong master, got nil")
	}
}

func TestLooksLikeEnvelope_RejectsPlaintext(t *testing.T) {
	cases := [][]byte{
		[]byte(``),
		[]byte(`abc123`),
		[]byte(`"deadbeef"`),
		[]byte(`{"foo":"bar"}`),                     // valid JSON, wrong shape
		[]byte(`{"v":2,"alg":"AES-256-GCM","ct":"x","nonce":"y"}`), // wrong version
		[]byte(`{"v":1,"alg":"AES-128-GCM","ct":"x","nonce":"y"}`), // wrong alg
		// hex-encoded 32-byte secret (legacy []byte plaintext shape)
		[]byte(hex.EncodeToString(bytes.Repeat([]byte{0xab}, 32))),
	}
	for _, raw := range cases {
		if _, ok := looksLikeEnvelope(raw); ok {
			t.Errorf("looksLikeEnvelope(%q) = true, want false", raw)
		}
	}
}

func TestDecodeMasterKey_AcceptsFormats(t *testing.T) {
	want := bytes.Repeat([]byte{0x11}, 32)
	cases := map[string]string{
		"raw-32":      string(want),
		"hex":         hex.EncodeToString(want),
		"std-base64":  base64.StdEncoding.EncodeToString(want),
		"raw-base64":  base64.RawStdEncoding.EncodeToString(want),
		"url-base64":  base64.URLEncoding.EncodeToString(want),
		"rawurl-b64":  base64.RawURLEncoding.EncodeToString(want),
	}
	for name, enc := range cases {
		t.Run(name, func(t *testing.T) {
			got, err := decodeMasterKey(enc)
			if err != nil {
				t.Fatalf("decodeMasterKey: %v", err)
			}
			if !bytes.Equal(got, want) {
				t.Errorf("decoded mismatch")
			}
		})
	}
}

func TestDecodeMasterKey_RejectsBadInput(t *testing.T) {
	cases := []string{
		"",
		"not-a-key",
		// Wrong-length hex: 31 bytes -> 62 chars, neither raw-32 nor hex-32.
		hex.EncodeToString(bytes.Repeat([]byte{0x11}, 31)),
		// Wrong-length base64: 16 bytes -> 24 chars, neither raw-32 nor any
		// recognized 32-byte encoding.
		base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0x11}, 16)),
	}
	for _, raw := range cases {
		if _, err := decodeMasterKey(raw); err == nil {
			t.Errorf("decodeMasterKey(%q) error = nil, want error", raw)
		}
	}
}

func TestEnvMasterKeyProvider(t *testing.T) {
	// Save and restore env so this test is hermetic.
	orig := os.Getenv(envEnvelopeMasterKey)
	t.Cleanup(func() { os.Setenv(envEnvelopeMasterKey, orig) })

	p := envMasterKeyProvider{}

	// Unset -> nil, no error.
	os.Unsetenv(envEnvelopeMasterKey)
	master, err := p.Master(context.Background())
	if err != nil || master != nil {
		t.Errorf("unset env: got (%v, %v), want (nil, nil)", master, err)
	}
	fp, err := p.Fingerprint(context.Background())
	if err != nil || fp != "" {
		t.Errorf("unset env fingerprint: got (%q, %v), want (\"\", nil)", fp, err)
	}

	// Set -> bytes match.
	want := makeKey(t)
	os.Setenv(envEnvelopeMasterKey, base64.StdEncoding.EncodeToString(want))
	master, err = p.Master(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(master, want) {
		t.Error("master bytes mismatch")
	}
	fp, err = p.Fingerprint(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if fp != fingerprintOf(want) {
		t.Errorf("fingerprint = %q, want %q", fp, fingerprintOf(want))
	}

	// kms:// is rejected (reserved).
	os.Setenv(envEnvelopeMasterKey, "kms://aws/some/arn")
	if _, err := p.Master(context.Background()); err == nil {
		t.Error("expected error for kms:// URL, got nil")
	}
}

// TestEnvelope_JSONShape locks the on-disk shape so future refactors don't
// silently break round-trips for already-stored values.
func TestEnvelope_JSONShape(t *testing.T) {
	master := makeKey(t)
	sealed, err := sealEnvelope(master, "/d", "p", []byte("x"))
	if err != nil {
		t.Fatal(err)
	}
	var raw map[string]any
	if err := json.Unmarshal(sealed, &raw); err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"v", "alg", "kid", "nonce", "ct"} {
		if _, ok := raw[key]; !ok {
			t.Errorf("envelope JSON missing key %q: %s", key, sealed)
		}
	}
}
