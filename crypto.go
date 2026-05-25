package oauth2

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/pkg/errors"
	"golang.org/x/crypto/hkdf"
)

// envEnvelopeMasterKey is the environment variable that, when set, enables
// envelope encryption of OAuth2 key material at rest. Accepts a raw 32-byte
// value, a base64-encoded 32-byte value (std or url, padded or unpadded), a
// hex-encoded 32-byte value, or a "kms://..." URL (reserved for future KMS
// providers, not implemented yet).
const envEnvelopeMasterKey = "OAUTH2_MASTER_KEY"

// envEnvelopeMasterKeysOld is the environment variable that lists past
// master keys (comma-separated, same encodings as OAUTH2_MASTER_KEY)
// retained for decrypt-only use during a rotation. New writes always
// re-encrypt with OAUTH2_MASTER_KEY (the active master).
const envEnvelopeMasterKeysOld = "OAUTH2_MASTER_KEY_OLD"

// envelopeVersion is the only currently understood envelope version. Old
// values may still be read (migration path), but new writes always use v1.
const envelopeVersion = 1

// envelopeAlg is the AEAD algorithm used inside v1 envelopes.
const envelopeAlg = "AES-256-GCM"

// fingerprintParamID is the _params row that stores the short fingerprint
// (first 8 bytes of SHA-256 hex) of the master key currently in use. If the
// env master and the stored fingerprint disagree, loads fail fast instead of
// silently decrypting to garbage.
const fingerprintParamID = "oauth2_master_key_fingerprint"

// hkdfInfoPrefix namespaces all HKDF "info" inputs so they cannot collide
// with HKDF derivations from other code paths that might share a master.
const hkdfInfoPrefix = "pbo2/v1/"

// MasterKeyProvider abstracts the source of the at-rest encryption master
// key. The default implementation reads from the OAUTH2_MASTER_KEY env var,
// but a KMS-backed provider can be supplied via Config.MasterKeyProvider.
type MasterKeyProvider interface {
	// Master returns the 32-byte raw master key. If encryption-at-rest is
	// disabled, Master must return (nil, nil) -- callers treat that as
	// "plaintext mode".
	Master(ctx context.Context) ([]byte, error)
	// Fingerprint returns a short stable hex identifier for the master
	// key (first 8 bytes of its SHA-256). Returns ("", nil) when no
	// master is configured.
	Fingerprint(ctx context.Context) (string, error)
}

// MasterKeyringProvider is an optional extension implemented by providers
// that retain historical (decrypt-only) master keys during a rotation. The
// plugin uses Keyring to:
//   - decrypt envelopes whose embedded kid does not match the active master
//     fingerprint (i.e. envelopes written before the rotation);
//   - re-encrypt those envelopes against the active master on the next read
//     (lazy rewrap).
//
// Implementations must include the active master in the returned map. The
// map is keyed by the per-master fingerprint (as returned by fingerprintOf).
type MasterKeyringProvider interface {
	Keyring(ctx context.Context) (map[string][]byte, error)
}

// envMasterKeyProvider reads the master key from OAUTH2_MASTER_KEY.
type envMasterKeyProvider struct{}

// DefaultMasterKeyProvider is the provider used when Config.MasterKeyProvider
// is nil. It reads OAUTH2_MASTER_KEY at call time (not at init), so tests
// can mutate the env between calls.
var DefaultMasterKeyProvider MasterKeyProvider = envMasterKeyProvider{}

func (envMasterKeyProvider) Master(_ context.Context) ([]byte, error) {
	raw := strings.TrimSpace(os.Getenv(envEnvelopeMasterKey))
	if raw == "" {
		return nil, nil
	}
	if strings.HasPrefix(raw, "kms://") {
		// Reserved for future KMS providers. Surface a clear error
		// instead of silently falling back to plaintext.
		return nil, errors.New("kms:// master key URLs are not yet implemented; supply a raw 32-byte key (base64 or hex)")
	}
	key, err := decodeMasterKey(raw)
	if err != nil {
		return nil, errors.Wrap(err, "invalid OAUTH2_MASTER_KEY")
	}
	return key, nil
}

func (p envMasterKeyProvider) Fingerprint(ctx context.Context) (string, error) {
	master, err := p.Master(ctx)
	if err != nil {
		return "", err
	}
	if master == nil {
		return "", nil
	}
	return fingerprintOf(master), nil
}

// Keyring returns the active master plus any historical decrypt-only
// masters listed in OAUTH2_MASTER_KEY_OLD. Old keys missing or
// malformed are silently skipped — fingerprint enforcement on the active
// master still happens via Master/Fingerprint.
func (p envMasterKeyProvider) Keyring(ctx context.Context) (map[string][]byte, error) {
	out := map[string][]byte{}
	active, err := p.Master(ctx)
	if err != nil {
		return nil, err
	}
	if active != nil {
		out[fingerprintOf(active)] = active
	}
	raw := strings.TrimSpace(os.Getenv(envEnvelopeMasterKeysOld))
	if raw == "" {
		return out, nil
	}
	for candidate := range strings.SplitSeq(raw, ",") {
		candidate = strings.TrimSpace(candidate)
		if candidate == "" {
			continue
		}
		k, derr := decodeMasterKey(candidate)
		if derr != nil {
			// Don't fail the whole load over a malformed historical
			// entry — the active master alone is sufficient for new
			// writes. Log via a sentinel error consumers can detect
			// if they care.
			continue
		}
		out[fingerprintOf(k)] = k
	}
	return out, nil
}

// decodeMasterKey accepts the master key as a raw 32-byte string, base64 (std
// or url, padded or not), or hex, and returns exactly 32 bytes. The
// detection order is unambiguous: raw 32 bytes is len==32, hex-encoded 32
// bytes is len==64, base64-encoded 32 bytes is len==43 (raw) or 44 (padded).
func decodeMasterKey(raw string) ([]byte, error) {
	// Raw 32-byte short-circuit. A literal 32-byte secret is len==32,
	// which cannot collide with the encoded forms (hex=64, base64>=43).
	if len(raw) == 32 {
		return []byte(raw), nil
	}
	// Try hex when it looks hex-shaped (64 chars, all hex).
	if len(raw) == 64 {
		if b, err := hex.DecodeString(raw); err == nil {
			if len(b) != 32 {
				return nil, fmt.Errorf("hex master key must decode to 32 bytes, got %d", len(b))
			}
			return b, nil
		}
	}
	// Then base64 variants.
	for _, enc := range []*base64.Encoding{
		base64.StdEncoding,
		base64.RawStdEncoding,
		base64.URLEncoding,
		base64.RawURLEncoding,
	} {
		if b, err := enc.DecodeString(raw); err == nil {
			if len(b) == 32 {
				return b, nil
			}
		}
	}
	return nil, errors.New("master key must be 32 bytes as raw string, base64, or hex")
}

// fingerprintOf returns the short fingerprint used for the mismatch guard.
// First 8 bytes of SHA-256, hex-encoded (16 hex chars).
func fingerprintOf(key []byte) string {
	sum := sha256.Sum256(key)
	return hex.EncodeToString(sum[:8])
}

// envelope is the on-disk shape of an encrypted _params value.
type envelope struct {
	V     int    `json:"v"`
	Alg   string `json:"alg"`
	Kid   string `json:"kid"`
	Nonce string `json:"nonce"`
	CT    string `json:"ct"`
}

// looksLikeEnvelope inspects raw bytes and returns true if they parse as a
// recognized v1 envelope. Anything else is treated as legacy plaintext.
func looksLikeEnvelope(raw []byte) (*envelope, bool) {
	trimmed := []byte(strings.TrimSpace(string(raw)))
	if len(trimmed) == 0 || trimmed[0] != '{' {
		return nil, false
	}
	var env envelope
	if err := json.Unmarshal(trimmed, &env); err != nil {
		return nil, false
	}
	if env.V != envelopeVersion || env.Alg != envelopeAlg || env.CT == "" || env.Nonce == "" {
		return nil, false
	}
	return &env, true
}

// deriveDEK computes the per-param data-encryption key from the master.
// The info string binds the DEK to (this plugin, a stable per-app context
// identifier, the param ID), so the same master used by two app instances
// still yields distinct DEKs per (app, param).
//
// ctxID is a stable per-app value (typically the UUID stored in
// oauth2_envelope_ctx_id). Previously this code passed app.DataDir() in
// place of ctxID, which silently broke decryption whenever the data
// directory was moved, renamed, accessed via a different relative path, or
// swapped onto a symlink. Migration callers may pass a legacy DataDir
// string to attempt decrypting envelopes sealed before the ctx-id switch;
// see openEnvelopeWithFallback.
func deriveDEK(master []byte, ctxID, paramID string) ([]byte, error) {
	info := []byte(hkdfInfoPrefix + ctxID + "/" + paramID)
	r := hkdf.New(sha256.New, master, nil, info)
	dek := make([]byte, 32)
	if _, err := io.ReadFull(r, dek); err != nil {
		return nil, errors.Wrap(err, "hkdf expand failed")
	}
	return dek, nil
}

// sealEnvelope encrypts plaintext under the DEK derived from master+ctxID
// and returns the JSON envelope bytes ready to store in _params.value. The
// envelope's Kid field is set to fingerprintOf(master) so a later loader
// holding a keyring can pick the right master for decryption.
func sealEnvelope(master []byte, ctxID, paramID string, plaintext []byte) ([]byte, error) {
	dek, err := deriveDEK(master, ctxID, paramID)
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(dek)
	if err != nil {
		return nil, errors.Wrap(err, "aes.NewCipher failed")
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, errors.Wrap(err, "cipher.NewGCM failed")
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, errors.Wrap(err, "nonce generation failed")
	}
	ct := gcm.Seal(nil, nonce, plaintext, nil)
	env := envelope{
		V:     envelopeVersion,
		Alg:   envelopeAlg,
		Kid:   fingerprintOf(master),
		Nonce: base64.StdEncoding.EncodeToString(nonce),
		CT:    base64.StdEncoding.EncodeToString(ct),
	}
	return json.Marshal(env)
}

// openEnvelope decrypts a v1 envelope using master+ctxID-derived DEK. We
// still verify the GCM auth tag, so a wrong key (or wrong ctxID) fails
// loudly here rather than silently producing garbage.
func openEnvelope(master []byte, ctxID, paramID string, env *envelope) ([]byte, error) {
	dek, err := deriveDEK(master, ctxID, paramID)
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(dek)
	if err != nil {
		return nil, errors.Wrap(err, "aes.NewCipher failed")
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, errors.Wrap(err, "cipher.NewGCM failed")
	}
	nonce, err := base64.StdEncoding.DecodeString(env.Nonce)
	if err != nil {
		return nil, errors.Wrap(err, "invalid nonce in envelope")
	}
	if len(nonce) != gcm.NonceSize() {
		return nil, fmt.Errorf("nonce length = %d, want %d", len(nonce), gcm.NonceSize())
	}
	ct, err := base64.StdEncoding.DecodeString(env.CT)
	if err != nil {
		return nil, errors.Wrap(err, "invalid ciphertext in envelope")
	}
	pt, err := gcm.Open(nil, nonce, ct, nil)
	if err != nil {
		return nil, errors.Wrap(err, "envelope decryption failed (wrong key or corrupted data)")
	}
	return pt, nil
}

// openEnvelopeWithKeyring decrypts using whichever master in the keyring
// matches env.Kid, with a fallback for envelopes whose ctxID was bound to
// the app's DataDir (the legacy v1 derivation, pre-15o fix). Returns the
// plaintext plus a needsRewrap flag set when the row should be re-sealed
// against (activeMaster, ctxID) — either because Kid pointed at a
// historical master (d9a) or because the legacy DataDir-derived DEK was
// what worked (15o).
//
// keyring must contain at least the active master. ctxID is the per-app
// stable context (UUID). legacyCtxID is the app's DataDir at call time,
// used only for the fallback attempt against pre-15o envelopes.
func openEnvelopeWithKeyring(
	keyring map[string][]byte,
	activeKid string,
	ctxID, legacyCtxID, paramID string,
	env *envelope,
) (plaintext []byte, needsRewrap bool, err error) {
	// First, try the master that this envelope advertises in Kid.
	if env.Kid != "" {
		if m, ok := keyring[env.Kid]; ok {
			if pt, oerr := openEnvelope(m, ctxID, paramID, env); oerr == nil {
				return pt, env.Kid != activeKid, nil
			}
			// Same master, but ctxID may have been bound to DataDir
			// before the 15o fix. Retry with legacyCtxID.
			if legacyCtxID != "" && legacyCtxID != ctxID {
				if pt, oerr := openEnvelope(m, legacyCtxID, paramID, env); oerr == nil {
					return pt, true, nil
				}
			}
		}
	}

	// Either Kid was empty (very old envelopes) or the Kid-lookup attempts
	// all failed. Fall through: brute-force the keyring, trying both the
	// current ctxID and the legacy one. This is bounded by the keyring
	// size which is expected to be 1-2 entries in practice.
	for kid, m := range keyring {
		if pt, oerr := openEnvelope(m, ctxID, paramID, env); oerr == nil {
			return pt, kid != activeKid || (env.Kid != "" && env.Kid != activeKid), nil
		}
		if legacyCtxID != "" && legacyCtxID != ctxID {
			if pt, oerr := openEnvelope(m, legacyCtxID, paramID, env); oerr == nil {
				return pt, true, nil
			}
		}
	}
	return nil, false, errors.New("envelope decryption failed for every keyring entry (wrong key, wrong context, or corrupted data)")
}
