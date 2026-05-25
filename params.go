package oauth2

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"database/sql"
	"encoding/hex"
	"encoding/json"

	"github.com/go-jose/go-jose/v3"
	"github.com/google/uuid"
	"github.com/pkg/errors"
	"github.com/pocketbase/pocketbase/core"
	"github.com/pocketbase/pocketbase/tools/types"
)

const (
	paramsKeyOAuth2RSAKey       = "oauth2_rsa_key"
	paramsKeyOAuth2GlobalSecret = "oauth2_global_secret"
)

// activeMasterKeyProvider returns the provider configured on the registered
// Instance for this app, falling back to the default env-backed provider
// when the instance is absent (tests that call loadParam* directly without
// going through Register, or first-boot edge cases).
func activeMasterKeyProvider(app core.App) MasterKeyProvider {
	if inst, ok := getInstance(app); ok && inst.cfg != nil && inst.cfg.MasterKeyProvider != nil {
		return inst.cfg.MasterKeyProvider
	}
	return DefaultMasterKeyProvider
}

// loadPrivateKeyFromAppStorage loads the private JSON-Web-Key from the app storage or generates
// a new one if it doesn't exist. The key is used for signing the OpenID Connect ID tokens and
// other related operations. The key is stored in the internal app _params table to ensure it
// persists across application restarts.
func loadPrivateKeyFromAppStorage(app core.App) (*jose.JSONWebKey, error) {
	return loadParamFromAppStorage(app, paramsKeyOAuth2RSAKey, &jose.JSONWebKey{}, func() (*jose.JSONWebKey, error) {
		// No existing key found, generate a new one
		privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			return nil, errors.Wrap(err, "failed to generate new RSA key")
		}
		// Build the JWK from the generated private key
		return &jose.JSONWebKey{
			Key:       privateKey,
			KeyID:     uuid.NewString(),
			Algorithm: string(jose.RS256),
			Use:       "sig",
		}, nil
	})
}

// loadGlobalSecretFromAppStorage loads the global secret from the app storage or generates
// a new one if it doesn't exist. The global secret is used for various cryptographic operations
// within the OAuth2 plugin, such as signing tokens, etc.
func loadGlobalSecretFromAppStorage(app core.App) ([]byte, error) {
	return loadParamFromAppStorage(app, paramsKeyOAuth2GlobalSecret, []byte{}, func() ([]byte, error) {
		// No existing secret found, generate a new one
		ret := make([]byte, 32)
		if _, err := rand.Read(ret); err != nil {
			return nil, err
		}
		return ret, nil
	})
}

//

// encodePlaintext renders a value into its on-disk plaintext representation.
// Mirrors the legacy switch in loadParamFromAppStorage: byte slices are
// hex-encoded; everything else is JSON.
func encodePlaintext[T any](value T) ([]byte, error) {
	switch v := any(value).(type) {
	case []byte:
		return hex.AppendEncode([]byte{}, v), nil
	default:
		b, err := json.Marshal(value)
		if err != nil {
			return nil, errors.Wrap(err, "failed to marshal value")
		}
		return b, nil
	}
}

// decodePlaintext inverts encodePlaintext.
func decodePlaintext[T any](raw []byte, value T) (T, error) {
	var zero T
	switch any(value).(type) {
	case []byte:
		decoded, err := hex.DecodeString(string(raw))
		if err != nil {
			return zero, errors.Wrap(err, "failed to decode value")
		}
		return any(decoded).(T), nil
	default:
		if err := json.Unmarshal(raw, &value); err != nil {
			return zero, errors.Wrap(err, "failed to unmarshal value")
		}
		return value, nil
	}
}

// verifyOrWriteFingerprint enforces the master-key consistency check. If a
// fingerprint row exists, it must match the active master. If it doesn't
// exist, this is a first-time write and we record the current fingerprint.
// Returns an error if the env-configured master disagrees with the row that
// previous runs wrote -- this prevents the "wrong key silently decrypts to
// garbage" footgun.
func verifyOrWriteFingerprint(app core.App, master []byte) error {
	if master == nil {
		// Plaintext mode -- nothing to verify, and we don't proactively
		// remove an existing fingerprint row either. Operators who
		// rotate from "encrypted" back to "plaintext" should clear
		// rows by hand.
		return nil
	}
	expected := fingerprintOf(master)
	param := &core.Param{}
	err := app.ModelQuery(param).Model(fingerprintParamID, param)
	if err != nil {
		if !errors.Is(err, sql.ErrNoRows) {
			return errors.Wrap(err, "failed to query master key fingerprint")
		}
		// First run with encryption enabled: record the fingerprint.
		row := &core.Param{}
		row.Id = fingerprintParamID
		row.Created = types.NowDateTime()
		row.Updated = row.Created
		row.Value = types.JSONRaw(`"` + expected + `"`)
		if err := app.Save(row); err != nil {
			return errors.Wrap(err, "failed to persist master key fingerprint")
		}
		return nil
	}
	var stored string
	if err := json.Unmarshal(param.Value, &stored); err != nil {
		return errors.Wrap(err, "failed to parse stored master key fingerprint")
	}
	if stored != expected {
		return errors.New("OAUTH2_MASTER_KEY fingerprint mismatch -- refusing to decrypt with wrong key (stored=" + stored + ", env=" + expected + ")")
	}
	return nil
}

// saveParamValue writes raw bytes into a _params row, creating or updating.
func saveParamValue(app core.App, paramID string, raw []byte, created bool) error {
	row := &core.Param{}
	if !created {
		// Update path: re-fetch so we preserve created timestamp and
		// satisfy PocketBase's "must exist" semantics on update.
		err := app.ModelQuery(row).Model(paramID, row)
		if err != nil {
			return errors.Wrap(err, "failed to reload param for update")
		}
		row.Value = types.JSONRaw(raw)
		row.Updated = types.NowDateTime()
		return app.Save(row)
	}
	row.Id = paramID
	row.Created = types.NowDateTime()
	row.Updated = row.Created
	row.Value = types.JSONRaw(raw)
	return app.Save(row)
}

// loadParamFromAppStorage is a generic helper that loads a parameter from
// the _params table, generating and persisting it if absent. When the
// OAUTH2_MASTER_KEY env (or a Config.MasterKeyProvider) supplies a master
// key, values are stored as v1 AES-256-GCM envelopes; otherwise they are
// stored as legacy plaintext (JSON for structured values, hex for []byte).
//
// Migration semantics:
//   - Existing plaintext rows are decoded as plaintext on load. If the
//     master is configured, the row is rewritten as an envelope on the
//     next successful load (read-once, rewrite-once, idempotent).
//   - Existing envelope rows are decrypted on load. If the master is
//     unset, this returns an error -- you cannot read encrypted data
//     without the key that produced it.
func loadParamFromAppStorage[T any](app core.App, paramId string, value T, generator func() (T, error)) (T, error) {
	var zero T

	provider := activeMasterKeyProvider(app)
	ctx := context.Background()
	master, err := provider.Master(ctx)
	if err != nil {
		return zero, errors.Wrap(err, "failed to load master key")
	}

	if err := verifyOrWriteFingerprint(app, master); err != nil {
		return zero, err
	}

	param := &core.Param{}
	err = app.ModelQuery(param).Model(paramId, param)
	if err != nil {
		if !errors.Is(err, sql.ErrNoRows) {
			return zero, errors.Wrap(err, "failed to query db")
		}
		// No existing value: generate, then store (encrypted if
		// master is set, plaintext otherwise).
		newValue, err := generator()
		if err != nil {
			return zero, errors.Wrap(err, "failed to generate new value")
		}
		plaintext, err := encodePlaintext(newValue)
		if err != nil {
			return zero, err
		}
		stored := plaintext
		if master != nil {
			stored, err = sealEnvelope(master, app.DataDir(), paramId, plaintext)
			if err != nil {
				return zero, errors.Wrap(err, "failed to seal envelope")
			}
		}
		if err := saveParamValue(app, paramId, stored, true); err != nil {
			return zero, errors.Wrap(err, "failed to save value")
		}
		return newValue, nil
	}

	// Existing row. Detect envelope vs. legacy plaintext.
	raw := []byte(param.Value)
	env, isEnv := looksLikeEnvelope(raw)
	if isEnv {
		if master == nil {
			return zero, errors.New("encrypted _params row found but OAUTH2_MASTER_KEY is unset")
		}
		plaintext, err := openEnvelope(master, app.DataDir(), paramId, env)
		if err != nil {
			return zero, err
		}
		return decodePlaintext(plaintext, value)
	}

	// Legacy plaintext path.
	decoded, err := decodePlaintext(raw, value)
	if err != nil {
		return zero, err
	}
	// Migration: if a master is configured, transparently rewrite the
	// row as an envelope. Failure to migrate is logged but does not
	// fail the load -- the next call will try again.
	if master != nil {
		plaintext, err := encodePlaintext(decoded)
		if err == nil {
			if sealed, sErr := sealEnvelope(master, app.DataDir(), paramId, plaintext); sErr == nil {
				if wErr := saveParamValue(app, paramId, sealed, false); wErr != nil {
					app.Logger().Warn("[Plugin/OAuth2] failed to migrate plaintext param to envelope", "param", paramId, "err", wErr)
				}
			}
		}
	}
	return decoded, nil
}
