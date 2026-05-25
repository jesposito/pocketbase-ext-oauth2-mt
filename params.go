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
	"github.com/pocketbase/dbx"
	"github.com/pocketbase/pocketbase/core"
	"github.com/pocketbase/pocketbase/tools/types"
)

const (
	paramsKeyOAuth2RSAKey         = "oauth2_rsa_key"
	paramsKeyOAuth2GlobalSecret   = "oauth2_global_secret"
	paramsKeyOAuth2EnvelopeCtxID  = "oauth2_envelope_ctx_id"
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

// resolveKeyring returns the full set of (kid → master) entries for
// decryption attempts. If the provider implements MasterKeyringProvider it
// supplies the set; otherwise the keyring is just the active master.
func resolveKeyring(ctx context.Context, p MasterKeyProvider) (map[string][]byte, error) {
	if kp, ok := p.(MasterKeyringProvider); ok {
		return kp.Keyring(ctx)
	}
	m, err := p.Master(ctx)
	if err != nil {
		return nil, err
	}
	if m == nil {
		return map[string][]byte{}, nil
	}
	return map[string][]byte{fingerprintOf(m): m}, nil
}

// getOrCreateEnvelopeContext returns the stable per-app context identifier
// used as HKDF info input. The value is a freshly-generated UUID persisted
// in the _params table on first call; subsequent calls return the stored
// value. The ID is intentionally divorced from app.DataDir() (the previous
// HKDF binding) because moving or symlinking the data directory would
// otherwise make existing envelopes undecryptable.
func getOrCreateEnvelopeContext(app core.App) (string, error) {
	param := &core.Param{}
	err := app.ModelQuery(param).Model(paramsKeyOAuth2EnvelopeCtxID, param)
	if err == nil {
		var stored string
		if uerr := json.Unmarshal(param.Value, &stored); uerr != nil {
			return "", errors.Wrap(uerr, "failed to parse stored envelope ctx id")
		}
		if stored == "" {
			return "", errors.New("stored envelope ctx id is empty")
		}
		return stored, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return "", errors.Wrap(err, "failed to query envelope ctx id")
	}
	// Generate and persist a new UUID.
	id := uuid.NewString()
	row := &core.Param{}
	row.Id = paramsKeyOAuth2EnvelopeCtxID
	row.Created = types.NowDateTime()
	row.Updated = row.Created
	row.Value = types.JSONRaw(`"` + id + `"`)
	if serr := app.Save(row); serr != nil {
		// Race: another caller inserted it between our query and save.
		// Re-read and return the winner's value.
		again := &core.Param{}
		if rerr := app.ModelQuery(again).Model(paramsKeyOAuth2EnvelopeCtxID, again); rerr == nil {
			var stored string
			if uerr := json.Unmarshal(again.Value, &stored); uerr == nil && stored != "" {
				return stored, nil
			}
		}
		return "", errors.Wrap(serr, "failed to persist envelope ctx id")
	}
	return id, nil
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
// fingerprint row exists, the stored fingerprint must match either the
// active master OR one of the keyring entries (a decrypt-only master
// retained across a rotation). On first run we record the active master's
// fingerprint. The row is lazily refreshed to the active fingerprint after
// a successful rotation read so subsequent loads stay in sync.
//
// Mismatch (no keyring entry matches) returns an error — refusing to load
// is the safe choice; silently decrypting to garbage corrupts downstream
// signing keys.
func verifyOrWriteFingerprint(app core.App, master []byte, provider MasterKeyProvider, ctx context.Context) error {
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
	if stored == expected {
		return nil
	}
	// Stored != active. Acceptable iff the stored fingerprint identifies a
	// keyring master (rotation in progress). Refresh the stored value to
	// the active fingerprint so future readers don't re-trigger this path.
	keyring, kerr := resolveKeyring(ctx, provider)
	if kerr != nil {
		return errors.Wrap(kerr, "failed to resolve keyring for fingerprint check")
	}
	if _, ok := keyring[stored]; !ok {
		return errors.New("OAUTH2_MASTER_KEY fingerprint mismatch -- refusing to decrypt with wrong key (stored=" + stored + ", env=" + expected + ")")
	}
	// Promote the fingerprint to the active master. CAS on the stored
	// bytes so two racing rotations don't fight.
	newValue := []byte(`"` + expected + `"`)
	if _, werr := updateParamValueCAS(app, fingerprintParamID, newValue, []byte(param.Value)); werr != nil {
		app.Logger().Warn("[Plugin/OAuth2] failed to promote master key fingerprint after rotation",
			"stored", stored, "active", expected, "err", werr)
	}
	return nil
}

// saveParamValue creates a brand-new _params row. The update path is split
// off into updateParamValueCAS so callers must explicitly carry the expected
// row.Updated through the read→compute→write cycle, eliminating the
// read-then-blind-overwrite race that loses concurrent updates.
func saveParamValue(app core.App, paramID string, raw []byte) error {
	row := &core.Param{}
	row.Id = paramID
	row.Created = types.NowDateTime()
	row.Updated = row.Created
	row.Value = types.JSONRaw(raw)
	return app.Save(row)
}

// updateParamValueCAS does a compare-and-swap UPDATE on a _params row. It
// only writes if the row's `value` column still equals expectedValue — the
// bytes the caller observed before computing the new payload. Returns
// (true, nil) on a successful swap, (false, nil) when the CAS lost (a
// concurrent writer mutated the row first — the caller decides whether to
// retry or accept the other writer's state), or (_, err) on a database
// failure.
//
// Value-based, not timestamp-based: types.DateTime has millisecond
// resolution and two writers can land in the same millisecond, in which
// case a timestamp CAS silently last-writer-wins. Comparing the value bytes
// the caller actually observed is the precise invariant.
//
// Mirrors the markRefreshRotated pattern in storage.go so concurrent
// migrations or rotations of a single _params row cannot silently overwrite
// each other.
func updateParamValueCAS(app core.App, paramID string, raw []byte, expectedValue []byte) (bool, error) {
	nowDT := types.NowDateTime()
	result, err := app.DB().NewQuery(
		"UPDATE {{_params}} " +
			"SET [[value]] = {:value}, [[updated]] = {:updated} " +
			"WHERE [[id]] = {:id} AND [[value]] = {:expected}").
		Bind(dbx.Params{
			"value":    string(raw),
			"updated":  nowDT.String(),
			"id":       paramID,
			"expected": string(expectedValue),
		}).Execute()
	if err != nil {
		return false, errors.Wrap(err, "failed to CAS-update _params row")
	}
	n, err := result.RowsAffected()
	if err != nil {
		return false, errors.Wrap(err, "failed to read CAS rows affected")
	}
	return n > 0, nil
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

	if err := verifyOrWriteFingerprint(app, master, provider, ctx); err != nil {
		return zero, err
	}

	// Per-app encryption context: a stable UUID stored in _params and used
	// as HKDF info input instead of app.DataDir(). Only needed when
	// encryption is active.
	ctxID := ""
	if master != nil {
		ctxID, err = getOrCreateEnvelopeContext(app)
		if err != nil {
			return zero, err
		}
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
			stored, err = sealEnvelope(master, ctxID, paramId, plaintext)
			if err != nil {
				return zero, errors.Wrap(err, "failed to seal envelope")
			}
		}
		if err := saveParamValue(app, paramId, stored); err != nil {
			// Race: another writer inserted the row between our SELECT
			// and INSERT. Read the winner's value and return that — both
			// writers were generating equivalent freshly-random material,
			// so the loser silently adopting the winner is safe and gives
			// the loop above idempotent first-write semantics.
			recovered := &core.Param{}
			if rErr := app.ModelQuery(recovered).Model(paramId, recovered); rErr == nil {
				return loadDecodedParam(ctx, provider, master, app.DataDir(), ctxID, paramId, recovered, value)
			}
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
		// Multi-key + legacy-ctxID-aware decrypt. Returns needsRewrap
		// when the envelope was sealed with a non-active master (d9a) or
		// with the legacy DataDir-bound HKDF info (15o); in either case
		// we re-seal with (active master, ctxID) on the next CAS.
		keyring, kerr := resolveKeyring(ctx, provider)
		if kerr != nil {
			return zero, errors.Wrap(kerr, "failed to resolve master keyring")
		}
		activeKid := fingerprintOf(master)
		plaintext, needsRewrap, oerr := openEnvelopeWithKeyring(
			keyring, activeKid, ctxID, app.DataDir(), paramId, env,
		)
		if oerr != nil {
			return zero, oerr
		}
		if needsRewrap {
			if resealed, sErr := sealEnvelope(master, ctxID, paramId, plaintext); sErr == nil {
				if _, wErr := updateParamValueCAS(app, paramId, resealed, raw); wErr != nil {
					app.Logger().Warn("[Plugin/OAuth2] failed to rewrap envelope under active master",
						"param", paramId, "err", wErr)
				}
			}
		}
		return decodePlaintext(plaintext, value)
	}

	// Legacy plaintext path.
	decoded, err := decodePlaintext(raw, value)
	if err != nil {
		return zero, err
	}
	// Migration: if a master is configured, transparently rewrite the
	// row as an envelope. CAS on the observed `raw` value bytes ensures
	// concurrent writers cannot last-writer-wins each other.
	if master != nil {
		plaintext, err := encodePlaintext(decoded)
		if err == nil {
			if sealed, sErr := sealEnvelope(master, ctxID, paramId, plaintext); sErr == nil {
				if _, wErr := updateParamValueCAS(app, paramId, sealed, raw); wErr != nil {
					app.Logger().Warn("[Plugin/OAuth2] failed to migrate plaintext param to envelope", "param", paramId, "err", wErr)
				}
			}
		}
	}
	return decoded, nil
}

// loadDecodedParam decodes a freshly-read _params row into T, applying the
// envelope-vs-plaintext detection plus the multi-key keyring decrypt path.
// Extracted so the create-race recovery branch in loadParamFromAppStorage
// can decode whichever value the winning racer wrote.
func loadDecodedParam[T any](
	ctx context.Context,
	provider MasterKeyProvider,
	master []byte,
	dataDir, ctxID, paramID string,
	param *core.Param,
	value T,
) (T, error) {
	var zero T
	raw := []byte(param.Value)
	if env, isEnv := looksLikeEnvelope(raw); isEnv {
		if master == nil {
			return zero, errors.New("encrypted _params row found but OAUTH2_MASTER_KEY is unset")
		}
		keyring, kerr := resolveKeyring(ctx, provider)
		if kerr != nil {
			return zero, errors.Wrap(kerr, "failed to resolve master keyring")
		}
		activeKid := fingerprintOf(master)
		plaintext, _, oerr := openEnvelopeWithKeyring(keyring, activeKid, ctxID, dataDir, paramID, env)
		if oerr != nil {
			return zero, oerr
		}
		return decodePlaintext(plaintext, value)
	}
	return decodePlaintext(raw, value)
}
