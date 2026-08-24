package oauth2

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/ory/fosite"
	"github.com/pocketbase/pocketbase/core"
)

// AccessTokenAuthority is the deliberately constrained attestation returned
// for a live OAuth access token. It exposes only the identities an embedding
// application needs to bind its own authorization policy; it exposes no key,
// secret, signature, request id, or token-minting capability.
type AccessTokenAuthority struct {
	ProviderPrefix string
	ClientID       string
	SubjectID      string
	UserCollection string
	ExpiresAt      time.Time
}

// ValidateAccessTokenAuthorityAt verifies a PocketBase-backed OAuth access
// token against one exact registered provider plane and its persistent access
// session. Deleted/revoked/expired rows, deleted clients, subject or collection
// mismatches, and unknown prefixes all fail closed.
func ValidateAccessTokenAuthorityAt(ctx context.Context, app core.App, prefix, rawToken string) (*AccessTokenAuthority, error) {
	if ctx == nil {
		return nil, errors.New("context is required")
	}
	prefix = normalizePrefix(prefix)
	inst, ok := getInstanceAt(app, prefix)
	if !ok || inst.store == nil {
		return nil, fmt.Errorf("OAuth provider is not initialized at prefix %q", prefix)
	}
	auth, err := app.FindAuthRecordByToken(rawToken, core.TokenTypeAuth)
	if err != nil {
		return nil, fmt.Errorf("invalid access token: %w", err)
	}
	parts := strings.Split(rawToken, ".")
	if len(parts) != 3 || parts[2] == "" {
		return nil, fosite.ErrInvalidTokenFormat
	}
	row, err := findSessionModelBySignature(app, prefix, &AccessTokenModel{}, parts[2])
	if err != nil {
		if errors.Is(err, fosite.ErrNotFound) {
			return nil, fosite.ErrInactiveToken
		}
		return nil, err
	}
	// Refresh-family terminal authority is committed independently of best-
	// effort row cleanup. A cleanup rollback may leave this access record
	// physically present, so every public validation path must consult the
	// same provider-scoped tombstone used by the Fosite storage adapter.
	if err := assertRefreshFamilyAllowsAccess(app, prefix, row.GetRequestID()); err != nil {
		return nil, err
	}
	expiresAt := row.GetExpiresAt()
	if expiresAt == nil || !expiresAt.After(time.Now()) {
		return nil, fosite.ErrInactiveToken
	}
	if row.GetSubject() == "" || row.GetSubject() != auth.Id {
		return nil, errors.New("access-token subject attestation mismatch")
	}
	if inst.cfg == nil || inst.cfg.UserCollection == "" || auth.Collection().Name != inst.cfg.UserCollection {
		return nil, errors.New("access-token provider-plane collection mismatch")
	}
	var session Session
	if err := json.Unmarshal(row.GetSessionData(), &session); err != nil {
		return nil, fmt.Errorf("invalid access-token session: %w", err)
	}
	if session.CollectionId == "" || session.CollectionId != auth.Collection().Id {
		return nil, errors.New("access-token collection attestation mismatch")
	}
	if _, err := inst.store.GetClient(ctx, row.GetClientID()); err != nil {
		return nil, fmt.Errorf("access-token client is not live in provider %q: %w", prefix, err)
	}
	return &AccessTokenAuthority{
		ProviderPrefix: prefix,
		ClientID:       row.GetClientID(),
		SubjectID:      auth.Id,
		UserCollection: auth.Collection().Name,
		ExpiresAt:      *expiresAt,
	}, nil
}
