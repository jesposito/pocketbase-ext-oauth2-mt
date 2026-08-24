package oauth2

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/ory/fosite"
	fositeoauth2 "github.com/ory/fosite/handler/oauth2"
	fositeopenid "github.com/ory/fosite/handler/openid"
	fositepkce "github.com/ory/fosite/handler/pkce"

	"github.com/jesposito/pocketbase-ext-oauth2-mt/consts"
	"github.com/pocketbase/dbx"
	"github.com/pocketbase/pocketbase/core"
)

//

type OAuth2Store struct {
	app    core.App
	prefix string
}

func NewOAuth2Store(app core.App) *OAuth2Store {
	return NewOAuth2StoreAt(app, DefaultPathPrefix)
}

func NewOAuth2StoreAt(app core.App, prefix string) *OAuth2Store {
	return &OAuth2Store{
		app: app, prefix: normalizePrefix(prefix),
	}
}

// https://github.com/ory/hydra/blob/master/persistence/sql/persister_oauth2.go#L571

// GetClient implements [fosite.ClientManager].
func (s *OAuth2Store) GetClient(ctx context.Context, id string) (fosite.Client, error) {
	m := &ClientModel{}
	c, err := s.app.FindCachedCollectionByNameOrId(consts.ClientCollectionName)
	if err != nil {
		c = core.NewBaseCollection("@__invalid__")
	}
	err = s.app.RecordQuery(c).
		AndWhere(dbx.HashExp{"client_id": id}).
		AndWhere(providerPrefixExp(s.app, s.prefix)).
		One(m)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, fosite.ErrNotFound
		}
		return nil, err
	}
	return m.ToClient()
}

// RegisterClient implements [RFC7591ClientStorage].
func (s *OAuth2Store) RegisterClient(ctx context.Context, client *RFC7591ClientMetadataRequest) (fosite.Client, string, error) {
	return NewClientFromRFC7591MetadataAt(s.app, s.prefix, client)
}

// ClientAssertionJWTValid implements [fosite.ClientManager].
func (s *OAuth2Store) ClientAssertionJWTValid(ctx context.Context, jti string) error {
	return hasJTIModel(s.app, s.prefix, jti)
}

// SetClientAssertionJWT implements [fosite.ClientManager].
func (s *OAuth2Store) SetClientAssertionJWT(ctx context.Context, jti string, exp time.Time) error {
	return newJTIModel(s.app, s.prefix, jti, exp)
}

// CreateAuthorizeCodeSession implements [oauth2.AuthorizeCodeStorage].
func (s *OAuth2Store) CreateAuthorizeCodeSession(ctx context.Context, code string, request fosite.Requester) (err error) {
	m := newSessionModel(s.app, &AuthCodeModel{})
	m.Set("provider_prefix", s.prefix)
	m.SetSignature(code)
	if err := m.SetRequester(request, fosite.AuthorizeCode); err != nil {
		return err
	}

	return s.app.Save(m)
}

// GetAuthorizeCodeSession implements [oauth2.AuthorizeCodeStorage].
func (s *OAuth2Store) GetAuthorizeCodeSession(ctx context.Context, code string, session fosite.Session) (request fosite.Requester, err error) {
	m, err := findSessionModelBySignature(s.app, s.prefix, &AuthCodeModel{}, code)
	if err != nil {
		return nil, err
	}

	req, err := m.ToRequest(ctx, s, session)
	if err != nil {
		return nil, err
	}

	if err := hasJTIModel(s.app, s.prefix, code); err != nil {
		if errors.Is(err, fosite.ErrJTIKnown) {
			return req, fosite.ErrInvalidatedAuthorizeCode
		} else {
			return req, fosite.ErrServerError.WithWrap(err).WithDebug("Failed to check if the authorization code has been invalidated")
		}
	}

	return req, nil
}

// InvalidateAuthorizeCodeSession implements [oauth2.AuthorizeCodeStorage].
func (s *OAuth2Store) InvalidateAuthorizeCodeSession(ctx context.Context, code string) (err error) {
	m, err := findSessionModelBySignature(s.app, s.prefix, &AuthCodeModel{}, code)
	if err != nil {
		if errors.Is(err, fosite.ErrNotFound) {
			return nil // if the session is not found, we can consider it already deleted and return no error
		}
		return err
	}
	expiresAt := m.GetExpiresAt()
	if expiresAt == nil {
		return errors.New("authorization code session has no expiry")
	}
	return newJTIModel(s.app, s.prefix, code, *expiresAt)
}

// CreateAccessTokenSession implements [oauth2.AccessTokenStorage].
func (s *OAuth2Store) CreateAccessTokenSession(ctx context.Context, signature string, request fosite.Requester) (err error) {
	return s.app.RunInTransaction(func(txApp core.App) error {
		terminal, err := hasRefreshTerminalAuthority(txApp, s.prefix, request.GetID())
		if err != nil {
			return fosite.ErrServerError.WithWrap(err).WithDebug("failed to read terminal refresh-family authority before access issuance")
		}
		if terminal {
			return fosite.ErrInactiveToken
		}
		m := newSessionModel(txApp, &AccessTokenModel{})
		m.Set("provider_prefix", s.prefix)
		m.SetSignature(signature)
		if err := m.SetRequester(request, fosite.AccessToken); err != nil {
			return err
		}
		return txApp.Save(m)
	})
}

// CreateRefreshTokenSession implements [oauth2.RefreshTokenStorage].
//
// Family-tracking behavior:
//   - On an authorization_code-grant issuance (chain root), a fresh
//     family_id is generated and parent_refresh_id is left empty.
//   - On a refresh_token-grant rotation, the predecessor row (already
//     marked status=rotated by RotateRefreshToken) is located by request_id
//     and the new row inherits its family_id with parent_refresh_id set to
//     the predecessor's record id.
//   - status defaults to active.
func (s *OAuth2Store) CreateRefreshTokenSession(ctx context.Context, signature string, accessSignature string, request fosite.Requester) (err error) {
	var abortErr error
	err = s.app.RunInTransaction(func(txApp core.App) error {
		m := newSessionModel(txApp, &RefreshTokenModel{})
		m.Set("provider_prefix", s.prefix)
		m.SetSignature(signature)
		if err := m.SetRequester(request, fosite.RefreshToken); err != nil {
			return err
		}

		familyID, parentID, lineageErr := s.resolveRefreshLineage(txApp, request)
		if lineageErr != nil {
			// Fosite creates the replacement access row between Rotate and
			// CreateRefreshTokenSession. If terminal family authority won that
			// gap, commit removal of the otherwise-orphaned access row before
			// returning the inactive-token error. A non-terminal duplicate only
			// owns its exact candidate access signature; do not delete the
			// legitimate winner's access row.
			if errors.Is(lineageErr, fosite.ErrInactiveToken) {
				if cleanupErr := deleteSessionModelsByRequestID(txApp, s.prefix, &AccessTokenModel{}, request.GetID()); cleanupErr != nil {
					return fosite.ErrServerError.WithWrap(cleanupErr).WithDebug("failed to remove access rows after terminal refresh-family state")
				}
			} else if accessSignature != "" {
				if cleanupErr := deleteSessionModelBySignature(txApp, s.prefix, &AccessTokenModel{}, accessSignature); cleanupErr != nil {
					return fosite.ErrServerError.WithWrap(cleanupErr).WithDebug("failed to remove rejected refresh replacement access row")
				}
			}
			abortErr = lineageErr
			return nil
		}
		m.SetFamilyID(familyID)
		m.SetParentRefreshID(parentID)
		m.SetStatus(RefreshStatusActive)
		m.SetRotatedAt(0)
		m.SetReusedAt(0)

		return txApp.Save(m)
	})
	if err != nil {
		return err
	}
	return abortErr
}

// resolveRefreshLineage decides the family_id and parent_refresh_id for a
// newly created refresh row. The fosite refresh-grant handler calls
// RotateRefreshToken before CreateRefreshTokenSession and propagates the
// original request id (see fosite/handler/oauth2/flow_refresh.go), so the
// predecessor row is the one with the same request_id that we just marked
// rotated. A root is allowed only when that provider prefix has no row at all
// for the non-empty request id; terminal and corrupt history fail closed.
func (s *OAuth2Store) resolveRefreshLineage(app core.App, request fosite.Requester) (familyID string, parentRefreshID string, err error) {
	requestID := request.GetID()
	if requestID == "" {
		return "", "", errors.New("refresh request has no request_id")
	}
	terminal, err := hasRefreshTerminalAuthority(app, s.prefix, requestID)
	if err != nil {
		return "", "", err
	}
	if terminal {
		return "", "", fosite.ErrInactiveToken
	}
	c, err := app.FindCachedCollectionByNameOrId(consts.RefreshCollectionName)
	if err != nil {
		return "", "", err
	}
	var rows []*RefreshTokenModel
	err = app.RecordQuery(c).
		AndWhere(dbx.HashExp{"request_id": requestID}).
		AndWhere(providerPrefixExp(app, s.prefix)).
		OrderBy("rotated_at DESC", "id DESC").
		All(&rows)
	if err != nil {
		return "", "", err
	}
	if len(rows) == 0 {
		return uuid.NewString(), "", nil
	}

	// A request id is a refresh-family authority, not permission to mint
	// another root. Every row must attest one family and only the most
	// recently rotated row may parent a replacement. Terminal or corrupt
	// state wins over every rotated breadcrumb, independent of row order.
	var parent *RefreshTokenModel
	terminalRow := false
	active := false
	var corruptErr error
	for _, row := range rows {
		if row.GetFamilyID() == "" {
			corruptErr = errors.New("refresh-family row has no family_id")
		} else if familyID == "" {
			familyID = row.GetFamilyID()
		} else if familyID != row.GetFamilyID() {
			corruptErr = errors.New("request_id spans multiple refresh families")
		}
		switch row.GetStatus() {
		case RefreshStatusReused, RefreshStatusRevoked:
			terminalRow = true
		case RefreshStatusRotated:
			if parent == nil {
				parent = row
			}
		case RefreshStatusActive:
			active = true
		default:
			corruptErr = errors.New("refresh-family row has an invalid status")
		}
	}
	if terminalRow {
		return "", "", fosite.ErrInactiveToken
	}
	if corruptErr != nil {
		return "", "", corruptErr
	}
	if active {
		return "", "", fosite.ErrSerializationFailure.WithDebug(
			"request already has an active refresh token")
	}
	if parent == nil {
		return "", "", errors.New("refresh-family request has no rotated predecessor")
	}
	return familyID, parent.GetID(), nil
}

// DeleteAccessTokenSession implements [oauth2.AccessTokenStorage].
func (s *OAuth2Store) DeleteAccessTokenSession(ctx context.Context, signature string) (err error) {
	return deleteSessionModelBySignature(s.app, s.prefix, &AccessTokenModel{}, signature)
}

// DeleteRefreshTokenSession implements [oauth2.RefreshTokenStorage].
func (s *OAuth2Store) DeleteRefreshTokenSession(ctx context.Context, signature string) (err error) {
	m, err := findSessionModelBySignature(s.app, s.prefix, &RefreshTokenModel{}, signature)
	if err != nil {
		if errors.Is(err, fosite.ErrNotFound) {
			return nil
		}
		return err
	}
	// Fosite calls DeleteRefreshTokenSession after GetRefreshTokenSession
	// reports reuse. Physically deleting that terminal row in the winner's
	// Rotate -> Create gap erases the only family authority and permits the
	// winner to create a fresh root. Keep terminal rows as tombstones; expiry
	// cleanup owns their eventual removal. Active rows retain the historical
	// direct-delete behavior.
	if m.GetStatus() == RefreshStatusReused || m.GetStatus() == RefreshStatusRevoked {
		return nil
	}
	return s.app.Delete(m.ProxyRecord())
}

// GetAccessTokenSession implements [oauth2.AccessTokenStorage].
func (s *OAuth2Store) GetAccessTokenSession(ctx context.Context, signature string, session fosite.Session) (request fosite.Requester, err error) {
	m, err := findSessionModelBySignature(s.app, s.prefix, &AccessTokenModel{}, signature)
	if err != nil {
		return nil, err
	}
	if err := assertRefreshFamilyAllowsAccess(s.app, s.prefix, m.GetRequestID()); err != nil {
		return nil, err
	}

	return m.ToRequest(ctx, s, session)
}

// GetRefreshTokenSession implements [oauth2.RefreshTokenStorage].
//
// Reuse detection: if the row exists but its status is not "active" the
// token is being replayed. We invalidate every row in the same family
// (status=reused, reused_at=now) and delete every access token issued
// against any row in the family, then return fosite.ErrInactiveToken so
// the upstream refresh-grant handler treats it as reuse per RFC 6819
// section 5.2.2.3.
func (s *OAuth2Store) GetRefreshTokenSession(ctx context.Context, signature string, session fosite.Session) (request fosite.Requester, err error) {
	m, err := findSessionModelBySignature(s.app, s.prefix, &RefreshTokenModel{}, signature)
	if err != nil {
		return nil, err
	}
	terminal, err := hasRefreshTerminalAuthority(s.app, s.prefix, m.GetRequestID())
	if err != nil {
		return nil, fosite.ErrServerError.WithWrap(err).WithDebug("failed to read terminal refresh-family authority")
	}
	if terminal {
		req, reqErr := m.ToRequest(ctx, s, session)
		if reqErr != nil {
			return nil, fosite.ErrServerError.WithWrap(reqErr).WithDebug("invalid terminal refresh session")
		}
		return req, fosite.ErrInactiveToken
	}

	if m.GetStatus() != RefreshStatusActive {
		req, reqErr := m.ToRequest(ctx, s, session)
		expiresAt := int64(0)
		if expiry := m.GetExpiresAt(); expiry != nil {
			expiresAt = expiry.Unix()
		}
		if authorityErr := commitRefreshTerminalAuthority(
			s.app, s.prefix, m.GetRequestID(), m.GetFamilyID(), expiresAt,
		); authorityErr != nil {
			return nil, fosite.ErrServerError.WithWrap(authorityErr).WithDebug("failed to commit reused refresh-family authority")
		}
		if familyID := m.GetFamilyID(); familyID != "" {
			if ierr := invalidateRefreshFamily(s.app, s.prefix, familyID); ierr != nil {
				return nil, fosite.ErrServerError.WithWrap(ierr).WithDebug("failed to invalidate reused refresh family")
			}
		} else if ierr := invalidateLegacyRefreshRow(s.app, s.prefix, m); ierr != nil {
			return nil, fosite.ErrServerError.WithWrap(ierr).WithDebug("failed to invalidate legacy reused refresh token")
		}
		if reqErr != nil {
			return nil, fosite.ErrServerError.WithWrap(reqErr).WithDebug("invalid reused refresh session")
		}
		return req, fosite.ErrInactiveToken
	}

	return m.ToRequest(ctx, s, session)
}

// RevokeAccessToken implements [oauth2.AccessTokenStorage].
func (s *OAuth2Store) RevokeAccessToken(ctx context.Context, requestID string) error {
	return deleteSessionModelsByRequestID(s.app, s.prefix, &AccessTokenModel{}, requestID)
}

// RevokeRefreshToken implements [oauth2.TokenRevocationStorage].
//
// The row is marked status=revoked instead of being deleted so a later
// replay of the same signature is still caught as reuse against the
// family breadcrumb. The cleanup cron deletes the row eventually via
// expires_at.
func (s *OAuth2Store) RevokeRefreshToken(ctx context.Context, requestID string) error {
	if err := commitRefreshTerminalAuthority(s.app, s.prefix, requestID, "", 0); err != nil {
		return err
	}
	return revokeRefreshFamilyByRequestID(s.app, s.prefix, requestID)
}

// RotateRefreshToken implements [oauth2.RefreshTokenStorage].
//
// Marks the predecessor refresh row as rotated (keeping the family
// breadcrumb for reuse detection) and deletes the predecessor access
// token by request_id. The replacement refresh row is created by the
// upstream handler in a follow-up CreateRefreshTokenSession call.
func (s *OAuth2Store) RotateRefreshToken(ctx context.Context, requestID string, refreshTokenSignature string) (err error) {
	if err := markRefreshRotated(s.app, s.prefix, requestID, refreshTokenSignature); err != nil {
		if errors.Is(err, fosite.ErrInactiveToken) {
			if cleanupErr := deleteSessionModelsByRequestID(s.app, s.prefix, &AccessTokenModel{}, requestID); cleanupErr != nil {
				return fosite.ErrServerError.WithWrap(cleanupErr).WithDebug("failed to remove access rows for inactive refresh rotation")
			}
		}
		return err
	}
	return deleteSessionModelsByRequestID(s.app, s.prefix, &AccessTokenModel{}, requestID)
}

// CreatePKCERequestSession implements [pkce.PKCERequestStorage].
func (s *OAuth2Store) CreatePKCERequestSession(ctx context.Context, signature string, requester fosite.Requester) error {
	m := newSessionModel(s.app, &PKCEModel{})
	m.Set("provider_prefix", s.prefix)
	m.SetSignature(signature)
	if err := m.SetRequester(requester, ""); err != nil {
		return err
	}

	return s.app.Save(m)
}

// DeletePKCERequestSession implements [pkce.PKCERequestStorage].
func (s *OAuth2Store) DeletePKCERequestSession(ctx context.Context, signature string) error {
	return deleteSessionModelBySignature(s.app, s.prefix, &PKCEModel{}, signature)
}

// GetPKCERequestSession implements [pkce.PKCERequestStorage].
func (s *OAuth2Store) GetPKCERequestSession(ctx context.Context, signature string, session fosite.Session) (fosite.Requester, error) {
	m, err := findSessionModelBySignature(s.app, s.prefix, &PKCEModel{}, signature)
	if err != nil {
		return nil, err
	}

	return m.ToRequest(ctx, s, session)
}

// CreateOpenIDConnectSession implements [openid.OpenIDConnectRequestStorage].
func (s *OAuth2Store) CreateOpenIDConnectSession(ctx context.Context, authorizeCode string, requester fosite.Requester) error {
	m := newSessionModel(s.app, &OpenIDConnectSessionModel{})
	m.Set("provider_prefix", s.prefix)
	m.SetSignature(authorizeCode)
	if err := m.SetRequester(requester, fosite.IDToken); err != nil {
		return err
	}

	return s.app.Save(m)
}

// DeleteOpenIDConnectSession implements [openid.OpenIDConnectRequestStorage].
func (s *OAuth2Store) DeleteOpenIDConnectSession(ctx context.Context, authorizeCode string) error {
	return deleteSessionModelBySignature(s.app, s.prefix, &OpenIDConnectSessionModel{}, authorizeCode)
}

// GetOpenIDConnectSession implements [openid.OpenIDConnectRequestStorage].
func (s *OAuth2Store) GetOpenIDConnectSession(ctx context.Context, authorizeCode string, requester fosite.Requester) (fosite.Requester, error) {
	m, err := findSessionModelBySignature(s.app, s.prefix, &OpenIDConnectSessionModel{}, authorizeCode)
	if err != nil {
		if errors.Is(err, fosite.ErrNotFound) {
			return nil, fositeopenid.ErrNoSessionFound
		}
		return nil, err
	}

	return m.ToRequest(ctx, s, requester.GetSession())
}

var _ fosite.Storage = (*OAuth2Store)(nil)
var _ fositeoauth2.AuthorizeCodeStorage = (*OAuth2Store)(nil)
var _ fositeoauth2.AccessTokenStorage = (*OAuth2Store)(nil)
var _ fositeoauth2.RefreshTokenStorage = (*OAuth2Store)(nil)
var _ fositeoauth2.TokenRevocationStorage = (*OAuth2Store)(nil)
var _ fositepkce.PKCERequestStorage = (*OAuth2Store)(nil)
var _ fositeopenid.OpenIDConnectRequestStorage = (*OAuth2Store)(nil)
var _ RFC7591ClientStorage = (*OAuth2Store)(nil)

// HELPER FUNCTIONS

func newSessionModel[T SessionModel](app core.App, m T) T {
	c, err := app.FindCachedCollectionByNameOrId(m.GetCollectionName())
	if err != nil {
		c = core.NewBaseCollection("@__invalid__")
	}
	m.SetProxyRecord(core.NewRecord(c))
	return m
}

func findSessionModelBySignature[T SessionModel](app core.App, prefix string, m T, signature string) (T, error) {
	c, err := app.FindCachedCollectionByNameOrId(m.GetCollectionName())
	if err != nil {
		c = core.NewBaseCollection("@__invalid__")
	}
	err = app.RecordQuery(c).
		AndWhere(dbx.HashExp{"signature": signature}).
		AndWhere(providerPrefixExp(app, prefix)).
		One(m)
	return m, mapRFCErr(err)
}

func deleteSessionModelBySignature[T SessionModel](app core.App, prefix string, m T, signature string) error {
	m, err := findSessionModelBySignature(app, prefix, m, signature)
	if err != nil {
		if errors.Is(err, fosite.ErrNotFound) {
			return nil // if the session is not found, we can consider it already deleted and return no error
		} else {
			return err
		}
	}
	return app.Delete(m.ProxyRecord())
}

func deleteSessionModelsByRequestID[T SessionModel](app core.App, prefix string, m T, requestID string) error {
	c, err := app.FindCachedCollectionByNameOrId(m.GetCollectionName())
	if err != nil {
		return err
	}
	var rows []T
	if err := app.RecordQuery(c).
		AndWhere(dbx.HashExp{"request_id": requestID}).
		AndWhere(providerPrefixExp(app, prefix)).All(&rows); err != nil {
		return err
	}
	for _, row := range rows {
		if err := app.Delete(row.ProxyRecord()); err != nil {
			return err
		}
	}
	return nil
}

//

func newJTIModel(app core.App, prefix, jti string, exp time.Time) error {
	m := NewJTIModel(app)
	m.Set("provider_prefix", normalizePrefix(prefix))
	m.Set("jti", jti)
	m.Set("expires_at", exp.Unix())

	return app.Save(m)
}

func hasJTIModel(app core.App, prefix, jti string) error {
	c, err := app.FindCachedCollectionByNameOrId(consts.JTICollectionName)
	if err != nil {
		return fosite.ErrServerError.WithWrap(err)
	}
	var rows []*JTIModel
	if err := app.RecordQuery(c).AndWhere(dbx.HashExp{"jti": jti}).AndWhere(providerPrefixExp(app, prefix)).All(&rows); err != nil {
		return fosite.ErrServerError.WithWrap(err)
	} else if len(rows) > 0 {
		return fosite.ErrJTIKnown
	}
	return nil
}

//

const missingRefreshTombstoneLifetime = 24 * time.Hour

// commitRefreshTerminalAuthority publishes the provider-scoped request-id
// tombstone before any fallible refresh-row/access cleanup. The marker is a
// separate transaction on purpose: cleanup rollback must never roll terminal
// authority back with it.
func commitRefreshTerminalAuthority(app core.App, prefix, requestID, familyID string, expiresAt int64) error {
	if requestID == "" {
		return errors.New("terminal refresh authority has no request_id")
	}
	prefix = normalizePrefix(prefix)
	minimumExpiry := time.Now().Add(missingRefreshTombstoneLifetime).Unix()
	if expiresAt < minimumExpiry {
		expiresAt = minimumExpiry
	}
	return app.RunInTransaction(func(txApp core.App) error {
		artifactFamily, artifactExpiry, _, err := scopedRefreshArtifactAuthority(txApp, prefix, requestID)
		if err != nil {
			return err
		}
		if familyID != "" && artifactFamily != "" && familyID != artifactFamily {
			return errors.New("terminal request_id spans multiple refresh families")
		}
		if familyID == "" {
			familyID = artifactFamily
		}
		if expiresAt < artifactExpiry {
			expiresAt = artifactExpiry
		}
		record, err := txApp.FindFirstRecordByFilter(
			consts.RefreshTombstoneCollectionName,
			"provider_prefix = {:prefix} && request_id = {:request}",
			dbx.Params{"prefix": prefix, "request": requestID},
		)
		if err == nil {
			existingFamily := record.GetString("family_id")
			if existingFamily != "" && familyID != "" && existingFamily != familyID {
				return errors.New("terminal request_id spans multiple refresh families")
			}
			if existingFamily == "" && familyID != "" {
				record.Set("family_id", familyID)
			}
			if int64(record.GetInt("expires_at")) < expiresAt {
				record.Set("expires_at", expiresAt)
			}
			return txApp.Save(record)
		}
		if !errors.Is(err, sql.ErrNoRows) {
			return err
		}
		collection, err := txApp.FindCachedCollectionByNameOrId(consts.RefreshTombstoneCollectionName)
		if err != nil {
			return err
		}
		record = core.NewRecord(collection)
		record.Set("provider_prefix", prefix)
		record.Set("request_id", requestID)
		record.Set("family_id", familyID)
		record.Set("expires_at", expiresAt)
		return txApp.Save(record)
	})
}

func hasRefreshTerminalAuthority(app core.App, prefix, requestID string) (bool, error) {
	if requestID == "" {
		return false, nil
	}
	_, err := app.FindFirstRecordByFilter(
		consts.RefreshTombstoneCollectionName,
		"provider_prefix = {:prefix} && request_id = {:request}",
		dbx.Params{"prefix": normalizePrefix(prefix), "request": requestID},
	)
	if err == nil {
		// Presence is terminal until the cleanup job physically removes the
		// expired marker. Treating an expired-but-not-yet-cleaned row as absent
		// would reopen a root-issuance window between expiry and cron cleanup.
		return true, nil
	}
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	return false, err
}

// scopedRefreshArtifactAuthority returns the single refresh family, maximum
// artifact expiry, and total number of refresh/access rows for one provider-
// scoped request. Tombstones use the count during cleanup: even an expired
// row whose deletion failed keeps terminal authority alive until the row is
// physically gone, because direct resource guards authorize by row presence.
func scopedRefreshArtifactAuthority(app core.App, prefix, requestID string) (familyID string, expiresAt int64, count int, err error) {
	refreshCollection, err := app.FindCachedCollectionByNameOrId(consts.RefreshCollectionName)
	if err != nil {
		return "", 0, 0, err
	}
	var rows []*RefreshTokenModel
	if err := app.RecordQuery(refreshCollection).
		AndWhere(dbx.HashExp{"request_id": requestID}).
		AndWhere(providerPrefixExp(app, prefix)).
		All(&rows); err != nil {
		return "", 0, 0, err
	}
	for _, row := range rows {
		count++
		if candidate := row.GetFamilyID(); candidate != "" {
			if familyID != "" && familyID != candidate {
				return "", 0, 0, errors.New("request_id spans multiple refresh families")
			}
			familyID = candidate
		}
		if expiry := row.GetExpiresAt(); expiry != nil && expiry.Unix() > expiresAt {
			expiresAt = expiry.Unix()
		}
	}
	accessCollection, err := app.FindCachedCollectionByNameOrId(consts.AccessCollectionName)
	if err != nil {
		return "", 0, 0, err
	}
	var accessRows []*AccessTokenModel
	if err := app.RecordQuery(accessCollection).
		AndWhere(dbx.HashExp{"request_id": requestID}).
		AndWhere(providerPrefixExp(app, prefix)).
		All(&accessRows); err != nil {
		return "", 0, 0, err
	}
	for _, row := range accessRows {
		count++
		if expiry := row.GetExpiresAt(); expiry != nil && expiry.Unix() > expiresAt {
			expiresAt = expiry.Unix()
		}
	}
	return familyID, expiresAt, count, nil
}

//

func mapRFCErr(err error) error {
	if errors.Is(err, sql.ErrNoRows) {
		return fosite.ErrNotFound
	}
	return err
}

// markRefreshRotated transitions the refresh row identified by signature
// to status=rotated and stamps rotated_at. The row is intentionally kept
// in place so a later replay of the same signature can be detected and
// the family invalidated.
//
// The transition is done as a single conditional UPDATE so concurrent
// refresh attempts on the same predecessor cannot both succeed. Two
// callers may both pass GetRefreshTokenSession (which only reads), but
// at most one will rotate the row from active→rotated. The loser sees
// zero rows affected and is failed with fosite.ErrSerializationFailure
// so the upstream refresh-grant handler aborts before
// CreateRefreshTokenSession mints a sibling child.
func markRefreshRotated(app core.App, prefix, requestID, signature string) error {
	terminal, err := hasRefreshTerminalAuthority(app, prefix, requestID)
	if err != nil {
		return fosite.ErrServerError.WithWrap(err).WithDebug("failed to read terminal refresh-family authority before rotation")
	}
	if terminal {
		return fosite.ErrInactiveToken
	}
	rotatedAt := time.Now().UnixMicro()
	prefix = normalizePrefix(prefix)
	prefixClause := "[[provider_prefix]] = {:prefix}"
	if legacyDefaultAllowed(app, prefix) {
		prefixClause = "([[provider_prefix]] = {:prefix} OR [[provider_prefix]] = '')"
	}
	result, err := app.DB().NewQuery(
		"UPDATE {{" + consts.RefreshCollectionName + "}} " +
			"SET [[status]] = {:rotated}, [[rotated_at]] = {:at} " +
			"WHERE [[signature]] = {:sig} AND [[status]] = {:active} AND " + prefixClause).
		Bind(dbx.Params{
			"rotated": RefreshStatusRotated,
			"at":      rotatedAt,
			"sig":     signature,
			"active":  RefreshStatusActive,
			"prefix":  prefix,
		}).Execute()
	if err != nil {
		return err
	}
	n, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if n > 0 {
		return nil
	}

	// Zero rows affected: either the row never existed, or some other
	// caller already moved it out of "active". Disambiguate by reading
	// the current state.
	m, lookupErr := findSessionModelBySignature(app, prefix, &RefreshTokenModel{}, signature)
	if lookupErr != nil {
		if errors.Is(lookupErr, fosite.ErrNotFound) {
			// The token was valid at the earlier read but disappeared before
			// Rotate. This is never idempotent success: commit a request-scoped
			// tombstone so even a misbehaving paused caller cannot mint a root.
			if err := commitRefreshTerminalAuthority(app, prefix, requestID, "", 0); err != nil {
				return fosite.ErrServerError.WithWrap(err).WithDebug("failed to tombstone missing refresh predecessor")
			}
			return fosite.ErrInactiveToken
		}
		return lookupErr
	}
	expiresAt := int64(0)
	if expiry := m.GetExpiresAt(); expiry != nil {
		expiresAt = expiry.Unix()
	}
	commitTerminal := func(debug string) error {
		if err := commitRefreshTerminalAuthority(app, prefix, requestID, m.GetFamilyID(), expiresAt); err != nil {
			return fosite.ErrServerError.WithWrap(err).WithDebug(debug)
		}
		return nil
	}

	switch m.GetStatus() {
	case RefreshStatusRotated:
		// Race lost: using an already-rotated token is a reuse signal, not a
		// harmless serialization retry. Tombstone the whole family before
		// returning so the winner cannot mint (or retain) a replacement in
		// the Rotate -> Create gap.
		if err := commitTerminal("failed to commit concurrently reused refresh-family authority"); err != nil {
			return err
		}
		familyID := m.GetFamilyID()
		if familyID == "" {
			if err := invalidateLegacyRefreshRow(app, prefix, m); err != nil {
				return fosite.ErrServerError.WithWrap(err).WithDebug("failed to invalidate concurrently reused legacy refresh token")
			}
		} else if err := invalidateRefreshFamily(app, prefix, familyID); err != nil {
			return fosite.ErrServerError.WithWrap(err).WithDebug("failed to invalidate concurrently reused refresh family")
		}
		return fosite.ErrInactiveToken
	case RefreshStatusReused, RefreshStatusRevoked:
		// The row was invalidated out from under us (reuse detection or
		// explicit revocation). Treat as inactive.
		if err := commitTerminal("failed to commit existing terminal refresh-family authority"); err != nil {
			return err
		}
		return fosite.ErrInactiveToken
	default:
		// Unknown state - be conservative and abort the rotation.
		if err := commitTerminal("failed to tombstone invalid refresh-family state"); err != nil {
			return err
		}
		return fosite.ErrInactiveToken
	}
}

// assertRefreshFamilyAllowsAccess prevents an access row created in Fosite's
// Rotate -> CreateAccess -> CreateRefresh gap from becoming usable after a
// concurrent reuse or explicit revocation won family authority. Access-only
// grants have no refresh rows and remain unaffected.
func assertRefreshFamilyAllowsAccess(app core.App, prefix, requestID string) error {
	if requestID == "" {
		return nil
	}
	terminal, err := hasRefreshTerminalAuthority(app, prefix, requestID)
	if err != nil {
		return fosite.ErrServerError.WithWrap(err)
	}
	if terminal {
		return fosite.ErrInactiveToken
	}
	c, err := app.FindCachedCollectionByNameOrId(consts.RefreshCollectionName)
	if err != nil {
		return fosite.ErrServerError.WithWrap(err)
	}
	var rows []*RefreshTokenModel
	if err := app.RecordQuery(c).
		AndWhere(dbx.HashExp{"request_id": requestID}).
		AndWhere(providerPrefixExp(app, prefix)).
		All(&rows); err != nil {
		return fosite.ErrServerError.WithWrap(err)
	}
	for _, row := range rows {
		switch row.GetStatus() {
		case RefreshStatusActive, RefreshStatusRotated:
			// A normal family contains rotated ancestors and one active leaf.
		case RefreshStatusReused, RefreshStatusRevoked:
			return fosite.ErrInactiveToken
		default:
			return fosite.ErrServerError.WithDebug("refresh-family row has an invalid status")
		}
	}
	return nil
}

// invalidateRefreshFamily marks every refresh row in the given family as
// reused (status=reused, reused_at=now) and deletes every access token
// whose request_id matches any row in the family. The entire mutation is
// transactional and every save/delete error is
// propagated; partial invalidation would leave a reusable sibling token.
func invalidateRefreshFamily(app core.App, prefix, familyID string) error {
	return mutateRefreshFamily(app, prefix, familyID, RefreshStatusReused)
}

func invalidateLegacyRefreshRow(app core.App, prefix string, row *RefreshTokenModel) error {
	allowLegacy := legacyDefaultAllowed(app, prefix)
	return app.RunInTransaction(func(txApp core.App) error {
		c, err := txApp.FindCachedCollectionByNameOrId(consts.RefreshCollectionName)
		if err != nil {
			return err
		}
		current := &RefreshTokenModel{}
		if err := txApp.RecordQuery(c).AndWhere(dbx.HashExp{"id": row.GetID()}).
			AndWhere(providerPrefixExpWithLegacy(prefix, allowLegacy)).One(current); err != nil {
			return err
		}
		current.SetStatus(RefreshStatusReused)
		if current.GetReusedAt() == 0 {
			current.SetReusedAt(time.Now().UnixMicro())
		}
		if err := txApp.Save(current.ProxyRecord()); err != nil {
			return err
		}
		accessCollection, err := txApp.FindCachedCollectionByNameOrId(consts.AccessCollectionName)
		if err != nil {
			return err
		}
		var accessRows []*AccessTokenModel
		if err := txApp.RecordQuery(accessCollection).AndWhere(dbx.HashExp{"request_id": current.GetRequestID()}).
			AndWhere(providerPrefixExpWithLegacy(prefix, allowLegacy)).All(&accessRows); err != nil {
			return err
		}
		for _, access := range accessRows {
			if err := txApp.Delete(access.ProxyRecord()); err != nil {
				return err
			}
		}
		return nil
	})
}

func mutateRefreshFamily(app core.App, prefix, familyID, status string) error {
	if familyID == "" {
		return nil
	}
	allowLegacy := legacyDefaultAllowed(app, prefix)
	return app.RunInTransaction(func(txApp core.App) error {
		c, err := txApp.FindCachedCollectionByNameOrId(consts.RefreshCollectionName)
		if err != nil {
			return err
		}
		var rows []*RefreshTokenModel
		if err := txApp.RecordQuery(c).AndWhere(dbx.HashExp{"family_id": familyID}).
			AndWhere(providerPrefixExpWithLegacy(prefix, allowLegacy)).All(&rows); err != nil {
			return err
		}
		now := time.Now().UnixMicro()
		seenRequestIDs := map[string]struct{}{}
		for _, row := range rows {
			if reqID := row.GetRequestID(); reqID != "" {
				seenRequestIDs[reqID] = struct{}{}
			}
			row.SetStatus(status)
			if status == RefreshStatusReused && row.GetReusedAt() == 0 {
				row.SetReusedAt(now)
			}
			if err := txApp.Save(row.ProxyRecord()); err != nil {
				return err
			}
		}
		accessCollection, err := txApp.FindCachedCollectionByNameOrId(consts.AccessCollectionName)
		if err != nil {
			return err
		}
		for reqID := range seenRequestIDs {
			var accessRows []*AccessTokenModel
			if err := txApp.RecordQuery(accessCollection).AndWhere(dbx.HashExp{"request_id": reqID}).
				AndWhere(providerPrefixExpWithLegacy(prefix, allowLegacy)).All(&accessRows); err != nil {
				return err
			}
			for _, access := range accessRows {
				if err := txApp.Delete(access.ProxyRecord()); err != nil {
					return err
				}
			}
		}
		return nil
	})
}

func revokeRefreshFamilyByRequestID(app core.App, prefix, requestID string) error {
	allowLegacy := legacyDefaultAllowed(app, prefix)
	return app.RunInTransaction(func(txApp core.App) error {
		refreshCollection, err := txApp.FindCachedCollectionByNameOrId(consts.RefreshCollectionName)
		if err != nil {
			return err
		}
		var seeds []*RefreshTokenModel
		if err := txApp.RecordQuery(refreshCollection).AndWhere(dbx.HashExp{"request_id": requestID}).
			AndWhere(providerPrefixExpWithLegacy(prefix, allowLegacy)).All(&seeds); err != nil {
			return err
		}
		if len(seeds) == 0 {
			return nil
		}
		families := map[string]struct{}{}
		for _, row := range seeds {
			if row.GetFamilyID() == "" {
				return errors.New("refresh row has no family_id")
			}
			families[row.GetFamilyID()] = struct{}{}
		}
		seenRequestIDs := map[string]struct{}{}
		for familyID := range families {
			var familyRows []*RefreshTokenModel
			if err := txApp.RecordQuery(refreshCollection).AndWhere(dbx.HashExp{"family_id": familyID}).
				AndWhere(providerPrefixExpWithLegacy(prefix, allowLegacy)).All(&familyRows); err != nil {
				return err
			}
			for _, row := range familyRows {
				if reqID := row.GetRequestID(); reqID != "" {
					seenRequestIDs[reqID] = struct{}{}
				}
				row.SetStatus(RefreshStatusRevoked)
				if err := txApp.Save(row.ProxyRecord()); err != nil {
					return err
				}
			}
		}
		accessCollection, err := txApp.FindCachedCollectionByNameOrId(consts.AccessCollectionName)
		if err != nil {
			return err
		}
		for reqID := range seenRequestIDs {
			var accessRows []*AccessTokenModel
			if err := txApp.RecordQuery(accessCollection).AndWhere(dbx.HashExp{"request_id": reqID}).
				AndWhere(providerPrefixExpWithLegacy(prefix, allowLegacy)).All(&accessRows); err != nil {
				return err
			}
			for _, access := range accessRows {
				if err := txApp.Delete(access.ProxyRecord()); err != nil {
					return err
				}
			}
		}
		return nil
	})
}
