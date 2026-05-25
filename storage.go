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
	app core.App
}

func NewOAuth2Store(app core.App) *OAuth2Store {
	return &OAuth2Store{
		app: app,
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
	return NewClientFromRFC7591Metadata(s.app, client)
}

// ClientAssertionJWTValid implements [fosite.ClientManager].
func (s *OAuth2Store) ClientAssertionJWTValid(ctx context.Context, jti string) error {
	return hasJTIModel(s.app, jti)
}

// SetClientAssertionJWT implements [fosite.ClientManager].
func (s *OAuth2Store) SetClientAssertionJWT(ctx context.Context, jti string, exp time.Time) error {
	return newJTIModel(s.app, jti, exp)
}

// CreateAuthorizeCodeSession implements [oauth2.AuthorizeCodeStorage].
func (s *OAuth2Store) CreateAuthorizeCodeSession(ctx context.Context, code string, request fosite.Requester) (err error) {
	m := newSessionModel(s.app, &AuthCodeModel{})
	m.SetSignature(code)
	m.SetRequester(request, fosite.AuthorizeCode)

	return s.app.Save(m)
}

// GetAuthorizeCodeSession implements [oauth2.AuthorizeCodeStorage].
func (s *OAuth2Store) GetAuthorizeCodeSession(ctx context.Context, code string, session fosite.Session) (request fosite.Requester, err error) {
	m, err := findSessionModelBySignature(s.app, &AuthCodeModel{}, code)
	if err != nil {
		return nil, err
	}

	req, err := m.ToRequest(ctx, s, session)
	if err != nil {
		return nil, err
	}

	if err := hasJTIModel(s.app, code); err != nil {
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
	m, err := findSessionModelBySignature(s.app, &AuthCodeModel{}, code)
	if err != nil {
		if errors.Is(err, fosite.ErrNotFound) {
			return nil // if the session is not found, we can consider it already deleted and return no error
		}
	}

	return newJTIModel(s.app, code, *m.GetExpiresAt())
}

// CreateAccessTokenSession implements [oauth2.AccessTokenStorage].
func (s *OAuth2Store) CreateAccessTokenSession(ctx context.Context, signature string, request fosite.Requester) (err error) {
	m := newSessionModel(s.app, &AccessTokenModel{})
	m.SetSignature(signature)
	m.SetRequester(request, fosite.AccessToken)

	return s.app.Save(m)
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
	m := newSessionModel(s.app, &RefreshTokenModel{})
	m.SetSignature(signature)
	if err := m.SetRequester(request, fosite.RefreshToken); err != nil {
		return err
	}

	familyID, parentID := s.resolveRefreshLineage(request)
	m.SetFamilyID(familyID)
	m.SetParentRefreshID(parentID)
	m.SetStatus(RefreshStatusActive)
	m.SetRotatedAt(0)
	m.SetReusedAt(0)

	return s.app.Save(m)
}

// resolveRefreshLineage decides the family_id and parent_refresh_id for a
// newly created refresh row. The fosite refresh-grant handler calls
// RotateRefreshToken before CreateRefreshTokenSession and propagates the
// original request id (see fosite/handler/oauth2/flow_refresh.go), so the
// predecessor row is the one with the same request_id that we just marked
// rotated. If no such predecessor exists, this is a new chain root.
func (s *OAuth2Store) resolveRefreshLineage(request fosite.Requester) (familyID string, parentRefreshID string) {
	requestID := request.GetID()
	if requestID != "" {
		c, err := s.app.FindCachedCollectionByNameOrId(consts.RefreshCollectionName)
		if err == nil {
			parent := &RefreshTokenModel{}
			err = s.app.RecordQuery(c).
				AndWhere(dbx.HashExp{
					"request_id": requestID,
					"status":     RefreshStatusRotated,
				}).
				OrderBy("rotated_at DESC").
				Limit(1).
				One(parent)
			if err == nil && parent.GetFamilyID() != "" {
				return parent.GetFamilyID(), parent.GetID()
			}
		}
	}
	return uuid.NewString(), ""
}

// DeleteAccessTokenSession implements [oauth2.AccessTokenStorage].
func (s *OAuth2Store) DeleteAccessTokenSession(ctx context.Context, signature string) (err error) {
	return deleteSessionModelBySignature(s.app, &AccessTokenModel{}, signature)
}

// DeleteRefreshTokenSession implements [oauth2.RefreshTokenStorage].
func (s *OAuth2Store) DeleteRefreshTokenSession(ctx context.Context, signature string) (err error) {
	return deleteSessionModelBySignature(s.app, &RefreshTokenModel{}, signature)
}

// GetAccessTokenSession implements [oauth2.AccessTokenStorage].
func (s *OAuth2Store) GetAccessTokenSession(ctx context.Context, signature string, session fosite.Session) (request fosite.Requester, err error) {
	m, err := findSessionModelBySignature(s.app, &AccessTokenModel{}, signature)
	if err != nil {
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
	m, err := findSessionModelBySignature(s.app, &RefreshTokenModel{}, signature)
	if err != nil {
		return nil, err
	}

	if m.GetStatus() != RefreshStatusActive {
		req, _ := m.ToRequest(ctx, s, session)
		// Best-effort family invalidation. Even if invalidation hits a
		// transient error we still surface ErrInactiveToken so the
		// upstream handler aborts the refresh attempt.
		if familyID := m.GetFamilyID(); familyID != "" {
			_ = invalidateRefreshFamily(s.app, familyID)
		}
		return req, fosite.ErrInactiveToken
	}

	return m.ToRequest(ctx, s, session)
}

// RevokeAccessToken implements [oauth2.AccessTokenStorage].
func (s *OAuth2Store) RevokeAccessToken(ctx context.Context, requestID string) error {
	return deleteSessionModelByRequestID(s.app, &AccessTokenModel{}, requestID)
}

// RevokeRefreshToken implements [oauth2.TokenRevocationStorage].
//
// The row is marked status=revoked instead of being deleted so a later
// replay of the same signature is still caught as reuse against the
// family breadcrumb. The cleanup cron deletes the row eventually via
// expires_at.
func (s *OAuth2Store) RevokeRefreshToken(ctx context.Context, requestID string) error {
	m, err := findSessionModelByRequestID(s.app, &RefreshTokenModel{}, requestID)
	if err != nil {
		if errors.Is(err, fosite.ErrNotFound) {
			return nil
		}
		return err
	}
	m.SetStatus(RefreshStatusRevoked)
	return s.app.Save(m.ProxyRecord())
}

// RotateRefreshToken implements [oauth2.RefreshTokenStorage].
//
// Marks the predecessor refresh row as rotated (keeping the family
// breadcrumb for reuse detection) and deletes the predecessor access
// token by request_id. The replacement refresh row is created by the
// upstream handler in a follow-up CreateRefreshTokenSession call.
func (s *OAuth2Store) RotateRefreshToken(ctx context.Context, requestID string, refreshTokenSignature string) (err error) {
	if err := markRefreshRotated(s.app, refreshTokenSignature); err != nil {
		return err
	}
	return deleteSessionModelByRequestID(s.app, &AccessTokenModel{}, requestID)
}

// CreatePKCERequestSession implements [pkce.PKCERequestStorage].
func (s *OAuth2Store) CreatePKCERequestSession(ctx context.Context, signature string, requester fosite.Requester) error {
	m := newSessionModel(s.app, &PKCEModel{})
	m.SetSignature(signature)
	m.SetRequester(requester, "")

	return s.app.Save(m)
}

// DeletePKCERequestSession implements [pkce.PKCERequestStorage].
func (s *OAuth2Store) DeletePKCERequestSession(ctx context.Context, signature string) error {
	return deleteSessionModelBySignature(s.app, &PKCEModel{}, signature)
}

// GetPKCERequestSession implements [pkce.PKCERequestStorage].
func (s *OAuth2Store) GetPKCERequestSession(ctx context.Context, signature string, session fosite.Session) (fosite.Requester, error) {
	m, err := findSessionModelBySignature(s.app, &PKCEModel{}, signature)
	if err != nil {
		return nil, err
	}

	return m.ToRequest(ctx, s, session)
}

// CreateOpenIDConnectSession implements [openid.OpenIDConnectRequestStorage].
func (s *OAuth2Store) CreateOpenIDConnectSession(ctx context.Context, authorizeCode string, requester fosite.Requester) error {
	m := newSessionModel(s.app, &OpenIDConnectSessionModel{})
	m.SetSignature(authorizeCode)
	m.SetRequester(requester, fosite.IDToken)

	return s.app.Save(m)
}

// DeleteOpenIDConnectSession implements [openid.OpenIDConnectRequestStorage].
func (s *OAuth2Store) DeleteOpenIDConnectSession(ctx context.Context, authorizeCode string) error {
	return deleteSessionModelBySignature(s.app, &OpenIDConnectSessionModel{}, authorizeCode)
}

// GetOpenIDConnectSession implements [openid.OpenIDConnectRequestStorage].
func (s *OAuth2Store) GetOpenIDConnectSession(ctx context.Context, authorizeCode string, requester fosite.Requester) (fosite.Requester, error) {
	m, err := findSessionModelBySignature(s.app, &OpenIDConnectSessionModel{}, authorizeCode)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
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

func findSessionModelBySignature[T SessionModel](app core.App, m T, signature string) (T, error) {
	c, err := app.FindCachedCollectionByNameOrId(m.GetCollectionName())
	if err != nil {
		c = core.NewBaseCollection("@__invalid__")
	}
	err = app.RecordQuery(c).
		AndWhere(dbx.HashExp{"signature": signature}).
		One(m)
	return m, mapRFCErr(err)
}

func findSessionModelByRequestID[T SessionModel](app core.App, m T, requestID string) (T, error) {
	c, err := app.FindCachedCollectionByNameOrId(m.GetCollectionName())
	if err != nil {
		c = core.NewBaseCollection("@__invalid__")
	}
	err = app.RecordQuery(c).
		AndWhere(dbx.HashExp{"request_id": requestID}).
		One(m)
	return m, mapRFCErr(err)
}

func deleteSessionModelBySignature[T SessionModel](app core.App, m T, signature string) error {
	m, err := findSessionModelBySignature(app, m, signature)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil // if the session is not found, we can consider it already deleted and return no error
		} else {
			return err
		}
	}
	return app.Delete(m.ProxyRecord())
}

func deleteSessionModelByRequestID[T SessionModel](app core.App, m T, requestID string) error {
	m, err := findSessionModelByRequestID(app, m, requestID)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil // if the session is not found, we can consider it already deleted and return no error
		} else {
			return err
		}
	}
	return app.Delete(m.ProxyRecord())
}

//

func newJTIModel(app core.App, jti string, exp time.Time) error {
	m := NewJTIModel(app)
	m.Set("jti", jti)
	m.Set("expires_at", exp.Unix())

	return app.Save(m)
}

func hasJTIModel(app core.App, jti string) error {
	if n, err := app.CountRecords(consts.JTICollectionName, dbx.HashExp{"jti": jti}); err != nil {
		return fosite.ErrServerError.WithWrap(err)
	} else if n > 0 {
		return fosite.ErrJTIKnown
	}
	return nil
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
func markRefreshRotated(app core.App, signature string) error {
	m, err := findSessionModelBySignature(app, &RefreshTokenModel{}, signature)
	if err != nil {
		if errors.Is(err, fosite.ErrNotFound) {
			return nil
		}
		return err
	}
	if m.GetStatus() == RefreshStatusRotated {
		return nil
	}
	m.SetStatus(RefreshStatusRotated)
	// Use microsecond precision so the chain order survives multiple
	// rotations within the same wall-clock second (e.g. test loops).
	// UnixMicro fits comfortably inside the float64 PocketBase NumberField.
	m.SetRotatedAt(time.Now().UnixMicro())
	return app.Save(m.ProxyRecord())
}

// invalidateRefreshFamily marks every refresh row in the given family as
// reused (status=reused, reused_at=now) and deletes every access token
// whose request_id matches any row in the family. Best-effort: per-row
// failures are not propagated so a single bad record cannot mask a
// reuse signal for the rest of the chain.
func invalidateRefreshFamily(app core.App, familyID string) error {
	if familyID == "" {
		return nil
	}
	c, err := app.FindCachedCollectionByNameOrId(consts.RefreshCollectionName)
	if err != nil {
		return err
	}
	var rows []*RefreshTokenModel
	if err := app.RecordQuery(c).
		AndWhere(dbx.HashExp{"family_id": familyID}).
		All(&rows); err != nil {
		return err
	}

	now := time.Now().UnixMicro()
	seenRequestIDs := map[string]struct{}{}
	for _, row := range rows {
		if reqID := row.GetRequestID(); reqID != "" {
			seenRequestIDs[reqID] = struct{}{}
		}
		if row.GetStatus() == RefreshStatusReused {
			continue
		}
		row.SetStatus(RefreshStatusReused)
		if row.GetReusedAt() == 0 {
			row.SetReusedAt(now)
		}
		_ = app.Save(row.ProxyRecord())
	}

	for reqID := range seenRequestIDs {
		_ = deleteSessionModelByRequestID(app, &AccessTokenModel{}, reqID)
	}

	return nil
}
