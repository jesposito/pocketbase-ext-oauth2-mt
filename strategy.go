package oauth2

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/ory/fosite"
	"github.com/ory/fosite/compose"
	fositeoauth2 "github.com/ory/fosite/handler/oauth2"
	"github.com/pocketbase/pocketbase/core"
)

type PocketBaseStrategy struct {
	App    core.App
	Config interface {
		fosite.AccessTokenIssuerProvider
		fosite.AccessTokenLifespanProvider
		fosite.JWTScopeFieldProvider
	}
	HMACSHAStrategy fositeoauth2.CoreStrategy
	ProviderPrefix  string
}

func NewPocketBaseStrategy(app core.App, config fosite.Configurator) *PocketBaseStrategy {
	return NewPocketBaseStrategyAt(app, config, DefaultPathPrefix)
}

func NewPocketBaseStrategyAt(app core.App, config fosite.Configurator, prefix string) *PocketBaseStrategy {
	return &PocketBaseStrategy{
		App:             app,
		Config:          config,
		HMACSHAStrategy: compose.NewOAuth2HMACStrategy(config),
		ProviderPrefix:  normalizePrefix(prefix),
	}
}

// ACCESS TOKEN

// AccessTokenSignature implements [oauth2.CoreStrategy].
func (s *PocketBaseStrategy) AccessTokenSignature(ctx context.Context, token string) string {
	split := strings.Split(token, ".")
	if len(split) != 3 {
		return ""
	}
	return split[2]
}

// GenerateAccessToken implements [oauth2.CoreStrategy].
func (s *PocketBaseStrategy) GenerateAccessToken(ctx context.Context, requester fosite.Requester) (token string, signature string, err error) {
	session, ok := requester.GetSession().(*Session)
	if !ok {
		return "", "", fmt.Errorf("Session must be of type oauth2.Session but got type: %T", requester.GetSession())
	}
	user, err := s.App.FindRecordById(session.CollectionId, session.Subject)
	if err != nil {
		return "", "", fmt.Errorf("Failed to get auth record for session: %w", err)
	}
	token, err = user.NewStaticAuthToken(s.Config.GetAccessTokenLifespan(ctx))
	if err != nil {
		return "", "", fmt.Errorf("Failed to generate new auth token: %w", err)
	}
	return token, s.AccessTokenSignature(ctx, token), nil
}

// ValidateAccessToken implements [oauth2.CoreStrategy].
//
// Three checks: (1) the PB native JWT must validate (cryptographic + expiry),
// (2) the corresponding _oauth2Access session row must still exist, and
// (3) no durable refresh-family terminal authority may cover its request.
// The storage checks are what make /oauth2/revoke actually effective for
// callers that reach this function (fosite introspection + the local
// RequireScope middleware). PB-native routes that use apis.RequireAuth()
// bypass this entirely — wire RevokedTokenGuard() on those routes when
// you need revocation to take effect there too.
func (s *PocketBaseStrategy) ValidateAccessToken(ctx context.Context, requester fosite.Requester, token string) error {
	if _, err := s.App.FindAuthRecordByToken(token, core.TokenTypeAuth); err != nil {
		return err
	}
	signature := s.AccessTokenSignature(ctx, token)
	if signature == "" {
		return fosite.ErrInvalidTokenFormat
	}
	row, err := findSessionModelBySignature(s.App, s.ProviderPrefix, &AccessTokenModel{}, signature)
	if err != nil {
		if errors.Is(err, fosite.ErrNotFound) {
			return fosite.ErrInactiveToken
		}
		return err
	}
	return assertRefreshFamilyAllowsAccess(s.App, s.ProviderPrefix, row.GetRequestID())
}

// REFRESH TOKEN

// RefreshTokenSignature implements [oauth2.CoreStrategy].
func (s *PocketBaseStrategy) RefreshTokenSignature(ctx context.Context, token string) string {
	return s.HMACSHAStrategy.RefreshTokenSignature(ctx, token)
}

// GenerateRefreshToken implements [oauth2.CoreStrategy].
func (s *PocketBaseStrategy) GenerateRefreshToken(ctx context.Context, requester fosite.Requester) (token string, signature string, err error) {
	return s.HMACSHAStrategy.GenerateRefreshToken(ctx, requester)
}

// ValidateRefreshToken implements [oauth2.CoreStrategy].
func (s *PocketBaseStrategy) ValidateRefreshToken(ctx context.Context, requester fosite.Requester, token string) (err error) {
	return s.HMACSHAStrategy.ValidateRefreshToken(ctx, requester, token)
}

// AUTHORIZATION CODE

// AuthorizeCodeSignature implements [oauth2.CoreStrategy].
func (s *PocketBaseStrategy) AuthorizeCodeSignature(ctx context.Context, token string) string {
	return s.HMACSHAStrategy.AuthorizeCodeSignature(ctx, token)
}

// GenerateAuthorizeCode implements [oauth2.CoreStrategy].
func (s *PocketBaseStrategy) GenerateAuthorizeCode(ctx context.Context, requester fosite.Requester) (token string, signature string, err error) {
	return s.HMACSHAStrategy.GenerateAuthorizeCode(ctx, requester)
}

// ValidateAuthorizeCode implements [oauth2.CoreStrategy].
func (s *PocketBaseStrategy) ValidateAuthorizeCode(ctx context.Context, requester fosite.Requester, token string) (err error) {
	return s.HMACSHAStrategy.ValidateAuthorizeCode(ctx, requester, token)
}

var _ fositeoauth2.CoreStrategy = (*PocketBaseStrategy)(nil)
