package oauth2

import (
	"maps"
	"time"

	"github.com/ory/fosite"
	fositeopenid "github.com/ory/fosite/handler/openid"
	"github.com/ory/fosite/token/jwt"
	"github.com/pocketbase/pocketbase/core"
)

// A session is passed from the `/auth` to the `/token` endpoint. You probably want to store data like: "Who made the request",
// "What organization does that person belong to" and so on.
// For our use case, the session will meet the requirements imposed by JWT access tokens, HMAC access tokens and OpenID Connect
// ID Tokens plus a custom field

// NewSession constructs a Session with issuer + subject metadata populated.
//
// Claims.ExpiresAt is intentionally left as the zero time.Time. fosite's
// openid/strategy_jwt.go computes the actual ID-token expiry from
// Config.GetIDTokenLifespan (or per-client overrides) when ExpiresAt is
// zero; setting an arbitrary 6-hour default here unconditionally
// over-rode that configuration. Callers that genuinely need a per-session
// override can still mutate Claims.ExpiresAt before passing the session
// to fosite.
func NewSession(app core.App, recordId string, collectionId string) *Session {
	return &Session{
		DefaultSession: fositeopenid.DefaultSession{
			Claims: &jwt.IDTokenClaims{
				Issuer:   app.Settings().Meta.AppURL,
				Subject:  recordId,
				IssuedAt: time.Now(),
			},
			Headers: &jwt.Headers{},
			Subject: recordId,
		},
		CollectionId: collectionId,
	}
}

type Session struct {
	fositeopenid.DefaultSession

	CollectionId string `json:"collection,omitempty"`
}

var _ fositeopenid.Session = (*Session)(nil)

func (s *Session) GetJWTClaims() jwt.JWTClaimsContainer {
	claims := &jwt.JWTClaims{}
	if s.Claims != nil {
		claims.FromMapClaims(s.Claims.ToMapClaims())
	}
	claims.Add("collection", s.CollectionId)
	return claims
}

// Clone returns a deep copy of the session. fosite calls Clone before
// mutating session state in introspection/refresh flows; sharing a single
// session pointer would let one request observe another's amr/acr/sub
// changes. We hand-clone instead of pulling in github.com/mohae/deepcopy
// (unmaintained since 2017) since the struct is small and fully known.
func (s *Session) Clone() fosite.Session {
	if s == nil {
		return nil
	}
	clone := &Session{
		DefaultSession: fositeopenid.DefaultSession{
			Subject:   s.Subject,
			Username:  s.Username,
			ExpiresAt: cloneTimeMap(s.ExpiresAt),
		},
		CollectionId: s.CollectionId,
	}
	if s.Claims != nil {
		c := *s.Claims
		// IDTokenClaims contains slices/maps that must be copied so the
		// clone cannot mutate the original.
		c.Audience = append([]string(nil), s.Claims.Audience...)
		c.AuthenticationMethodsReferences = append([]string(nil), s.Claims.AuthenticationMethodsReferences...)
		if s.Claims.Extra != nil {
			c.Extra = maps.Clone(s.Claims.Extra)
		}
		clone.Claims = &c
	}
	if s.Headers != nil {
		h := jwt.Headers{}
		if s.Headers.Extra != nil {
			h.Extra = maps.Clone(s.Headers.Extra)
		}
		clone.Headers = &h
	}
	return clone
}

// cloneTimeMap copies a fosite ExpiresAt map (token-type -> expiry time)
// so the clone's mutations don't ripple back to the original.
func cloneTimeMap(in map[fosite.TokenType]time.Time) map[fosite.TokenType]time.Time {
	if in == nil {
		return nil
	}
	return maps.Clone(in)
}
