package oauth2

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/go-jose/go-jose/v3"
	"github.com/ory/fosite"
	"github.com/pocketbase/pocketbase/core"
)

// iatMatches reports whether `presented` matches any configured Initial
// Access Token. Comparison is constant-time per entry to avoid leaking
// the count or content of the token list via timing.
func iatMatches(allowed []string, presented string) bool {
	pres := []byte(presented)
	for _, t := range allowed {
		if t == "" {
			continue
		}
		if subtle.ConstantTimeCompare([]byte(t), pres) == 1 {
			return true
		}
	}
	return false
}

// validateRedirectURI enforces redirect_uri hygiene per RFC 7591 §2 +
// OAuth 2.1 §4.1.2.1: HTTPS scheme is required except for loopback
// development addresses (RFC 8252 §7.3). Fragments are forbidden.
// Empty + opaque + non-absolute URIs are rejected.
func validateRedirectURI(raw string) error {
	if raw == "" {
		return fmt.Errorf("redirect_uri must be a non-empty absolute URI")
	}
	u, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("redirect_uri %q is not a valid URI: %w", raw, err)
	}
	if !u.IsAbs() {
		return fmt.Errorf("redirect_uri %q must be an absolute URI", raw)
	}
	if u.Fragment != "" {
		return fmt.Errorf("redirect_uri %q must not contain a fragment", raw)
	}
	switch strings.ToLower(u.Scheme) {
	case "https":
		return nil
	case "http":
		// Loopback exception: 127.0.0.1, [::1], localhost — only for
		// dev clients. Reject any other plain-HTTP redirect.
		h := strings.ToLower(u.Hostname())
		if h == "127.0.0.1" || h == "::1" || h == "localhost" {
			return nil
		}
		return fmt.Errorf("redirect_uri %q must use https:// (plain http is only permitted for loopback)", raw)
	default:
		// Custom schemes (myapp://callback) are permitted — native /
		// mobile clients legitimately need them. We don't have enough
		// context here to validate further; the operator should review
		// registered clients periodically.
		return nil
	}
}

type RFC7591ClientStorage interface {
	// RegisterClient registers a new client with the given metadata
	// and returns the created client or an error if the registration failed.
	RegisterClient(ctx context.Context, client *RFC7591ClientMetadataRequest) (fosite.Client, string, error)
}

type RFC7591ClientMetadataRequest struct {
	Scope                   string              `json:"scope"`
	RedirectURIs            []string            `json:"redirect_uris"`
	TokenEndpointAuthMethod string              `json:"token_endpoint_auth_method"`
	GrantTypes              []string            `json:"grant_types"`
	ResponseTypes           []string            `json:"response_types"`
	Contacts                []string            `json:"contacts,omitempty"`
	ClientName              string              `json:"client_name"`
	ClientURI               string              `json:"client_uri,omitempty"`
	LogoURI                 string              `json:"logo_uri,omitempty"`
	TermsOfServiceURI       string              `json:"tos_uri,omitempty"`
	PolicyURI               string              `json:"policy_uri,omitempty"`
	JwksURI                 string              `json:"jwks_uri,omitempty"`
	Jwks                    *jose.JSONWebKeySet `json:"jwks,omitempty"`
	SoftwareID              string              `json:"software_id,omitempty"`
	SoftwareVersion         string              `json:"software_version,omitempty"`

	// The following fields are not part of the RFC7591 but are required for OpenID Connect client registration.
	// @ref https://openid.net/specs/openid-connect-core-1_0.html#rfc.section.6.2
	RequestURIs []string `json:"request_uris,omitempty"`
}

type RFC7591ClientMetadata struct {
	RFC7591ClientMetadataRequest
	ClientID              string `json:"client_id"`
	ClientSecret          string `json:"client_secret"`
	ClientSecretExpiresAt int64  `json:"client_secret_expires_at"`
}

// @ref https://datatracker.ietf.org/doc/html/rfc7591#section-3
func api_OAuth2Register(e *core.RequestEvent, inst *Instance) error {
	r := e.Request
	w := e.Response

	if r.Method != http.MethodPost {
		return e.Error(http.StatusMethodNotAllowed, "", nil)
	}

	// RFC 7591 §3 Initial Access Token gate. The route is only bound by
	// Register() when either (a) an IAT list is configured or (b) the
	// operator explicitly opted into unauthenticated DCR; the second
	// branch here is the (a) check.
	if len(inst.cfg.DynamicClientRegistrationInitialAccessTokens) > 0 {
		got := bearerTokenFromHeader(r.Header.Get("Authorization"))
		if got == "" || !iatMatches(inst.cfg.DynamicClientRegistrationInitialAccessTokens, got) {
			w.Header().Set("WWW-Authenticate",
				`Bearer realm="OAuth Registration", error="invalid_token", error_description="A valid Initial Access Token is required to register a client."`)
			return e.Error(http.StatusUnauthorized, "invalid_token", nil)
		}
	}

	var md RFC7591ClientMetadataRequest

	if err := json.NewDecoder(r.Body).Decode(&md); err != nil {
		return e.BadRequestError(err.Error(), err)
	}

	if len(md.RedirectURIs) == 0 {
		return e.BadRequestError("redirect_uris is required", nil)
	}

	// Redirect URI policy: HTTPS-only except for localhost development.
	// Without this, an attacker can register a client with a plain-HTTP
	// redirect_uri and exfiltrate authorization codes over the wire.
	for _, u := range md.RedirectURIs {
		if err := validateRedirectURI(u); err != nil {
			return e.BadRequestError(err.Error(), err)
		}
	}

	c, clientSecret, err := inst.store.RegisterClient(r.Context(), &md)
	if err != nil {
		return e.InternalServerError("", err)
	}

	resp := &RFC7591ClientMetadata{
		RFC7591ClientMetadataRequest: md,
		ClientID:                     c.GetID(),
		ClientSecret:                 clientSecret,
		ClientSecretExpiresAt:        0,
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)

	if err := json.NewEncoder(w).Encode(resp); err != nil {
		return e.InternalServerError("", err)
	}
	return nil
}
