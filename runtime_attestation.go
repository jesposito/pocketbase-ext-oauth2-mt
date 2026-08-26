package oauth2

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/go-jose/go-jose/v3"
	"github.com/pocketbase/pocketbase/core"
)

const (
	runtimeAttestationAudience      = "urn:facetcloud:oauth-runtime-attestation:v1"
	runtimeAttestationType          = "facet-oauth-runtime-attestation+jwt"
	runtimeAttestationLifetime      = 60 * time.Second
	runtimeAttestationWindow        = time.Minute
	runtimeAttestationInstanceLimit = 120
)

var (
	runtimeAttestationSHA      = regexp.MustCompile(`^[0-9a-f]{40}$`)
	runtimeAttestationDigest   = regexp.MustCompile(`^[0-9a-f]{64}$`)
	runtimeAttestationTenant   = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$`)
	runtimeAttestationIdentity = regexp.MustCompile(`^[A-Za-z0-9._:-]{1,128}$`)
)

// RuntimeAttestationSnapshot is the complete, typed application-owned state
// the provider may attest. It intentionally contains no arbitrary claims,
// payload bytes, JOSE controls, key selectors, or expiry knobs.
type RuntimeAttestationSnapshot struct {
	Tenant           string
	ReleaseSHA       string
	SourceSHA        string
	SourceID         string
	BootID           string
	AuthConfigSHA256 string
}

type runtimeAttestationClaims struct {
	AttestationVersion int    `json:"attestation_version"`
	Audience           string `json:"aud"`
	AuthConfigSHA256   string `json:"auth_config_sha256"`
	BootID             string `json:"boot_id"`
	ExpiresAt          int64  `json:"exp"`
	IssuedAt           int64  `json:"iat"`
	Issuer             string `json:"iss"`
	Nonce              string `json:"nonce"`
	Origin             string `json:"origin"`
	Prefix             string `json:"prefix"`
	ReleaseSHA         string `json:"release_sha"`
	SourceID           string `json:"source_id"`
	SourceSHA          string `json:"source_sha"`
	Tenant             string `json:"tenant"`
	UserCollection     string `json:"user_collection"`
}

type runtimeAttestationResponse struct {
	Attestation string `json:"attestation"`
}

type runtimeAttestationWindowState struct {
	started time.Time
	count   int
}

type runtimeAttestationLimiter struct {
	mu    sync.Mutex
	state runtimeAttestationWindowState
}

// allow bounds RSA signing per provider Instance/PathPrefix without deriving
// identity from a socket peer or attacker-controlled forwarding headers. This
// keeps shared ingress callers usable and preserves core.App tenant isolation;
// aggregate process CPU limits remain the embedding host's responsibility.
func (l *runtimeAttestationLimiter) allow(now time.Time) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.state.started.IsZero() || now.Sub(l.state.started) >= runtimeAttestationWindow {
		l.state = runtimeAttestationWindowState{started: now}
	}
	if l.state.count >= runtimeAttestationInstanceLimit {
		return false
	}
	l.state.count++
	return true
}

func apiOAuth2RuntimeAttestation(e *core.RequestEvent, inst *Instance) error {
	now := time.Now().UTC()
	if !inst.attestationLimiter.allow(now) {
		return e.TooManyRequestsError("runtime attestation rate limit exceeded", nil)
	}
	values, present := e.Request.URL.Query()["nonce"]
	if !present || len(values) != 1 || !validRuntimeAttestationNonce(values[0]) {
		return e.BadRequestError("invalid runtime attestation nonce", nil)
	}
	e.Response.Header().Set("Cache-Control", "no-store")
	e.Response.Header().Set("Pragma", "no-cache")

	snapshot, err := inst.cfg.RuntimeAttestationSnapshot(e.Request.Context())
	if err != nil {
		return e.InternalServerError("runtime attestation snapshot unavailable", err)
	}
	token, err := signRuntimeAttestation(e.App, inst, snapshot, values[0], now)
	if err != nil {
		return e.InternalServerError("runtime attestation unavailable", err)
	}
	return e.JSON(http.StatusOK, runtimeAttestationResponse{Attestation: token})
}

func signRuntimeAttestation(app core.App, inst *Instance, snapshot RuntimeAttestationSnapshot, nonce string, now time.Time) (string, error) {
	if app == nil || inst == nil || inst.cfg == nil || inst.cfg.RuntimeAttestationSnapshot == nil {
		return "", errors.New("runtime attestation is not configured")
	}
	if err := validateRuntimeAttestationSnapshot(snapshot); err != nil {
		return "", err
	}
	if !validRuntimeAttestationNonce(nonce) {
		return "", errors.New("runtime attestation nonce must be canonical base64url for 32 bytes")
	}
	inst.mu.RLock()
	if inst.privateKey == nil || inst.privateKey.Key == nil || inst.privateKey.KeyID == "" || inst.privateKey.Algorithm != string(jose.RS256) {
		inst.mu.RUnlock()
		return "", errors.New("runtime attestation signing key is unavailable")
	}
	signingKey := *inst.privateKey
	inst.mu.RUnlock()

	origin := strings.TrimRight(app.Settings().Meta.AppURL, "/")
	parsedOrigin, err := url.Parse(origin)
	if err != nil || parsedOrigin.Scheme != "https" || parsedOrigin.Host == "" || parsedOrigin.User != nil || parsedOrigin.Path != "" || parsedOrigin.RawQuery != "" || parsedOrigin.Fragment != "" || parsedOrigin.String() != origin {
		return "", errors.New("runtime attestation origin is not an exact HTTPS origin")
	}
	prefix := normalizePrefix(inst.cfg.PathPrefix)
	issuer := providerIssuer(app, inst.cfg)
	options := (&jose.SignerOptions{}).WithType(runtimeAttestationType).WithHeader("kid", signingKey.KeyID)
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: signingKey}, options)
	if err != nil {
		return "", fmt.Errorf("create runtime attestation signer: %w", err)
	}
	claims := runtimeAttestationClaims{
		AttestationVersion: 1, Audience: runtimeAttestationAudience,
		AuthConfigSHA256: snapshot.AuthConfigSHA256, BootID: snapshot.BootID,
		ExpiresAt: now.Add(runtimeAttestationLifetime).Unix(), IssuedAt: now.Unix(),
		Issuer: issuer, Nonce: nonce, Origin: origin, Prefix: prefix,
		ReleaseSHA: snapshot.ReleaseSHA, SourceID: snapshot.SourceID,
		SourceSHA: snapshot.SourceSHA, Tenant: snapshot.Tenant,
		UserCollection: inst.cfg.UserCollection,
	}
	payload, err := json.Marshal(claims)
	if err != nil {
		return "", fmt.Errorf("encode runtime attestation: %w", err)
	}
	signed, err := signer.Sign(payload)
	if err != nil {
		return "", fmt.Errorf("sign runtime attestation: %w", err)
	}
	compact, err := signed.CompactSerialize()
	if err != nil {
		return "", fmt.Errorf("serialize runtime attestation: %w", err)
	}
	return compact, nil
}

func validRuntimeAttestationNonce(nonce string) bool {
	decoded, err := base64.RawURLEncoding.DecodeString(nonce)
	return err == nil && len(decoded) == 32 && base64.RawURLEncoding.EncodeToString(decoded) == nonce
}

func validateRuntimeAttestationSnapshot(snapshot RuntimeAttestationSnapshot) error {
	if !runtimeAttestationTenant.MatchString(snapshot.Tenant) {
		return errors.New("runtime attestation tenant is invalid")
	}
	if !runtimeAttestationSHA.MatchString(snapshot.ReleaseSHA) || !runtimeAttestationSHA.MatchString(snapshot.SourceSHA) {
		return errors.New("runtime attestation SHA is invalid")
	}
	if !runtimeAttestationIdentity.MatchString(snapshot.SourceID) || !runtimeAttestationIdentity.MatchString(snapshot.BootID) {
		return errors.New("runtime attestation source or boot identity is invalid")
	}
	if !runtimeAttestationDigest.MatchString(snapshot.AuthConfigSHA256) {
		return errors.New("runtime attestation auth config digest is invalid")
	}
	return nil
}
