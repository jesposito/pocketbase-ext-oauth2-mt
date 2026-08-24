package oauth2

import (
	"net/url"
	"slices"
	"strings"
	"sync"

	"github.com/go-jose/go-jose/v3"
	"github.com/ory/fosite"
	"github.com/pocketbase/pocketbase/core"

	"github.com/jesposito/pocketbase-ext-oauth2-mt/openid"
	"github.com/jesposito/pocketbase-ext-oauth2-mt/rfc9728"
)

// DefaultPathPrefix is the path prefix used when Config.PathPrefix is empty
// and when callers pass an empty prefix to the *At lookup helpers. Public
// constant so callers can reference the default consistently.
const DefaultPathPrefix = "/oauth2"

const storeKeyBase = "github.com/jesposito/pocketbase-ext-oauth2-mt/instance"
const registeringKeyBase = storeKeyBase + "/registering"

// instanceStoreKey returns the app.Store() key under which the Instance
// for a given PathPrefix is stored. Different prefixes on the same app
// (e.g. /oauth2/admin + /oauth2/members) land in different slots so a
// single tenant can host multiple OPs side by side.
func instanceStoreKey(prefix string) string {
	return storeKeyBase + ":" + normalizePrefix(prefix)
}

// registeringStoreKey is the per-prefix variant of the legacy
// registeringKey sentinel.
func registeringStoreKey(prefix string) string {
	return registeringKeyBase + ":" + normalizePrefix(prefix)
}

// normalizePrefix collapses empty / unset prefixes to DefaultPathPrefix so
// helpers that take prefix as an optional argument behave consistently.
func normalizePrefix(prefix string) string {
	prefix = strings.TrimSpace(prefix)
	if prefix == "" {
		return DefaultPathPrefix
	}
	if !strings.HasPrefix(prefix, "/") {
		prefix = "/" + prefix
	}
	prefix = strings.TrimRight(prefix, "/")
	if prefix == "" {
		return DefaultPathPrefix
	}
	return prefix
}

// Instance holds all OAuth2 provider state for a single (app, prefix) pair.
// It replaces the upstream package-level globals to enable safe multi-tenant
// usage where multiple core.App instances run in the same process; with the
// per-prefix store key, a single app can also host multiple OPs at
// different path prefixes.
type Instance struct {
	cfg        *Config
	store      *OAuth2Store
	provider   fosite.OAuth2Provider
	privateKey *jose.JSONWebKey
	metadata   *openid.OpenIDProviderMetadata
	protected  map[string]*rfc9728.ProtectedResourceMetadata
	mu         sync.RWMutex
}

// getInstance looks up the Instance registered at the DefaultPathPrefix.
// Use getInstanceAt when reaching for a non-default prefix.
func getInstance(app core.App) (*Instance, bool) {
	return getInstanceAt(app, DefaultPathPrefix)
}

// getInstanceAt looks up the Instance registered at the given path prefix.
// An empty prefix resolves to DefaultPathPrefix.
func getInstanceAt(app core.App, prefix string) (*Instance, bool) {
	inst, ok := app.Store().Get(instanceStoreKey(prefix)).(*Instance)
	return inst, ok
}

func mustGetInstance(app core.App) *Instance {
	return mustGetInstanceAt(app, DefaultPathPrefix)
}

func mustGetInstanceAt(app core.App, prefix string) *Instance {
	inst, ok := getInstanceAt(app, prefix)
	if !ok || inst == nil {
		panic("[Plugin/OAuth2] instance not initialized — call Register() first (prefix=" + normalizePrefix(prefix) + ")")
	}
	return inst
}

// RegisterProtectedResourceMetadata registers a protected resource
// metadata entry for the OAuth2 instance at DefaultPathPrefix on the
// given app. Use RegisterProtectedResourceMetadataAt for non-default
// prefixes (e.g. when an app hosts multiple OPs).
func RegisterProtectedResourceMetadata(app core.App, md *rfc9728.ProtectedResourceMetadata) {
	mustGetInstance(app).RegisterProtectedResourceMetadata(md)
}

// RegisterProtectedResourceMetadataAt is the prefix-aware variant.
func RegisterProtectedResourceMetadataAt(app core.App, prefix string, md *rfc9728.ProtectedResourceMetadata) {
	mustGetInstanceAt(app, prefix).RegisterProtectedResourceMetadata(md)
}

// RegisterProtectedResourceMetadata registers a protected resource metadata
// entry for this OAuth2 instance.
//
// Safe to call before app bootstrap: the entry is buffered in inst.protected
// and the discovery metadata's ScopesSupported is merged later in loadParams
// once inst.metadata exists.
func (inst *Instance) RegisterProtectedResourceMetadata(md *rfc9728.ProtectedResourceMetadata) {
	if !inst.cfg.EnableRFC9728ProtectedResourceMetadata {
		return
	}

	url, _ := url.Parse(md.Resource)
	key := strings.Trim(url.Path, "/")

	inst.mu.Lock()
	defer inst.mu.Unlock()

	inst.protected[key] = md
	if inst.metadata != nil {
		mergeProtectedScopes(inst.metadata, md.ScopesSupported)
	}
}

// mergeProtectedScopes appends scopes that aren't already advertised in the
// discovery metadata. Caller must hold inst.mu (or otherwise own metadata).
func mergeProtectedScopes(md *openid.OpenIDProviderMetadata, scopes []string) {
	for _, scope := range scopes {
		if !slices.Contains(md.ScopesSupported, scope) {
			md.ScopesSupported = append(md.ScopesSupported, scope)
		}
	}
}
