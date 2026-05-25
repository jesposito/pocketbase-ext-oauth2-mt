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

const storeKey = "github.com/jesposito/pocketbase-ext-oauth2-mt/instance"
const registeringKey = storeKey + "/registering"

// Instance holds all OAuth2 provider state for a single PocketBase app.
// It replaces the upstream package-level globals to enable safe multi-tenant
// usage where multiple core.App instances run in the same process.
type Instance struct {
	cfg        *Config
	store      *OAuth2Store
	provider   fosite.OAuth2Provider
	privateKey *jose.JSONWebKey
	metadata   *openid.OpenIDProviderMetadata
	protected  map[string]*rfc9728.ProtectedResourceMetadata
	mu         sync.RWMutex
}

func getInstance(app core.App) (*Instance, bool) {
	inst, ok := app.Store().Get(storeKey).(*Instance)
	return inst, ok
}

func mustGetInstance(app core.App) *Instance {
	inst, ok := getInstance(app)
	if !ok || inst == nil {
		panic("[Plugin/OAuth2] instance not initialized — call Register() first")
	}
	return inst
}

// RegisterProtectedResourceMetadata registers a protected resource metadata
// entry for the OAuth2 instance associated with the given app.
func RegisterProtectedResourceMetadata(app core.App, md *rfc9728.ProtectedResourceMetadata) {
	mustGetInstance(app).RegisterProtectedResourceMetadata(md)
}

// RegisterProtectedResourceMetadata registers a protected resource metadata
// entry for this OAuth2 instance.
func (inst *Instance) RegisterProtectedResourceMetadata(md *rfc9728.ProtectedResourceMetadata) {
	if !inst.cfg.EnableRFC9728ProtectedResourceMetadata {
		return
	}

	url, _ := url.Parse(md.Resource)
	key := strings.Trim(url.Path, "/")

	inst.mu.Lock()
	defer inst.mu.Unlock()

	inst.protected[key] = md
	for _, scope := range md.ScopesSupported {
		if !slices.Contains(inst.metadata.ScopesSupported, scope) {
			inst.metadata.ScopesSupported = append(inst.metadata.ScopesSupported, scope)
		}
	}
}
