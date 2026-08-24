package oauth2

import (
	"fmt"

	"github.com/jesposito/pocketbase-ext-oauth2-mt/consts"
	"github.com/pocketbase/dbx"
	"github.com/pocketbase/pocketbase/core"
)

var providerScopedCollections = []string{
	consts.ClientCollectionName,
	consts.AccessCollectionName,
	consts.RefreshCollectionName,
	consts.RefreshTombstoneCollectionName,
	consts.AuthCodeCollectionName,
	consts.PKCECollectionName,
	consts.OpenIDConnectCollectionName,
	consts.JTICollectionName,
	consts.InteractionCollectionName,
	consts.ConsentCollectionName,
}

func legacyDefaultAllowed(app core.App, prefix string) bool {
	if normalizePrefix(prefix) != DefaultPathPrefix {
		return false
	}
	prefixes := listRegisteredPrefixes(app)
	return len(prefixes) == 1 && normalizePrefix(prefixes[0]) == DefaultPathPrefix
}

func providerPrefixExp(app core.App, prefix string) dbx.Expression {
	prefix = normalizePrefix(prefix)
	return providerPrefixExpWithLegacy(prefix, legacyDefaultAllowed(app, prefix))
}

func providerPrefixExpWithLegacy(prefix string, allowLegacy bool) dbx.Expression {
	prefix = normalizePrefix(prefix)
	if allowLegacy {
		return dbx.NewExp("([[provider_prefix]] = {:prefix} OR [[provider_prefix]] = '')", dbx.Params{"prefix": prefix})
	}
	return dbx.HashExp{"provider_prefix": prefix}
}

// validateProviderPrefixState rejects a multi-provider app if any persistent
// OAuth row predates provider attestation. Such a row cannot be assigned to a
// plane safely. A sole default provider may continue reading legacy rows;
// all new writes are explicitly tagged.
func validateProviderPrefixState(app core.App) error {
	if len(listRegisteredPrefixes(app)) < 2 {
		return nil
	}
	for _, collection := range providerScopedCollections {
		n, err := app.CountRecords(collection, dbx.HashExp{"provider_prefix": ""})
		if err != nil {
			return fmt.Errorf("query legacy provider state in %s: %w", collection, err)
		}
		if n != 0 {
			return fmt.Errorf("ambiguous legacy OAuth state: %s contains %d row(s) without provider_prefix; refusing multi-provider startup", collection, n)
		}
	}
	return nil
}
