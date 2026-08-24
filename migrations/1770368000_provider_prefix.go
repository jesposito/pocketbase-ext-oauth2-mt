package migrations

import (
	"github.com/jesposito/pocketbase-ext-oauth2-mt/consts"
	"github.com/pocketbase/pocketbase/core"
)

// provider_prefix makes every persistent OAuth artifact belong to exactly
// one provider instance. Existing rows intentionally remain empty: runtime
// compatibility permits them only while the default provider is the sole
// registered instance, and refuses a second provider while ambiguous legacy
// rows exist. Silently backfilling data created by an older multi-prefix
// build would assign records to the wrong security plane.
func init() {
	core.SystemMigrations.Register(func(txApp core.App) error {
		collections := []string{
			consts.ClientCollectionName,
			consts.AccessCollectionName,
			consts.RefreshCollectionName,
			consts.AuthCodeCollectionName,
			consts.PKCECollectionName,
			consts.OpenIDConnectCollectionName,
			consts.JTICollectionName,
			consts.InteractionCollectionName,
			consts.ConsentCollectionName,
		}
		for _, name := range collections {
			collection, err := txApp.FindCollectionByNameOrId(name)
			if err != nil {
				return err
			}
			if collection.Fields.GetByName("provider_prefix") == nil {
				collection.Fields.Add(&core.TextField{Name: "provider_prefix", Max: 255})
			}
			switch name {
			case consts.ClientCollectionName:
				collection.AddIndex("idx_oauth2_client_provider", true, "`provider_prefix`, `client_id`", "")
			case consts.JTICollectionName:
				collection.AddIndex("idx_oauth2_jti_provider", true, "`provider_prefix`, `jti`", "")
			case consts.ConsentCollectionName:
				collection.AddIndex("idx_oauth2_consent_provider", true, "`provider_prefix`, `user_collection`, `user_id`, `client_id`", "")
			case consts.InteractionCollectionName:
				collection.AddIndex("idx_oauth2_interaction_provider", false, "`provider_prefix`, `expires_at`", "")
			default:
				collection.AddIndex("idx_oauth2_"+name[7:]+"_provider_sig", true, "`provider_prefix`, `signature`", "")
				collection.AddIndex("idx_oauth2_"+name[7:]+"_provider_request", false, "`provider_prefix`, `request_id`", "")
			}
			if err := txApp.Save(collection); err != nil {
				return err
			}
		}
		return nil
	}, func(txApp core.App) error {
		return nil
	})
}
