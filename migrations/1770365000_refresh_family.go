package migrations

import (
	"github.com/jesposito/pocketbase-ext-oauth2-mt/consts"
	"github.com/pocketbase/pocketbase/core"
)

// refresh_family adds OAuth 2.1 reuse-detection columns to the
// _oauth2Refresh collection. With these columns each refresh row carries:
//   - family_id: a UUID shared by every refresh in the same rotation chain
//   - parent_refresh_id: the record id of the predecessor refresh row,
//     empty for the chain root
//   - status: active | rotated | revoked | reused
//   - rotated_at: unix ts when the row was rotated (0 if not rotated)
//   - reused_at: unix ts when the family was invalidated by reuse (0 otherwise)
//
// Storage.RotateRefreshToken keeps the predecessor row around with
// status=rotated so a later replay of that signature is detectable as reuse;
// when reuse is detected the entire family is invalidated.
func init() {
	core.SystemMigrations.Register(func(txApp core.App) error {
		collection, err := txApp.FindCollectionByNameOrId(consts.RefreshCollectionName)
		if err != nil {
			return err
		}

		collection.Fields.Add(
			&core.TextField{Name: "family_id"},
			&core.TextField{Name: "parent_refresh_id"},
			&core.TextField{Name: "status"},
			&core.NumberField{Name: "rotated_at"},
			&core.NumberField{Name: "reused_at"},
		)

		return txApp.Save(collection)
	}, func(txApp core.App) error {
		// no-op down: dropping the new columns would lose reuse-detection
		// state for any active deployments; the columns are additive and
		// safe to leave in place.
		return nil
	})
}
