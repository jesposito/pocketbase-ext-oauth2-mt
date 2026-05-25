// Adds requested_acr_values JSONField to the _oauth2Interactions
// collection so the server-owned interaction store can pass the
// authorize request's acr_values through to the login UI (g0hb /
// facets-sh-bu41). Idempotent — guards on field absence.
package migrations

import (
	"github.com/pocketbase/pocketbase/core"
	m "github.com/pocketbase/pocketbase/migrations"

	"github.com/jesposito/pocketbase-ext-oauth2-mt/consts"
)

func init() {
	m.Register(func(app core.App) error {
		c, err := app.FindCollectionByNameOrId(consts.InteractionCollectionName)
		if err != nil {
			return err
		}
		if c.Fields.GetByName("requested_acr_values") != nil {
			return nil // already present
		}
		c.Fields.Add(&core.JSONField{Name: "requested_acr_values"})
		return app.Save(c)
	}, func(app core.App) error {
		c, err := app.FindCollectionByNameOrId(consts.InteractionCollectionName)
		if err != nil {
			return err
		}
		c.Fields.RemoveByName("requested_acr_values")
		return app.Save(c)
	})
}
