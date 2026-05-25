package migrations

import (
	"github.com/jesposito/pocketbase-ext-oauth2-mt/consts"
	"github.com/pocketbase/pocketbase/core"
)

// 1770366000_interactions_and_consents creates two new system collections
// that close the audit-flagged token-exfiltration and consent-bypass holes:
//
//   - _oauth2Interactions stores the server-side authorization-request
//     state that previously lived in a browser-controlled base64 JSON
//     blob. The login UI now references each pending authorization by an
//     opaque interaction_id instead of decoding (and trusting) a state
//     payload; the redirect_uri the server uses to complete the OAuth
//     flow is read from this row, never from request input.
//
//   - _oauth2Consents records each (user, client, granted_scopes) tuple
//     so prompt=none and silent-consent flows can require a prior
//     explicit grant. Rows survive until the user revokes consent via
//     the consent management UI or until the client is deleted.
//
// Cleanup: the existing hourly cleanup job already iterates a list of
// session collections; we extend it (in oauth2.go) to include
// InteractionCollectionName so expired interactions are removed.
func init() {
	core.SystemMigrations.Register(func(txApp core.App) error {
		// _oauth2Interactions: opaque server-side pending-authorization
		// store. request_form is the marshaled url.Values from the
		// original /auth call; the server replays it on /login/complete.
		interactions := core.NewBaseCollection(consts.InteractionCollectionName)
		interactions.System = true
		interactions.Fields.Add(
			&core.TextField{Name: "client_id"},
			&core.TextField{Name: "client_name"},
			&core.TextField{Name: "user_collection"},
			&core.TextField{Name: "redirect_uri"},
			&core.JSONField{Name: "request_form"},
			&core.JSONField{Name: "requested_scopes"},
			&core.NumberField{Name: "requested_at"},
			&core.NumberField{Name: "expires_at"},
			&core.TextField{Name: "prompt"},
		)
		if err := txApp.Save(interactions); err != nil {
			return err
		}

		// _oauth2Consents: explicit user grants per (user, client).
		// granted_scopes is a JSON array; queries union it against the
		// requested scope set on each new authorization.
		consents := core.NewBaseCollection(consts.ConsentCollectionName)
		consents.System = true
		consents.Fields.Add(
			&core.TextField{Name: "user_id"},
			&core.TextField{Name: "user_collection"},
			&core.TextField{Name: "client_id"},
			&core.JSONField{Name: "granted_scopes"},
			&core.NumberField{Name: "granted_at"},
		)
		return txApp.Save(consents)
	}, func(txApp core.App) error {
		// Down: drop both collections. Safe because they only hold
		// short-lived pending state (interactions) and revocable user
		// grants (consents) — losing either causes pending flows to
		// require re-authentication on next attempt.
		for _, name := range []string{consts.InteractionCollectionName, consts.ConsentCollectionName} {
			c, err := txApp.FindCollectionByNameOrId(name)
			if err != nil {
				continue
			}
			if err := txApp.Delete(c); err != nil {
				return err
			}
		}
		return nil
	})
}
