package migrations

import (
	"database/sql"
	"errors"
	"fmt"

	"github.com/jesposito/pocketbase-ext-oauth2-mt/consts"
	"github.com/pocketbase/pocketbase/core"
)

// Refresh-family tombstones are the durable terminal authority that closes
// Fosite's multi-call Rotate -> CreateAccess -> CreateRefresh window. They are
// committed before fallible row/access cleanup, so a cleanup rollback cannot
// allow a paused winner to mint a new root.
func init() {
	core.SystemMigrations.Register(func(txApp core.App) error {
		collection, err := txApp.FindCollectionByNameOrId(consts.RefreshTombstoneCollectionName)
		if err != nil {
			if !errors.Is(err, sql.ErrNoRows) {
				return err
			}
			collection = core.NewBaseCollection(consts.RefreshTombstoneCollectionName)
		}
		if !collection.IsBase() {
			return fmt.Errorf("%s must be a base collection", consts.RefreshTombstoneCollectionName)
		}
		collection.System = true
		if err := ensureRefreshTombstoneTextField(collection, "provider_prefix", true); err != nil {
			return err
		}
		if err := ensureRefreshTombstoneTextField(collection, "request_id", true); err != nil {
			return err
		}
		if err := ensureRefreshTombstoneTextField(collection, "family_id", false); err != nil {
			return err
		}
		if err := ensureRefreshTombstoneExpiryField(collection); err != nil {
			return err
		}
		collection.AddIndex("idx_oauth2_refresh_tombstone_request", true, "`provider_prefix`, `request_id`", "")
		return txApp.Save(collection)
	}, func(txApp core.App) error {
		// Terminal authority is security state. As with refresh-family columns,
		// a down migration intentionally preserves it rather than resurrecting
		// a revoked family after rollback.
		return nil
	})
}

func ensureRefreshTombstoneTextField(collection *core.Collection, name string, required bool) error {
	field := collection.Fields.GetByName(name)
	if field == nil {
		collection.Fields.Add(&core.TextField{Name: name, Required: required, Max: 255})
		return nil
	}
	textField, ok := field.(*core.TextField)
	if !ok {
		return fmt.Errorf("%s.%s must be a text field", collection.Name, name)
	}
	textField.Required = required
	textField.Max = 255
	return nil
}

func ensureRefreshTombstoneExpiryField(collection *core.Collection) error {
	field := collection.Fields.GetByName("expires_at")
	if field == nil {
		collection.Fields.Add(&core.NumberField{Name: "expires_at", Required: true, OnlyInt: true})
		return nil
	}
	numberField, ok := field.(*core.NumberField)
	if !ok {
		return fmt.Errorf("%s.expires_at must be a number field", collection.Name)
	}
	numberField.Required = true
	numberField.OnlyInt = true
	return nil
}
