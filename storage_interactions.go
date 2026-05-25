package oauth2

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"slices"
	"time"

	"github.com/google/uuid"
	"github.com/pocketbase/pocketbase/core"

	"github.com/jesposito/pocketbase-ext-oauth2-mt/consts"
)

// interactionLifespan is how long a pending /oauth2/auth interaction stays
// usable before it must be re-initiated. 10 minutes matches typical OIDC
// login session budgets (long enough for password+OTP+MFA, short enough
// that abandoned tabs don't accumulate exploitable state).
const interactionLifespan = 10 * time.Minute

// Interaction is the server-owned snapshot of a pending authorization
// request. It replaces the previous browser-controlled base64 JSON
// `state` parameter. The UI references each interaction by an opaque
// id, and the server reconstructs the original authorization request
// from request_form when completing the flow — so a malicious /login URL
// cannot smuggle in an attacker-chosen redirect_uri (lr7).
type Interaction struct {
	ID              string
	ClientID        string
	ClientName      string
	UserCollection  string
	RedirectURI     string
	RequestForm     url.Values
	RequestedScopes []string
	// RequestedAcrValues — space-separated acr_values from the original
	// authorize request, parsed into the standard list shape. The
	// consumer (login UI) MUST inspect this and either satisfy the
	// requested authentication context (e.g. force a passkey assertion
	// when "loa3" is requested) or surface the
	// insufficient_user_authentication error via /login/complete with
	// decision="acr_unsatisfiable". Empty = no requested values, any
	// auth method is acceptable.
	RequestedAcrValues []string
	Prompt             string
	RequestedAt        time.Time
	ExpiresAt          time.Time
}

// CreateInteraction persists a new pending authorization for later
// completion. Returns the generated interaction id.
func CreateInteraction(app core.App, in *Interaction) (string, error) {
	c, err := app.FindCollectionByNameOrId(consts.InteractionCollectionName)
	if err != nil {
		return "", fmt.Errorf("find interactions collection: %w", err)
	}
	if in.ID == "" {
		in.ID = uuid.NewString()
	}
	if in.RequestedAt.IsZero() {
		in.RequestedAt = time.Now()
	}
	if in.ExpiresAt.IsZero() {
		in.ExpiresAt = in.RequestedAt.Add(interactionLifespan)
	}
	formJSON, err := json.Marshal(in.RequestForm)
	if err != nil {
		return "", fmt.Errorf("marshal request_form: %w", err)
	}
	scopesJSON, err := json.Marshal(in.RequestedScopes)
	if err != nil {
		return "", fmt.Errorf("marshal requested_scopes: %w", err)
	}
	acrJSON, err := json.Marshal(in.RequestedAcrValues)
	if err != nil {
		return "", fmt.Errorf("marshal requested_acr_values: %w", err)
	}
	rec := core.NewRecord(c)
	rec.Id = in.ID
	rec.Set("client_id", in.ClientID)
	rec.Set("client_name", in.ClientName)
	rec.Set("user_collection", in.UserCollection)
	rec.Set("redirect_uri", in.RedirectURI)
	rec.Set("request_form", string(formJSON))
	rec.Set("requested_scopes", string(scopesJSON))
	rec.Set("requested_acr_values", string(acrJSON))
	rec.Set("requested_at", in.RequestedAt.Unix())
	rec.Set("expires_at", in.ExpiresAt.Unix())
	rec.Set("prompt", in.Prompt)
	if err := app.SaveNoValidate(rec); err != nil {
		return "", fmt.Errorf("save interaction: %w", err)
	}
	return in.ID, nil
}

// FindInteraction loads + validates an interaction by id. Returns an
// error if the row is missing or expired; in both cases the UI should
// treat the interaction as gone and force the user back through /auth.
func FindInteraction(app core.App, id string) (*Interaction, error) {
	if id == "" {
		return nil, errors.New("interaction id is required")
	}
	rec, err := app.FindRecordById(consts.InteractionCollectionName, id)
	if err != nil {
		return nil, fmt.Errorf("find interaction %q: %w", id, err)
	}
	exp := rec.GetInt("expires_at")
	if time.Now().Unix() > int64(exp) {
		return nil, errors.New("interaction expired")
	}
	var form url.Values
	if err := json.Unmarshal([]byte(rec.GetString("request_form")), &form); err != nil {
		return nil, fmt.Errorf("unmarshal request_form: %w", err)
	}
	var scopes []string
	_ = json.Unmarshal([]byte(rec.GetString("requested_scopes")), &scopes)
	var acrValues []string
	_ = json.Unmarshal([]byte(rec.GetString("requested_acr_values")), &acrValues)
	return &Interaction{
		ID:                 rec.Id,
		ClientID:           rec.GetString("client_id"),
		ClientName:         rec.GetString("client_name"),
		UserCollection:     rec.GetString("user_collection"),
		RedirectURI:        rec.GetString("redirect_uri"),
		RequestForm:        form,
		RequestedScopes:    scopes,
		RequestedAcrValues: acrValues,
		Prompt:             rec.GetString("prompt"),
		RequestedAt:        time.Unix(int64(rec.GetInt("requested_at")), 0).UTC(),
		ExpiresAt:          time.Unix(int64(exp), 0).UTC(),
	}, nil
}

// DeleteInteraction removes a completed (or denied) interaction row so
// it cannot be replayed.
func DeleteInteraction(app core.App, id string) error {
	rec, err := app.FindRecordById(consts.InteractionCollectionName, id)
	if err != nil {
		return nil // already gone
	}
	return app.Delete(rec)
}

// Consent represents a single user's explicit grant of a scope set to a
// given client. Subsequent prompt=none flows from the same client can
// proceed silently only when the requested scopes are a subset of an
// existing Consent. (mci)
type Consent struct {
	ID             string
	UserID         string
	UserCollection string
	ClientID       string
	GrantedScopes  []string
	GrantedAt      time.Time
}

// FindConsent returns the most recent consent row for (user, client) or
// (nil, nil) if none exists.
func FindConsent(app core.App, userID, userCollection, clientID string) (*Consent, error) {
	records, err := app.FindRecordsByFilter(
		consts.ConsentCollectionName,
		"user_id = {:user} && user_collection = {:coll} && client_id = {:client}",
		"-granted_at",
		1,
		0,
		map[string]any{"user": userID, "coll": userCollection, "client": clientID},
	)
	if err != nil {
		return nil, fmt.Errorf("query consents: %w", err)
	}
	if len(records) == 0 {
		return nil, nil
	}
	rec := records[0]
	var granted []string
	_ = json.Unmarshal([]byte(rec.GetString("granted_scopes")), &granted)
	return &Consent{
		ID:             rec.Id,
		UserID:         rec.GetString("user_id"),
		UserCollection: rec.GetString("user_collection"),
		ClientID:       rec.GetString("client_id"),
		GrantedScopes:  granted,
		GrantedAt:      time.Unix(int64(rec.GetInt("granted_at")), 0).UTC(),
	}, nil
}

// UpsertConsent merges newly-granted scopes into the (user, client) row,
// creating it if absent. Returns the merged Consent.
func UpsertConsent(app core.App, userID, userCollection, clientID string, newScopes []string) (*Consent, error) {
	existing, err := FindConsent(app, userID, userCollection, clientID)
	if err != nil {
		return nil, err
	}
	merged := mergeScopes(nil, newScopes)
	if existing != nil {
		merged = mergeScopes(existing.GrantedScopes, newScopes)
	}
	scopesJSON, err := json.Marshal(merged)
	if err != nil {
		return nil, fmt.Errorf("marshal granted_scopes: %w", err)
	}
	now := time.Now()
	c, err := app.FindCollectionByNameOrId(consts.ConsentCollectionName)
	if err != nil {
		return nil, fmt.Errorf("find consents collection: %w", err)
	}
	var rec *core.Record
	if existing != nil {
		rec, err = app.FindRecordById(consts.ConsentCollectionName, existing.ID)
		if err != nil {
			return nil, fmt.Errorf("reload consent for update: %w", err)
		}
	} else {
		rec = core.NewRecord(c)
		rec.Set("user_id", userID)
		rec.Set("user_collection", userCollection)
		rec.Set("client_id", clientID)
	}
	rec.Set("granted_scopes", string(scopesJSON))
	rec.Set("granted_at", now.Unix())
	if err := app.SaveNoValidate(rec); err != nil {
		return nil, fmt.Errorf("save consent: %w", err)
	}
	return &Consent{
		ID:             rec.Id,
		UserID:         userID,
		UserCollection: userCollection,
		ClientID:       clientID,
		GrantedScopes:  merged,
		GrantedAt:      now,
	}, nil
}

// ConsentCovers reports whether `granted` includes every scope in
// `requested`. Empty requested → true (no scopes to consent to).
func ConsentCovers(granted, requested []string) bool {
	for _, s := range requested {
		if !slices.Contains(granted, s) {
			return false
		}
	}
	return true
}

// mergeScopes returns the deduplicated union of existing and additions,
// preserving relative ordering of existing followed by new entries.
func mergeScopes(existing, additions []string) []string {
	out := append([]string{}, existing...)
	for _, s := range additions {
		if !slices.Contains(out, s) {
			out = append(out, s)
		}
	}
	return out
}
