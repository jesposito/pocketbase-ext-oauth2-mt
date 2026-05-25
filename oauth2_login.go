package oauth2

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"strconv"
	"time"

	"github.com/ory/fosite"
	"github.com/pocketbase/pocketbase/core"
)

// urlParse exists so tests can stub it; in production it's net/url.Parse.
var urlParse = url.Parse

// loginStateResponse is the JSON shape returned by GET /oauth2/login/state.
// The UI calls it with ?id=<interaction_id> after landing on /login to
// learn what consent screen to render — without ever decoding a
// browser-controlled state blob (lr7).
type loginStateResponse struct {
	ClientID        string   `json:"client_id"`
	ClientName      string   `json:"client_name"`
	UserCollection  string   `json:"user_collection"`
	RequestedScopes []string `json:"requested_scopes"`
	GrantedScopes   []string `json:"granted_scopes"` // previously consented scopes for this (user not known yet here, so empty) → kept for future
	Prompt          string   `json:"prompt"`
	ExpiresAt       int64    `json:"expires_at"`
}

// loginCompleteRequest is the JSON body the UI POSTs to /oauth2/login/complete.
// The server validates the bound interaction, optionally records explicit
// consent, and either completes the OAuth flow (returning a same-origin
// redirect) or surfaces a fosite error redirect — in either case the
// browser navigates to a server-chosen URL.
type loginCompleteRequest struct {
	InteractionID  string   `json:"interaction_id"`
	PBToken        string   `json:"pb_token"`
	PBTokenIAT     int64    `json:"pb_token_iat"`
	Decision       string   `json:"decision"` // "approve" | "deny"
	ConsentedScopes []string `json:"consented_scopes"`
}

// loginCompleteResponse tells the UI where to navigate next. RedirectURI
// is the client's OAuth redirect (success or error) prepared by fosite.
type loginCompleteResponse struct {
	RedirectURI string `json:"redirect_uri"`
}

// api_OAuth2LoginState exposes (read-only) metadata for a pending
// authorization interaction so the login UI can render the consent
// screen. It is intentionally permissive about CORS — the metadata
// it returns (client name + scopes) is the same data a logged-in user
// would see, and the endpoint requires a valid interaction id that
// expires after 10 minutes.
func api_OAuth2LoginState(e *core.RequestEvent, inst *Instance) error {
	r := e.Request
	w := e.Response

	if r.Method == http.MethodOptions {
		setLoginCORS(w)
		return e.NoContent(http.StatusNoContent)
	}
	if r.Method != http.MethodGet {
		return e.Error(http.StatusMethodNotAllowed, "", nil)
	}
	setLoginCORS(w)

	id := r.URL.Query().Get("id")
	if id == "" {
		return e.BadRequestError("missing interaction id", nil)
	}
	in, err := FindInteraction(e.App, id)
	if err != nil {
		// Don't leak whether the row never existed vs. expired.
		return e.NotFoundError("interaction not found or expired", nil)
	}

	resp := loginStateResponse{
		ClientID:        in.ClientID,
		ClientName:      in.ClientName,
		UserCollection:  in.UserCollection,
		RequestedScopes: in.RequestedScopes,
		Prompt:          in.Prompt,
		ExpiresAt:       in.ExpiresAt.Unix(),
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	return json.NewEncoder(w).Encode(resp)
}

// api_OAuth2LoginComplete finishes a pending interaction. The UI POSTs:
//   {
//     "interaction_id": "<uuid>",
//     "pb_token":      "<PB auth token from PocketBase auth-with-password>",
//     "pb_token_iat":  <unix seconds the token was issued>,
//     "decision":      "approve" | "deny",
//     "consented_scopes": ["openid", "profile", ...]   // only on approve
//   }
//
// The server:
//   - looks up the interaction and rejects if missing/expired,
//   - validates the PB auth token belongs to the configured user
//     collection,
//   - if decision == "deny" returns an access_denied redirect (RFC 6749
//     §4.1.2.1 + RFC 9207 iss),
//   - otherwise verifies that consented_scopes ∪ stored Consent for
//     (user, client) covers requested_scopes — failure ⇒
//     interaction_required redirect (mci),
//   - upserts the explicit Consent so prompt=none works on future runs,
//   - replays the original /auth form synthesizing pb_token in, calls
//     fosite NewAuthorizeRequest + NewAuthorizeResponse, and returns the
//     resulting redirect URI as JSON for the browser to navigate to.
//
// The redirect URI ALWAYS comes from server-side state, never from
// request input — that is what closes lr7.
func api_OAuth2LoginComplete(e *core.RequestEvent, inst *Instance) error {
	r := e.Request
	w := e.Response
	ctx := r.Context()

	if r.Method == http.MethodOptions {
		setLoginCORS(w)
		return e.NoContent(http.StatusNoContent)
	}
	if r.Method != http.MethodPost {
		return e.Error(http.StatusMethodNotAllowed, "", nil)
	}
	setLoginCORS(w)

	var req loginCompleteRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		return e.BadRequestError("invalid JSON body", err)
	}
	if req.InteractionID == "" {
		return e.BadRequestError("interaction_id is required", nil)
	}
	in, err := FindInteraction(e.App, req.InteractionID)
	if err != nil {
		return e.NotFoundError("interaction not found or expired", nil)
	}
	// Always consume the interaction — even if validation fails below the
	// row should not be reusable. Defer the delete so it runs on every
	// code path.
	defer func() { _ = DeleteInteraction(e.App, in.ID) }()

	// Reconstruct the original authorize request from server-stored
	// form values, NOT from request input. The browser's only influence
	// on the OAuth flow at this point is decision + consented_scopes +
	// the PB auth token they supply.
	form := in.RequestForm

	// Decision: deny → access_denied redirect.
	if req.Decision == "deny" {
		return writeInteractionError(ctx, e, inst, form, in.RedirectURI, fosite.ErrAccessDenied)
	}
	if req.Decision != "approve" {
		return e.BadRequestError(`decision must be "approve" or "deny"`, nil)
	}

	// Validate the PB auth token (must be a real PB token, must belong
	// to the configured user collection).
	if req.PBToken == "" {
		return writeInteractionError(ctx, e, inst, form, in.RedirectURI, fosite.ErrLoginRequired)
	}
	u, err := e.App.FindAuthRecordByToken(req.PBToken)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return writeInteractionError(ctx, e, inst, form, in.RedirectURI, fosite.ErrLoginRequired)
		}
		return e.InternalServerError("token lookup failed", err)
	}
	if u.Collection().Name != in.UserCollection {
		return writeInteractionError(ctx, e, inst, form, in.RedirectURI, fosite.ErrAccessDenied.WithDebug("user collection mismatch"))
	}

	// Consent enforcement (mci). Merge any previously-recorded consent
	// with the newly-clicked one; the request can only authorize scopes
	// the user explicitly approved this round AND/OR previously granted.
	prior, err := FindConsent(e.App, u.Id, u.Collection().Name, in.ClientID)
	if err != nil {
		e.App.Logger().Warn("[Plugin/OAuth2] FindConsent failed", slog.Any("err", err))
	}
	available := append([]string{}, req.ConsentedScopes...)
	if prior != nil {
		available = mergeScopes(prior.GrantedScopes, available)
	}
	if !ConsentCovers(available, in.RequestedScopes) {
		return writeInteractionError(ctx, e, inst, form, in.RedirectURI, fosite.ErrConsentRequired)
	}
	// Record the merged consent for next time (prompt=none silent reuse).
	if _, cerr := UpsertConsent(e.App, u.Id, u.Collection().Name, in.ClientID, available); cerr != nil {
		e.App.Logger().Warn("[Plugin/OAuth2] UpsertConsent failed (continuing)", slog.Any("err", cerr))
	}

	// Stamp rat (requested-at) into the replayed form so the eventual
	// ID token's rat claim matches the original /auth call.
	if !form.Has("rat") {
		form.Set("rat", strconv.FormatInt(in.RequestedAt.Unix(), 10))
	}

	// Replay the authorize request through fosite using the
	// server-stored form. We have to wrap the form into a request
	// fosite understands; the cleanest path is to set r.Form directly.
	r.Form = form
	r.PostForm = form

	ar, err := inst.provider.NewAuthorizeRequest(ctx, r)
	if err != nil {
		return writeInteractionError(ctx, e, inst, form, in.RedirectURI, err)
	}

	for _, scope := range ar.GetRequestedScopes() {
		ar.GrantScope(scope)
	}
	for _, aud := range ar.GetRequestedAudience() {
		ar.GrantAudience(aud)
	}

	mySessionData := NewSession(e.App, u.Id, u.Collection().Id)
	mySessionData.Claims.AuthTime = time.Unix(req.PBTokenIAT, 0).UTC()
	mySessionData.Claims.RequestedAt = in.RequestedAt

	var loa int = 1
	var amr []string
	if u.Collection().PasswordAuth.Enabled {
		amr = append(amr, "pwd")
	}
	if u.Collection().OTP.Enabled {
		amr = append(amr, "otp")
	}
	if u.Collection().MFA.Enabled {
		loa += 1
		amr = append(amr, "mfa")
	}
	mySessionData.Claims.AuthenticationMethodsReferences = amr
	mySessionData.Claims.AuthenticationContextClassReference = fmt.Sprintf("loa%d", loa)

	response, err := inst.provider.NewAuthorizeResponse(ctx, ar, mySessionData)
	if err != nil {
		return writeInteractionError(ctx, e, inst, form, in.RedirectURI, err)
	}
	response.AddParameter("iss", e.App.Settings().Meta.AppURL)

	// Instead of writing the redirect directly, we capture it and hand
	// the URL back to the UI as JSON. The browser will then navigate —
	// this lets the UI run cleanup (clear cached state, etc.) before
	// leaving the page.
	rec := &captureResponseWriter{header: http.Header{}}
	inst.provider.WriteAuthorizeResponse(ctx, rec, ar, response)
	redirect := rec.header.Get("Location")
	if redirect == "" {
		// form_post mode: fosite writes an HTML form, no Location. The
		// UI doesn't support form_post for the moment; surface as
		// server_error so the operator sees the gap.
		return e.InternalServerError("form_post response mode is not supported by the built-in login UI", nil)
	}

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	return json.NewEncoder(w).Encode(loginCompleteResponse{RedirectURI: redirect})
}

// writeInteractionError builds a fosite error redirect using the
// server-stored redirect_uri and writes it as JSON so the UI can
// navigate the browser. Unlike writeAuthorizeErrorWithIss (which writes
// directly), this returns JSON so the UI controls the final hop.
func writeInteractionError(ctx context.Context, e *core.RequestEvent, inst *Instance, form url.Values, redirectURI string, oerr error) error {
	if redirectURI == "" {
		// No client redirect possible. Surface as JSON error.
		rfcerr := fosite.ErrorToRFC6749Error(oerr)
		e.Response.Header().Set("Content-Type", "application/json")
		e.Response.WriteHeader(rfcerr.CodeField)
		_ = json.NewEncoder(e.Response).Encode(rfcerr)
		return nil
	}
	iss := e.App.Settings().Meta.AppURL
	rfcerr := fosite.ErrorToRFC6749Error(oerr).
		WithLegacyFormat(inst.cfg.BaseConfig.GetUseLegacyErrorFormat(ctx)).
		WithExposeDebug(inst.cfg.BaseConfig.GetSendDebugMessagesToClients(ctx))

	params := rfcerr.ToValues()
	if state := form.Get("state"); state != "" {
		params.Set("state", state)
	}
	params.Set("iss", iss)

	u, err := urlParse(redirectURI)
	if err != nil {
		return e.InternalServerError("stored redirect_uri is not parseable", err)
	}
	u.Fragment = ""
	// Default to query mode unless the client explicitly asked for
	// fragment via response_mode (preserves OIDC implicit-style flows;
	// we don't support those in OAuth 2.1 mode anyway).
	switch form.Get("response_mode") {
	case "fragment":
		u.RawFragment = params.Encode()
	default:
		existing := u.Query()
		for k, vs := range params {
			for _, v := range vs {
				existing.Add(k, v)
			}
		}
		u.RawQuery = existing.Encode()
	}
	e.Response.Header().Set("Content-Type", "application/json")
	e.Response.Header().Set("Cache-Control", "no-store")
	return json.NewEncoder(e.Response).Encode(loginCompleteResponse{RedirectURI: u.String()})
}

// setLoginCORS enables same-origin XHR from the login UI even when the
// UI was loaded from a different sub-path. The login endpoints accept
// JSON only and run on the same origin as the auth endpoint.
func setLoginCORS(w http.ResponseWriter) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
}

// captureResponseWriter is a no-op ResponseWriter that captures the
// Location header that fosite would write, so we can hand it to the UI
// as JSON instead of streaming a 303 directly.
type captureResponseWriter struct {
	header http.Header
	status int
	body   []byte
}

func (c *captureResponseWriter) Header() http.Header { return c.header }
func (c *captureResponseWriter) WriteHeader(status int) { c.status = status }
func (c *captureResponseWriter) Write(b []byte) (int, error) {
	c.body = append(c.body, b...)
	return len(b), nil
}
