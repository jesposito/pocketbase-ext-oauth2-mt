package oauth2

import (
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strconv"
	"time"

	"github.com/jesposito/pocketbase-ext-oauth2-mt/client"
	"github.com/ory/fosite"
	"github.com/pocketbase/pocketbase/core"
)

func api_OAuth2Authorize(e *core.RequestEvent, inst *Instance) error {
	r := e.Request
	w := e.Response
	ctx := r.Context()

	_ = r.ParseForm()

	// Let's create an AuthorizeRequest object!
	// It will analyze the request and extract important information like scopes, response type and others.
	ar, err := inst.provider.NewAuthorizeRequest(ctx, r)
	if err != nil {
		e.App.Logger().Info("[Plugin/OAuth2] Error occurred in NewAuthorizeRequest", slog.Any("error", err))
		var rfc6749err *fosite.RFC6749Error
		if errors.As(err, &rfc6749err) {
			e.App.Logger().Debug(fmt.Sprintf("[Plugin/OAuth2] %s", rfc6749err.DebugField))
			e.App.Logger().Debug(fmt.Sprintf("[Plugin/OAuth2] %+v", rfc6749err.StackTrace()))
		}
		inst.provider.WriteAuthorizeError(ctx, w, ar, err)
		return nil
	}
	// You have now access to authorizeRequest, Code ResponseTypes, Scopes ...

	var u *core.Record
	var issuedAt time.Time
	var requestedAt time.Time

	if err := ar.GetRequestForm().Get("error"); err != "" {
		switch err {
		case "account_selection_required", "consent_required", "interaction_required":
			inst.provider.WriteAuthorizeError(ctx, w, ar, fosite.ErrInteractionRequired)
		case "login_required":
			inst.provider.WriteAuthorizeError(ctx, w, ar, fosite.ErrLoginRequired)
		default:
			inst.provider.WriteAuthorizeError(ctx, w, ar, fosite.ErrServerError.WithDebug(fmt.Sprintf("Unknown error: %s", err)))
		}
		return nil
	}

	if token := ar.GetRequestForm().Get("pb_token"); len(token) > 0 {
		if u, err = e.App.FindAuthRecordByToken(token); err != nil {
			if !errors.Is(err, sql.ErrNoRows) {
				return e.InternalServerError("Internal Error", err)
			}
		}
	}

	if tokenIat := ar.GetRequestForm().Get("pb_token_iat"); len(tokenIat) > 0 {
		if iatInt, err := strconv.ParseInt(tokenIat, 10, 64); err == nil {
			issuedAt = time.Unix(iatInt, 0).In(time.UTC)
		}
	}

	if rat := ar.GetRequestForm().Get("rat"); len(rat) > 0 {
		if ratInt, err := strconv.ParseInt(rat, 10, 64); err == nil {
			requestedAt = time.Unix(ratInt, 0).In(time.UTC)
		}
	}
	if requestedAt.IsZero() {
		requestedAt = ar.GetRequestedAt()
	}

	ar.GetRequestForm().Del("pb_token")
	ar.GetRequestForm().Del("pb_token_iat")

	if !ar.GetRequestForm().Has("rat") {
		ar.GetRequestForm().Set("rat", strconv.FormatInt(requestedAt.Unix(), 10))
	}

	if u == nil {
		c, _ := ar.GetClient().(*client.Client)
		state := map[string]interface{}{
			"collection":       inst.cfg.UserCollection,
			"client_id":        c.ID,
			"client_name":      c.Name,
			"client_uri":       c.ClientURI,
			"prompt":           ar.GetRequestForm().Get("prompt"),
			"max_age":          ar.GetRequestForm().Get("max_age"),
			"login_hint":       ar.GetRequestForm().Get("login_hint"),
			"requested_scopes": ar.GetRequestedScopes(),
			"redirect_uri":     e.App.Settings().Meta.AppURL + inst.cfg.PathPrefix + "/auth?" + ar.GetRequestForm().Encode(),
		}
		// Base64-URL encode the state to make it safe for URL usage.
		stateBytes, _ := json.Marshal(state)
		stateB64Str := base64.RawURLEncoding.EncodeToString(stateBytes)
		return e.Redirect(http.StatusTemporaryRedirect, e.App.Settings().Meta.AppURL+inst.cfg.PathPrefix+"/login?state="+stateB64Str)
	}

	// Check if the user belongs to the expected collection. This is optional,
	// but it can be a good way to ensure that the login hasn't been tampered
	// with.

	if u.Collection().Name != inst.cfg.UserCollection {
		return e.BadRequestError("Invalid user collection", nil)
	}

	// At this point, the user is authenticated and we can grant the requested scopes.

	for _, scope := range ar.GetRequestedScopes() {
		ar.GrantScope(scope)
	}
	// Grant the requested audiences as well. Without this, the session
	// persists granted_audience as empty, and any downstream audience
	// validation (RFC 8707, resource indicators) sees no granted scope.
	// fosite has already validated that requested audiences are allowed
	// for this client via its AudienceMatchingStrategy.
	for _, aud := range ar.GetRequestedAudience() {
		ar.GrantAudience(aud)
	}

	// Now that the user is authorized, we set up a session:
	mySessionData := NewSession(e.App, u.Id, u.Collection().Id)
	mySessionData.Claims.AuthTime = issuedAt
	mySessionData.Claims.RequestedAt = requestedAt

	var loa int = 1  // Level of Assurance (LOA)
	var amr []string // Authentication Methods References (AMR)
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

	// Now we need to get a response. This is the place where the AuthorizeEndpointHandlers kick in and start processing the request.
	// NewAuthorizeResponse is capable of running multiple response type handlers which in turn enables this library
	// to support open id connect.
	response, err := inst.provider.NewAuthorizeResponse(ctx, ar, mySessionData)

	// Catch any errors, e.g.:
	// * unknown client
	// * invalid redirect
	// * ...
	if err != nil {
		e.App.Logger().Info("[Plugin/OAuth2] Error occurred in NewAuthorizeResponse", slog.Any("error", err))
		var rfc6749err *fosite.RFC6749Error
		if errors.As(err, &rfc6749err) {
			e.App.Logger().Debug(fmt.Sprintf("[Plugin/OAuth2] %s", rfc6749err.DebugField))
			e.App.Logger().Debug(fmt.Sprintf("[Plugin/OAuth2] %+v", rfc6749err.StackTrace()))
		}
		inst.provider.WriteAuthorizeError(ctx, w, ar, err)
		return nil
	}

	// RFC 9207 — Authorization Response Issuer Identification. Include
	// "iss" in every authorization response so clients can detect
	// mix-up attacks. Advertised via
	// authorization_response_iss_parameter_supported in discovery.
	response.AddParameter("iss", e.App.Settings().Meta.AppURL)

	// Last but not least, send the response!
	inst.provider.WriteAuthorizeResponse(ctx, w, ar, response)
	return nil
}
