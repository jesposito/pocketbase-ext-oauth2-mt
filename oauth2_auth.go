package oauth2

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/jesposito/pocketbase-ext-oauth2-mt/client"
	"github.com/ory/fosite"
	"github.com/pocketbase/pocketbase/core"
)

// cloneForm returns a deep copy of a url.Values so callers can mutate
// the result without affecting the original (e.g. stripping pb_token
// before persisting an Interaction).
func cloneForm(in url.Values) url.Values {
	out := make(url.Values, len(in))
	for k, vs := range in {
		out[k] = append([]string(nil), vs...)
	}
	return out
}

func api_OAuth2Authorize(e *core.RequestEvent, inst *Instance) error {
	r := e.Request
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
		writeAuthorizeErrorWithIss(ctx, e, inst, ar, err)
		return nil
	}
	// You have now access to authorizeRequest, Code ResponseTypes, Scopes ...

	if err := ar.GetRequestForm().Get("error"); err != "" {
		switch err {
		case "account_selection_required", "consent_required", "interaction_required":
			writeAuthorizeErrorWithIss(ctx, e, inst, ar, fosite.ErrInteractionRequired)
		case "login_required":
			writeAuthorizeErrorWithIss(ctx, e, inst, ar, fosite.ErrLoginRequired)
		case "access_denied":
			// RFC 6749 §4.1.2.1: the resource owner has denied the request
			// (e.g. clicked "Decline" on the consent screen). MUST be
			// surfaced to the client as access_denied, not server_error,
			// otherwise the RP can't distinguish "user said no" from "OP
			// crashed" and may retry indefinitely.
			writeAuthorizeErrorWithIss(ctx, e, inst, ar, fosite.ErrAccessDenied)
		default:
			writeAuthorizeErrorWithIss(ctx, e, inst, ar, fosite.ErrServerError.WithDebug(fmt.Sprintf("Unknown error: %s", err)))
		}
		return nil
	}

	// lr7: the authorize endpoint NEVER consumes a pb_token from the
	// request form. The previous design accepted it here, which combined
	// with a browser-controlled `state` parameter allowed token
	// exfiltration. Authentication is now strictly server-mediated
	// through /oauth2/login/complete, which sources the redirect_uri and
	// scopes from a server-stored Interaction.
	requestedAt := ar.GetRequestedAt()
	if rat := ar.GetRequestForm().Get("rat"); len(rat) > 0 {
		if ratInt, err := strconv.ParseInt(rat, 10, 64); err == nil {
			requestedAt = time.Unix(ratInt, 0).In(time.UTC)
		}
	}
	// Strip any inbound pb_token attempt so a malicious form param can't
	// re-enter the legacy path if any future code reads it.
	ar.GetRequestForm().Del("pb_token")
	ar.GetRequestForm().Del("pb_token_iat")
	if !ar.GetRequestForm().Has("rat") {
		ar.GetRequestForm().Set("rat", strconv.FormatInt(requestedAt.Unix(), 10))
	}

	// Store the pending authorization server-side and redirect to /login
	// carrying ONLY an opaque interaction id. The UI looks up state via
	// /login/state and completes via /login/complete. No browser-
	// controlled redirect_uri ever reaches the token-exchange path.
	c, _ := ar.GetClient().(*client.Client)
	formCopy := cloneForm(ar.GetRequestForm())
	formCopy.Del("pb_token")
	formCopy.Del("pb_token_iat")
	interactionID, ierr := CreateInteractionAt(e.App, inst.cfg.PathPrefix, &Interaction{
		ClientID:           c.ID,
		ClientName:         c.Name,
		UserCollection:     inst.cfg.UserCollection,
		RedirectURI:        c.GetRedirectURIs()[0],
		RequestForm:        formCopy,
		RequestedScopes:    ar.GetRequestedScopes(),
		RequestedAcrValues: parseAcrValues(ar.GetRequestForm().Get("acr_values")),
		Prompt:             ar.GetRequestForm().Get("prompt"),
		RequestedAt:        requestedAt,
	})
	if ierr != nil {
		return e.InternalServerError("failed to create interaction", ierr)
	}
	return e.Redirect(http.StatusTemporaryRedirect,
		e.App.Settings().Meta.AppURL+inst.cfg.PathPrefix+"/login?interaction_id="+interactionID)
}

// parseAcrValues splits the space-separated acr_values parameter from
// the authorize request into a slice. Empty / blank input → nil. Per
// OIDC Core §3.1.2.1 the value is a space-separated list of voluntary
// requested Authentication Context Class References, ordered by
// preference (first = highest priority). We preserve the order so the
// consumer can apply that preference verbatim.
func parseAcrValues(raw string) []string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil
	}
	parts := strings.Fields(raw)
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

// writeAuthorizeErrorWithIss writes a fosite authorize error response with
// the RFC 9207 "iss" parameter appended to the error redirect (query,
// fragment, and form_post response modes). When the redirect_uri is
// missing/invalid, no redirect happens and a JSON error is written — iss
// MUST NOT be included in that response because there is no client-bound
// channel to attach it to (per RFC 9207 §2.3).
//
// This mirrors fosite.WriteAuthorizeError (authorize_error.go) but adds iss
// to the parameter set. The mirror is intentional: fosite has no public
// hook for "add a parameter to the error response", and wrapping
// http.ResponseWriter to mutate the Location header after the fact is
// fragile against the form_post template path. Keep this in sync with
// fosite's logic on major version bumps.
func writeAuthorizeErrorWithIss(ctx context.Context, e *core.RequestEvent, inst *Instance, ar fosite.AuthorizeRequester, oerr error) {
	rw := e.Response
	iss := providerIssuer(e.App, inst.cfg)
	cfg := inst.cfg.BaseConfig

	rw.Header().Set("Cache-Control", "no-store")
	rw.Header().Set("Pragma", "no-cache")

	rfcerr := fosite.ErrorToRFC6749Error(oerr).
		WithLegacyFormat(cfg.GetUseLegacyErrorFormat(ctx)).
		WithExposeDebug(cfg.GetSendDebugMessagesToClients(ctx))

	if !ar.IsRedirectURIValid() {
		// No redirect possible. RFC 9207 §2.3: iss is only on
		// redirect-based responses.
		rw.Header().Set("Content-Type", "application/json;charset=UTF-8")
		js, jerr := json.Marshal(rfcerr)
		if jerr != nil {
			http.Error(rw, `{"error":"server_error"}`, http.StatusInternalServerError)
			return
		}
		rw.WriteHeader(rfcerr.CodeField)
		_, _ = rw.Write(js)
		return
	}

	redirectURI := ar.GetRedirectURI()
	// "The endpoint URI MUST NOT include a fragment component." (RFC 6749 §3.1.2)
	redirectURI.Fragment = ""

	params := rfcerr.ToValues()
	params.Set("state", ar.GetState())
	params.Set("iss", iss)

	if ar.GetResponseMode() == fosite.ResponseModeFormPost {
		rw.Header().Set("Content-Type", "text/html;charset=UTF-8")
		tpl := fosite.DefaultFormPostTemplate
		if f, ok := inst.provider.(*fosite.Fosite); ok {
			tpl = fosite.GetPostFormHTMLTemplate(ctx, f)
		}
		fosite.WriteAuthorizeFormPostResponse(redirectURI.String(), params, tpl, rw)
		return
	}

	var redirectURIString string
	if ar.GetResponseMode() == fosite.ResponseModeFragment {
		redirectURIString = redirectURI.String() + "#" + params.Encode()
	} else {
		// query mode (default for code response_type)
		for key, values := range redirectURI.Query() {
			for _, value := range values {
				params.Add(key, value)
			}
		}
		redirectURI.RawQuery = params.Encode()
		redirectURIString = redirectURI.String()
	}

	rw.Header().Set("Location", redirectURIString)
	rw.WriteHeader(http.StatusSeeOther)
}
