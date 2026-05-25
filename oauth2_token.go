package oauth2

import (
	"errors"
	"fmt"
	"log/slog"

	"github.com/ory/fosite"
	"github.com/pocketbase/pocketbase/core"
)

func api_OAuth2Token(e *core.RequestEvent, inst *Instance) error {
	r := e.Request
	w := e.Response
	// This context will be passed to all methods.
	ctx := r.Context()
	// Create an empty session object which will be passed to the request handlers
	mySessionData := NewSession(e.App, "", "")
	// This will create an access request object and iterate through the registered TokenEndpointHandlers to validate the request.
	accessRequest, err := inst.provider.NewAccessRequest(ctx, r, mySessionData)

	// Catch any errors, e.g.:
	// * unknown client
	// * invalid redirect
	// * ...
	if err != nil {
		e.App.Logger().Info("[Plugin/OAuth2] Error occurred in NewAccessRequest", slog.Any("error", err))
		var rfc6749err *fosite.RFC6749Error
		if errors.As(err, &rfc6749err) {
			e.App.Logger().Debug(fmt.Sprintf("[Plugin/OAuth2] %s", rfc6749err.DebugField))
			e.App.Logger().Debug(fmt.Sprintf("[Plugin/OAuth2] %+v", rfc6749err.StackTrace()))
		}
		inst.provider.WriteAccessError(ctx, w, accessRequest, err)
		return nil
	}

	// client_credentials grant is intentionally not supported: the factory is
	// not registered in compose.Compose(), and discovery does not advertise
	// it. NewAccessRequest above rejects unsupported grant types before we
	// reach this point.

	// Next we create a response for the access request. Again, we iterate through the TokenEndpointHandlers
	// and aggregate the result in response.
	response, err := inst.provider.NewAccessResponse(ctx, accessRequest)
	if err != nil {
		e.App.Logger().Info("[Plugin/OAuth2] Error occurred in NewAccessResponse", slog.Any("error", err))
		var rfc6749err *fosite.RFC6749Error
		if errors.As(err, &rfc6749err) {
			e.App.Logger().Debug(fmt.Sprintf("[Plugin/OAuth2] %s", rfc6749err.DebugField))
			e.App.Logger().Debug(fmt.Sprintf("[Plugin/OAuth2] %+v", rfc6749err.StackTrace()))
		}
		inst.provider.WriteAccessError(ctx, w, accessRequest, err)
		return nil
	}

	// All done, send the response.
	// The client now has a valid access token
	inst.provider.WriteAccessResponse(ctx, w, accessRequest, response)
	return nil
}
