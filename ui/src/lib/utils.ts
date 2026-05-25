/**
 * Converts and normalizes string into a sentence.
 *
 * @param  {String}  str
 * @param  {Boolean} [stopCheck]
 * @return {String}
 */
export function sentenize(str: string, stopCheck = true): string {
    if (typeof str !== "string") {
        return "";
    }

    str = str.trim().split("_").join(" ");
    if (str === "") {
        return str;
    }

    str = str[0].toUpperCase() + str.substring(1);

    if (stopCheck) {
        let lastChar = str[str.length - 1];
        if (lastChar !== "." && lastChar !== "?" && lastChar !== "!") {
            str += ".";
        }
    }

    return str
}

/**
 * Completes a pending OAuth2 interaction by POSTing JSON to the
 * server-controlled /oauth2/login/complete endpoint, then navigates the
 * browser to the redirect_uri the server returns.
 *
 * IMPORTANT (lr7): the browser never decides where to navigate. The
 * server's stored Interaction holds the canonical redirect_uri; we just
 * follow whatever JSON we get back. A malicious /login URL therefore
 * cannot make the UI POST credentials anywhere except this same-origin
 * server endpoint.
 */
export async function completeInteraction(
    pathPrefix: string,
    payload: {
        interaction_id: string;
        pb_token?: string;
        pb_token_iat?: number;
        decision: "approve" | "deny";
        consented_scopes?: string[];
    }
): Promise<void> {
    const resp = await fetch(`${pathPrefix}/login/complete`, {
        method: "POST",
        credentials: "same-origin",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload),
    });
    if (!resp.ok) {
        const txt = await resp.text();
        throw new Error(`login/complete failed: ${resp.status} ${txt}`);
    }
    const data = await resp.json();
    if (!data.redirect_uri) {
        throw new Error("login/complete returned no redirect_uri");
    }
    window.location.assign(String(data.redirect_uri));
}

/**
 * Fetches the server-side metadata for a pending Interaction. The UI
 * uses the returned scopes / client name to render the consent screen.
 */
export async function fetchInteractionState(
    pathPrefix: string,
    interactionID: string
): Promise<{
    client_id: string;
    client_name: string;
    user_collection: string;
    requested_scopes: string[];
    granted_scopes: string[];
    prompt: string;
    expires_at: number;
}> {
    const resp = await fetch(
        `${pathPrefix}/login/state?id=${encodeURIComponent(interactionID)}`,
        { credentials: "same-origin" }
    );
    if (!resp.ok) {
        const txt = await resp.text();
        throw new Error(`login/state failed: ${resp.status} ${txt}`);
    }
    return resp.json();
}