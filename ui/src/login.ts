import Alpine from "alpinejs";
import PocketBase, { type AuthRecord, type AuthMethodsList } from "pocketbase";
import MultiAuthStore from "./lib/multi-auth-store";
import toastStore from "./lib/toast-store";
import {
    completeInteraction,
    fetchInteractionState,
    sentenize,
} from "./lib/utils";
import "./login.style.min.css";

// pathPrefix is the OAuth2 plugin's mounted prefix relative to the app
// origin. The login UI is served at <prefix>/login, so the parent dir
// of the current URL is the prefix.
const pathPrefix = window.location.pathname.replace(/\/login\/?$/, "");

//

type LoginState = {
    page: "account-selection" | "login-password" | "login-otp" | "consent";
    state: {
        passwordLoginForm: {
            submitting: boolean;
            identity: string;
            password: string;
        };
        otpLoginForm: {
            requesting: boolean;
            submitting: boolean;
            id: string;
            prevId: string;
            identity: string;
            password: string;
        };
        consentForm: {
            submitting: boolean;
        };
        mfaId: string;
        methods: AuthMethodsList | null;
        authRecord: AuthRecord | null;
        validAccountsForReq: AuthRecord[];
    };

    params: {
        interaction_id: string;
        collection: string;
        client_id: string;
        client_name: string;
        prompt: "login" | "none" | "consent" | "";
        max_age?: number;
        requested_scopes: string[];
        granted_scopes: string[];
    };

    error: string;

    //

    init: () => Promise<void>;
    isEmailIdentity(): boolean;
    showAccountSelection(): boolean;
    showLoginPassword(): boolean;
    showLoginRequestOtp(): boolean;
    showLoginOtp(): boolean;
    showConsent(): boolean;
    uiUserLabel(record: AuthRecord): string;
    uiUserLabelShort(record: AuthRecord): string;
    uiIdentityLabel(): string;
    uiClientNameLabel(): string;
    uiConsentButtonLabel(): string;
    selectAccount: (record: AuthRecord) => Promise<void>;
    switchAccount: () => void;
    newAccount: () => void;
    submitAuthWithPassword: () => Promise<void>;
    submitAuthWithOTP: () => Promise<void>;
    requestOTP: () => Promise<void>;
    submitConsent: () => Promise<void>;
    declineConsent: () => void;
    onEscape: () => void;
    focusFirstInPanel: (panelName: string) => void;
    handleSuccessfulLogin: () => void;
    handleSuccessfulConsent: () => void;
    handleErr: (err: any) => void;
};

Alpine.data<Partial<LoginState>, any>('oauth', () => {

    const pbAuthStore = new MultiAuthStore('__pb_oauth2_cache__');
    const pb = new PocketBase(window.location.origin, pbAuthStore);

    //

    const getValidAccountsForReq = (): AuthRecord[] => {
        return pbAuthStore.records
            .filter(item =>
                (
                    item.record?.collectionId === ret.params.collection ||
                    item.record?.collectionName === ret.params.collection
                ) &&
                (
                    item.iat + (ret.params.max_age ?? 0) > Math.floor(Date.now() / 1000)
                )
            )
            .map(item => item.record);
    };

    //

    const ret: LoginState = {
        page: "account-selection",
        state: {
            passwordLoginForm: {
                submitting: false,
                identity: "",
                password: ""
            },
            otpLoginForm: {
                requesting: false,
                submitting: false,
                id: "",
                prevId: "",
                identity: "",
                password: "",
            },
            consentForm: {
                submitting: false,
            },
            mfaId: "",
            methods: null,
            authRecord: null,
            validAccountsForReq: [],
        },

        params: {
            interaction_id: "",
            collection: "",
            client_id: "",
            client_name: "",
            prompt: "",
            max_age: 7 * 24 * 60 * 60, // 7 days in seconds
            requested_scopes: [],
            granted_scopes: [],
        },

        error: "",

        //

        async init() {

            this.state!.validAccountsForReq = getValidAccountsForReq();

            if (this.params.prompt === "none") {
                // prompt=none: silent attempt. Server enforces consent
                // policy (mci); the UI just forwards a token if one is
                // cached and lets the server decide.
                if (this.state.validAccountsForReq.length === 1) {
                    const cached = pbAuthStore.selectByRecord(this.state.validAccountsForReq[0])!;
                    try {
                        await completeInteraction(pathPrefix, {
                            interaction_id: this.params.interaction_id,
                            pb_token: cached.token,
                            pb_token_iat: cached.iat,
                            decision: "approve",
                            // For silent flows we offer the previously
                            // granted scopes only; the server will check
                            // coverage and reject if insufficient.
                            consented_scopes: this.params.granted_scopes,
                        });
                    } catch (err) {
                        this.handleErr(err);
                    }
                } else {
                    // No cached account (or multiple): server-side flow
                    // emits the appropriate RP redirect via
                    // login/complete with decision=deny.
                    try {
                        await completeInteraction(pathPrefix, {
                            interaction_id: this.params.interaction_id,
                            decision: "deny",
                        });
                    } catch (err) {
                        this.handleErr(err);
                    }
                }
                return;

            } else if (this.params.prompt === "consent") {
                if (this.state.validAccountsForReq.length === 1) {
                    this.state!.authRecord = pbAuthStore.selectByRecord(this.state.validAccountsForReq[0])?.record || null;
                    this.page = "consent";
                } else {
                    // TODO/conformance: Check login_hint if provided. If it matches exactly, go to consent, else go to account-selection.
                    this.page = "account-selection";
                }
            } else if (this.params.prompt === "login") {
                this.page = "login-password";
            }

            //

            try {
                this.state!.methods = await pb.collection(this.params!.collection).listAuthMethods();

                if (this.state.validAccountsForReq.length === 0 || this.params.prompt === "login") {
                    if (this.state!.methods.password.enabled) {
                        this.page = "login-password";
                    } else if (this.state!.methods.otp.enabled) {
                        this.page = "login-otp";
                    } else {
                        throw new Error("No supported authentication methods available");
                    }
                }
            } catch (err) {
                this.handleErr(err);
            }
        },

        //

        isEmailIdentity() {
            return (
                !!this.state!.methods?.password.enabled &&
                this.state!.methods.password.identityFields.length === 1 &&
                this.state!.methods.password.identityFields[0] === "email"
            );
        },

        //

        showAccountSelection() {
            return !this.error && !!this.state!.methods && this.page === "account-selection";
        },
        showLoginPassword() {
            return !this.error && !!this.state!.methods && this.page === "login-password";
        },
        showLoginRequestOtp() {
            return !this.error && !!this.state!.methods && this.page === "login-otp" && !this.state!.otpLoginForm.id;
        },
        showLoginOtp() {
            return !this.error && !!this.state!.methods && this.page === "login-otp" && !!this.state!.otpLoginForm.id;
        },
        showConsent() {
            return !this.error && !!this.state!.methods && this.page === "consent";
        },

        //

        uiUserLabel(record: AuthRecord) {
            if (!record) {
                return "Unknown Account";
            }
            if (record.name) {
                if (record.email) {
                    return `${record.name} (${record.email})`;
                } else {
                    return `${record.name} (${record.id})`;
                }
            } else if (record.email) {
                return record.email;
            } else {
                return record.id;
            }
        },
        uiUserLabelShort(record: AuthRecord) {
            if (!record) {
                return "Unknown Account";
            }
            return record.name || record.email || record.id;
        },
        uiIdentityLabel() {
            return sentenize(`${this.state!.methods?.password?.identityFields?.join(' or ') || 'Identity'}`, false);
        },
        uiClientNameLabel() {
            return this.params.client_name || `Unnamed OAuth2 Client (${this.params.client_id?.substr(0, 8)}...)`
        },
        uiConsentButtonLabel() {
            return "Authorize " + (this.params.client_name || `Third-Party App`);
        },

        //

        async selectAccount(record: AuthRecord) {
            pbAuthStore.select(pbAuthStore.findIndex(record));
            this.handleSuccessfulLogin();
        },

        async switchAccount() {
            pbAuthStore.select(-1);
            this.state!.authRecord = null;
            this.page = "account-selection";
        },

        async newAccount() {
            this.page = "login-password";
            // TODO: clear form state
        },

        async submitAuthWithPassword() {
            if (this.state!.passwordLoginForm.submitting) {
                return;
            }

            this.state!.passwordLoginForm.submitting = true;

            const identity = this.state!.passwordLoginForm.identity;
            const password = this.state!.passwordLoginForm.password;

            try {
                await pb
                    .collection(this.params!.collection)
                    .authWithPassword(identity, password)
                    .then(() => this.handleSuccessfulLogin());
            } catch (err: any) {
                if (err.status === 401) {
                    this.state!.mfaId = err.response.mfaId;

                    if (
                        this.state!.methods?.otp.enabled &&
                        this.isEmailIdentity() ||
                        (
                            // if the identity looks like an email, we can assume it's an email
                            /^[^\@\s]+@[^\@\s]+$/.test(identity)
                        )
                    ) {
                        this.page = "login-otp";
                        this.state!.otpLoginForm.identity = identity;
                        await this.requestOTP();
                    }
                } else if (err.status !== 400) {
                    this.handleErr(err);
                } else {
                    Alpine.store("toast").addToast("error", "Invalid identity or password");
                }
            }

            this.state!.passwordLoginForm.submitting = false;
        },

        async submitAuthWithOTP() {
            if (this.state!.otpLoginForm.submitting) {
                return;
            }

            this.state!.otpLoginForm.submitting = true;

            try {
                await pb
                    .collection(this.params!.collection)
                    .authWithOTP(this.state!.otpLoginForm.id || this.state!.otpLoginForm.prevId, this.state!.otpLoginForm.password, { mfaId: this.state!.mfaId })
                    .then(() => this.handleSuccessfulLogin());
            } catch (err) {
                this.handleErr(err);
            }

            this.state!.otpLoginForm.submitting = false;
        },

        async requestOTP() {
            if (this.state!.otpLoginForm.requesting) {
                return;
            }

            this.state!.otpLoginForm.requesting = true;

            try {
                const result = await pb
                    .collection(this.params!.collection)
                    .requestOTP(this.state!.otpLoginForm.identity);
                this.state!.otpLoginForm.id = result.otpId;
                this.state!.otpLoginForm.prevId = result.otpId;
            } catch (err: any) {
                if (err.status === 429) {
                    this.state!.otpLoginForm.id = this.state!.otpLoginForm.prevId;
                }
                this.handleErr(err);
            }

            this.state!.otpLoginForm.requesting = false;
        },

        async submitConsent() {
            this.state!.consentForm.submitting = true;
            this.handleSuccessfulConsent();
        },

        // declineConsent calls /login/complete with decision=deny. The
        // server returns the RP redirect (RFC 6749 §4.1.2.1
        // error=access_denied + RFC 9207 iss) and we navigate to it.
        async declineConsent() {
            try {
                await completeInteraction(pathPrefix, {
                    interaction_id: this.params.interaction_id,
                    decision: "deny",
                });
            } catch (err) {
                this.handleErr(err);
            }
        },

        // onEscape: pressing Escape on the consent panel declines the grant.
        // On other panels it does nothing so users don't lose form state by
        // accident.
        onEscape() {
            if (this.showConsent && this.showConsent()) {
                this.declineConsent();
            }
        },

        // focusFirstInPanel moves keyboard focus into the named panel so AT
        // users follow the UI when state transitions swap panels via x-show.
        // Called by selectAccount, switchAccount, newAccount, and the post-
        // login consent transition.
        focusFirstInPanel(panelName: string) {
            requestAnimationFrame(() => {
                const panel = document.querySelector(`[data-panel="${panelName}"]`) as HTMLElement | null;
                if (!panel) return;
                const target = panel.querySelector(
                    'input:not([type=hidden]), button[type=submit], h1, h2, [tabindex]:not([tabindex="-1"])'
                ) as HTMLElement | null;
                target?.focus();
            });
        },

        //

        handleSuccessfulLogin() {
            this.state!.authRecord = pbAuthStore.selected?.record || null;
            this.state!.validAccountsForReq = getValidAccountsForReq();
            
            if (this.params.prompt === "login") {
                this.handleSuccessfulConsent();
            } else {
                this.page = "consent";
            }
        },

        //

        async handleSuccessfulConsent() {
            const sel = pbAuthStore.selected;
            if (!sel) {
                this.handleErr(new Error("No selected account; cannot complete consent."));
                return;
            }
            try {
                await completeInteraction(pathPrefix, {
                    interaction_id: this.params.interaction_id,
                    pb_token: sel.token,
                    pb_token_iat: sel.iat,
                    decision: "approve",
                    consented_scopes: this.params.requested_scopes,
                });
            } catch (err) {
                this.handleErr(err);
            }
        },

        //

        handleErr(err: any) {
            // @ts-ignore
            if (!err || !(err instanceof Error) || err.isAbort) {
                return;
            }
             // @ts-ignore
            const responseData = err?.data || {};
            const msg = responseData.message || err.message || "An error occurred";
            Alpine.store("toast").addToast("error", msg);
        }
    };

    //

    // lr7: the UI no longer trusts (or even reads) a browser-supplied
    // state JSON blob. The only thing carried in the URL is the opaque
    // interaction_id. All authoritative metadata (client name, requested
    // scopes, prompt, user collection, redirect_uri) is fetched from the
    // server's /oauth2/login/state endpoint and held in memory only.
    const interactionID = new URLSearchParams(window.location.search).get("interaction_id") || "";
    if (!interactionID) {
        return { error: "Missing interaction_id" };
    }
    ret.params!.interaction_id = interactionID;

    // Block init() until the server-side state has been resolved.
    const stateLoadPromise = fetchInteractionState(pathPrefix, interactionID)
        .then((data) => {
            if (!data || !data.client_id || !data.user_collection) {
                throw new Error("Interaction state is missing required fields");
            }
            ret.params!.collection = data.user_collection;
            ret.params!.client_id = data.client_id;
            ret.params!.client_name = data.client_name || "";
            ret.params!.prompt = (data.prompt || "consent") as any;
            ret.params!.requested_scopes = (data.requested_scopes || []).map(String);
            ret.params!.granted_scopes = (data.granted_scopes || []).map(String);
        })
        .catch((err) => {
            ret.error = "Invalid or expired interaction: " + (err instanceof Error ? err.message : String(err));
        });

    const originalInit = ret.init!.bind(ret);
    ret.init = async () => {
        await stateLoadPromise;
        if (ret.error) return;
        await originalInit();
    };

    return ret;
});

//

window.Alpine = Alpine;
window.Alpine.store("toast", toastStore);
window.Alpine.start();
