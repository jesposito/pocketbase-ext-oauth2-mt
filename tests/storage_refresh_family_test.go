package oauth2

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	oauth2 "github.com/jesposito/pocketbase-ext-oauth2-mt"
	"github.com/jesposito/pocketbase-ext-oauth2-mt/consts"
	"github.com/ory/fosite"
	fositeopenid "github.com/ory/fosite/handler/openid"
	"github.com/ory/fosite/token/jwt"
	"github.com/pocketbase/dbx"
	"github.com/pocketbase/pocketbase/core"
)

// makeRefreshSession is a small helper to build a fosite session usable
// in refresh-family scenarios. Each test gets its own subject so cross
// contamination is impossible if helpers ever get reordered.
func makeRefreshSession(subject string) *oauth2.Session {
	return &oauth2.Session{
		DefaultSession: fositeopenid.DefaultSession{
			Claims: &jwt.IDTokenClaims{
				Subject:   subject,
				ExpiresAt: time.Now().Add(time.Hour),
			},
			Headers: &jwt.Headers{},
			Subject: subject,
		},
	}
}

// loadRefreshRow returns the raw record for a refresh signature so tests
// can assert on the family/status columns directly without depending on
// any new public API.
func loadRefreshRow(t *testing.T, app core.App, signature string) *core.Record {
	t.Helper()
	rec, err := app.FindFirstRecordByFilter(
		consts.RefreshCollectionName,
		"signature = {:sig}",
		dbx.Params{"sig": signature},
	)
	if err != nil {
		t.Fatalf("refresh row with signature %q not found: %v", signature, err)
	}
	return rec
}

// rotate simulates what fosite's refresh-grant handler does on a valid
// rotation: call RotateRefreshToken on the predecessor, then create a
// fresh refresh+access pair with the SAME request_id as the predecessor
// (because fosite propagates the original request id via
// request.SetID(originalRequest.GetID()) before calling the storage).
func rotate(t *testing.T, store *oauth2.OAuth2Store, ctx context.Context,
	requestID, oldRefreshSig, newRefreshSig, newAccessSig string,
	session *oauth2.Session,
) {
	t.Helper()
	if err := store.RotateRefreshToken(ctx, requestID, oldRefreshSig); err != nil {
		t.Fatalf("RotateRefreshToken(%s) failed: %v", oldRefreshSig, err)
	}
	req := &fosite.Request{
		ID: requestID, Client: &fosite.DefaultClient{ID: testClientID},
		RequestedScope: fosite.Arguments{"openid"},
		GrantedScope:   fosite.Arguments{"openid"},
		Session:        session,
	}
	if err := store.CreateAccessTokenSession(ctx, newAccessSig, req); err != nil {
		t.Fatalf("CreateAccessTokenSession failed: %v", err)
	}
	if err := store.CreateRefreshTokenSession(ctx, newRefreshSig, newAccessSig, req); err != nil {
		t.Fatalf("CreateRefreshTokenSession failed: %v", err)
	}
}

// TestRefreshFamily_HappyPath issues a chain root via the
// authorization_code path and rotates three times. Every refresh row
// must share the same family_id and the parent_refresh_id chain must
// link them in order.
func TestRefreshFamily_HappyPath(t *testing.T) {
	app := setupTestApp(t)
	defer app.Cleanup()

	seedTestClient(t, app)

	store := oauth2.NewOAuth2Store(app)
	ctx := context.Background()
	session := makeRefreshSession("happy-path-user")

	// Chain root: simulate an authorization_code grant.
	rootReq := &fosite.Request{
		ID:             "happy-req-root",
		Client:         &fosite.DefaultClient{ID: testClientID},
		RequestedScope: fosite.Arguments{"openid"},
		GrantedScope:   fosite.Arguments{"openid"},
		Session:        session,
	}
	if err := store.CreateAccessTokenSession(ctx, "happy-access-0", rootReq); err != nil {
		t.Fatalf("create root access failed: %v", err)
	}
	if err := store.CreateRefreshTokenSession(ctx, "happy-refresh-0", "happy-access-0", rootReq); err != nil {
		t.Fatalf("create root refresh failed: %v", err)
	}

	root := loadRefreshRow(t, app, "happy-refresh-0")
	familyID := root.GetString("family_id")
	if familyID == "" {
		t.Fatal("chain root should be issued a family_id")
	}
	if root.GetString("parent_refresh_id") != "" {
		t.Errorf("chain root parent_refresh_id = %q, want empty", root.GetString("parent_refresh_id"))
	}
	if root.GetString("status") != "active" {
		t.Errorf("chain root status = %q, want active", root.GetString("status"))
	}

	// Rotate three times.
	rotate(t, store, ctx, "happy-req-root", "happy-refresh-0", "happy-refresh-1", "happy-access-1", session)
	rotate(t, store, ctx, "happy-req-root", "happy-refresh-1", "happy-refresh-2", "happy-access-2", session)
	rotate(t, store, ctx, "happy-req-root", "happy-refresh-2", "happy-refresh-3", "happy-access-3", session)

	// Re-read root after rotations to pick up status=rotated.
	rows := []*core.Record{
		loadRefreshRow(t, app, "happy-refresh-0"),
		loadRefreshRow(t, app, "happy-refresh-1"),
		loadRefreshRow(t, app, "happy-refresh-2"),
		loadRefreshRow(t, app, "happy-refresh-3"),
	}

	// All four rows share the family.
	for i, r := range rows {
		if got := r.GetString("family_id"); got != familyID {
			t.Errorf("row[%d] family_id = %q, want %q", i, got, familyID)
		}
	}

	// Parent chain: rows[i].parent_refresh_id == rows[i-1].id.
	for i := 1; i < len(rows); i++ {
		if got, want := rows[i].GetString("parent_refresh_id"), rows[i-1].Id; got != want {
			t.Errorf("row[%d] parent_refresh_id = %q, want row[%d].id = %q", i, got, i-1, want)
		}
	}

	// First three are rotated, last is active.
	wantStatuses := []string{"rotated", "rotated", "rotated", "active"}
	for i, r := range rows {
		if got := r.GetString("status"); got != wantStatuses[i] {
			t.Errorf("row[%d] status = %q, want %q", i, got, wantStatuses[i])
		}
		if i < 3 && r.GetInt("rotated_at") == 0 {
			t.Errorf("row[%d] rotated_at should be set after rotation", i)
		}
	}

	// Active row resolves normally.
	if _, err := store.GetRefreshTokenSession(ctx, "happy-refresh-3", &oauth2.Session{}); err != nil {
		t.Errorf("GetRefreshTokenSession on active refresh failed: %v", err)
	}
}

// TestRefreshFamily_ReuseInvalidatesDescendants replays a rotated
// refresh token and asserts that:
//   - the replay attempt returns fosite.ErrInactiveToken
//   - every refresh row in the family is marked status=reused with
//     reused_at stamped
//   - every access token whose request_id appears in the family is
//     deleted
func TestRefreshFamily_ReuseInvalidatesDescendants(t *testing.T) {
	app := setupTestApp(t)
	defer app.Cleanup()

	seedTestClient(t, app)

	store := oauth2.NewOAuth2Store(app)
	ctx := context.Background()
	session := makeRefreshSession("reuse-user")

	rootReq := &fosite.Request{
		ID:             "reuse-req-root",
		Client:         &fosite.DefaultClient{ID: testClientID},
		RequestedScope: fosite.Arguments{"openid"},
		GrantedScope:   fosite.Arguments{"openid"},
		Session:        session,
	}
	if err := store.CreateAccessTokenSession(ctx, "reuse-access-0", rootReq); err != nil {
		t.Fatalf("create access failed: %v", err)
	}
	if err := store.CreateRefreshTokenSession(ctx, "reuse-refresh-0", "reuse-access-0", rootReq); err != nil {
		t.Fatalf("create refresh failed: %v", err)
	}

	// Two legitimate rotations.
	rotate(t, store, ctx, "reuse-req-root", "reuse-refresh-0", "reuse-refresh-1", "reuse-access-1", session)
	rotate(t, store, ctx, "reuse-req-root", "reuse-refresh-1", "reuse-refresh-2", "reuse-access-2", session)

	// Sanity: the active refresh resolves and its access token exists.
	if _, err := store.GetRefreshTokenSession(ctx, "reuse-refresh-2", &oauth2.Session{}); err != nil {
		t.Fatalf("active refresh should resolve before reuse: %v", err)
	}
	if _, err := store.GetAccessTokenSession(ctx, "reuse-access-2", &oauth2.Session{}); err != nil {
		t.Fatalf("active access token should resolve before reuse: %v", err)
	}

	// Replay the original rotated refresh: this is the theft signal.
	_, err := store.GetRefreshTokenSession(ctx, "reuse-refresh-0", &oauth2.Session{})
	if err == nil {
		t.Fatal("replay of rotated refresh should fail")
	}
	if !errors.Is(err, fosite.ErrInactiveToken) {
		t.Errorf("expected fosite.ErrInactiveToken on reuse, got %v", err)
	}

	// Every refresh row in the family is now reused.
	familyID := loadRefreshRow(t, app, "reuse-refresh-0").GetString("family_id")
	rows, err := app.FindAllRecords(
		consts.RefreshCollectionName,
		dbx.HashExp{"family_id": familyID},
	)
	if err != nil {
		t.Fatalf("listing family rows failed: %v", err)
	}
	if len(rows) != 3 {
		t.Fatalf("expected 3 rows in family, got %d", len(rows))
	}
	for _, r := range rows {
		if got := r.GetString("status"); got != "reused" {
			t.Errorf("family row sig=%q status = %q, want reused", r.GetString("signature"), got)
		}
		if r.GetInt("reused_at") == 0 {
			t.Errorf("family row sig=%q reused_at should be set", r.GetString("signature"))
		}
	}

	// The active descendant refresh now also reports reuse on lookup.
	_, err = store.GetRefreshTokenSession(ctx, "reuse-refresh-2", &oauth2.Session{})
	if !errors.Is(err, fosite.ErrInactiveToken) {
		t.Errorf("descendant refresh lookup after reuse: got %v, want ErrInactiveToken", err)
	}

	// Every access token in the family must be gone. The family shares
	// one request_id, so checking any of the three access sigs works,
	// but we check all for clarity.
	for _, sig := range []string{"reuse-access-0", "reuse-access-1", "reuse-access-2"} {
		if _, err := store.GetAccessTokenSession(ctx, sig, &oauth2.Session{}); err == nil {
			t.Errorf("access token %q should be deleted after family invalidation", sig)
		}
	}
}

// TestRefreshFamily_RevokeMarksNotDeletes verifies that an explicit
// RevokeRefreshToken leaves the row in place with status=revoked rather
// than deleting it, so reuse detection retains its breadcrumb.
func TestRefreshFamily_RevokeMarksNotDeletes(t *testing.T) {
	app := setupTestApp(t)
	defer app.Cleanup()

	seedTestClient(t, app)

	store := oauth2.NewOAuth2Store(app)
	ctx := context.Background()
	session := makeRefreshSession("revoke-user")

	req := &fosite.Request{
		ID:             "revoke-family-req-1",
		Client:         &fosite.DefaultClient{ID: testClientID},
		RequestedScope: fosite.Arguments{"openid"},
		GrantedScope:   fosite.Arguments{"openid"},
		Session:        session,
	}
	if err := store.CreateRefreshTokenSession(ctx, "revoke-family-refresh", "revoke-family-access", req); err != nil {
		t.Fatalf("create refresh failed: %v", err)
	}

	if err := store.RevokeRefreshToken(ctx, "revoke-family-req-1"); err != nil {
		t.Fatalf("RevokeRefreshToken failed: %v", err)
	}

	row := loadRefreshRow(t, app, "revoke-family-refresh")
	if got := row.GetString("status"); got != "revoked" {
		t.Errorf("status after revoke = %q, want revoked", got)
	}

	// A subsequent lookup must report the token as inactive but the
	// row must still exist (loadRefreshRow above would have t.Fatal'd
	// otherwise).
	_, err := store.GetRefreshTokenSession(ctx, "revoke-family-refresh", &oauth2.Session{})
	if !errors.Is(err, fosite.ErrInactiveToken) {
		t.Errorf("lookup after revoke: got %v, want ErrInactiveToken", err)
	}
}

func TestRefreshFamily_RevokeCoversRotatedFamilyAndAccess(t *testing.T) {
	app := setupTestApp(t)
	defer app.Cleanup()
	seedTestClient(t, app)
	store := oauth2.NewOAuth2Store(app)
	ctx := context.Background()
	session := makeRefreshSession("revoke-rotated-user")
	reqID := "revoke-rotated-request"
	req := &fosite.Request{ID: reqID, Client: &fosite.DefaultClient{ID: testClientID}, Session: session}
	if err := store.CreateAccessTokenSession(ctx, "revoke-access-0", req); err != nil {
		t.Fatal(err)
	}
	if err := store.CreateRefreshTokenSession(ctx, "revoke-refresh-0", "revoke-access-0", req); err != nil {
		t.Fatal(err)
	}
	rotate(t, store, ctx, reqID, "revoke-refresh-0", "revoke-refresh-1", "revoke-access-1", session)
	rotate(t, store, ctx, reqID, "revoke-refresh-1", "revoke-refresh-2", "revoke-access-2", session)
	if err := store.RevokeRefreshToken(ctx, reqID); err != nil {
		t.Fatalf("revoke family: %v", err)
	}
	for i := 0; i < 3; i++ {
		row := loadRefreshRow(t, app, fmt.Sprintf("revoke-refresh-%d", i))
		if got := row.GetString("status"); got != oauth2.RefreshStatusRevoked {
			t.Errorf("row %d status=%q", i, got)
		}
	}
	if _, err := app.FindFirstRecordByFilter(consts.AccessCollectionName, "request_id = {:id}", dbx.Params{"id": reqID}); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("associated access rows remain or lookup failed: %v", err)
	}
}

func TestRefreshFamily_ReuseInvalidationFailuresRollbackAndPropagate(t *testing.T) {
	for _, tc := range []struct {
		name       string
		failDelete bool
	}{
		{name: "save"}, {name: "delete", failDelete: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			app := setupTestApp(t)
			defer app.Cleanup()
			seedTestClient(t, app)
			store := oauth2.NewOAuth2Store(app)
			ctx := context.Background()
			session := makeRefreshSession("fault-" + tc.name)
			reqID := "fault-request-" + tc.name
			req := &fosite.Request{ID: reqID, Client: &fosite.DefaultClient{ID: testClientID}, Session: session}
			if err := store.CreateAccessTokenSession(ctx, "fault-access-0-"+tc.name, req); err != nil {
				t.Fatal(err)
			}
			if err := store.CreateRefreshTokenSession(ctx, "fault-refresh-0-"+tc.name, "", req); err != nil {
				t.Fatal(err)
			}
			rotate(t, store, ctx, reqID, "fault-refresh-0-"+tc.name, "fault-refresh-1-"+tc.name, "fault-access-1-"+tc.name, session)
			sentinel := errors.New("injected family " + tc.name + " failure")
			if tc.failDelete {
				app.OnRecordDelete(consts.AccessCollectionName).BindFunc(func(e *core.RecordEvent) error { return sentinel })
			} else {
				app.OnRecordUpdate(consts.RefreshCollectionName).BindFunc(func(e *core.RecordEvent) error {
					if e.Record.GetString("status") == oauth2.RefreshStatusReused {
						return sentinel
					}
					return e.Next()
				})
			}
			_, err := store.GetRefreshTokenSession(ctx, "fault-refresh-0-"+tc.name, &oauth2.Session{})
			if err == nil || !errors.Is(err, sentinel) {
				t.Fatalf("reuse error=%v, want wrapped %q", err, sentinel)
			}
			root := loadRefreshRow(t, app, "fault-refresh-0-"+tc.name)
			child := loadRefreshRow(t, app, "fault-refresh-1-"+tc.name)
			if root.GetString("status") != oauth2.RefreshStatusRotated || child.GetString("status") != oauth2.RefreshStatusActive {
				t.Fatalf("failed transaction partially mutated family: root=%s child=%s", root.GetString("status"), child.GetString("status"))
			}
			if _, err := app.FindFirstRecordByFilter(consts.AccessCollectionName, "request_id = {:id}", dbx.Params{"id": reqID}); err != nil {
				t.Fatalf("failed transaction deleted access row: %v", err)
			}
			// Cleanup rolled back, but the separately committed request tombstone
			// must still make every physically surviving access row unusable.
			if _, err := store.GetAccessTokenSession(ctx, "fault-access-1-"+tc.name, &oauth2.Session{}); !errors.Is(err, fosite.ErrInactiveToken) {
				t.Fatalf("surviving access error=%v, want ErrInactiveToken", err)
			}
		})
	}
}

// TestRefreshFamily_TerminalAuthorityWinsRotateCreateGap uses explicit channel
// barriers around the same three separate calls Fosite makes during refresh:
// RotateRefreshToken, CreateAccessTokenSession, CreateRefreshTokenSession.
// Reuse or revocation is injected after the winning rotate and before the two
// creates. The winner must not resurrect a new active root/child and its
// candidate access row must be removed.
func TestRefreshFamily_TerminalAuthorityWinsRotateCreateGap(t *testing.T) {
	tests := []struct {
		name       string
		seedChild  bool
		invalidate func(t *testing.T, store *oauth2.OAuth2Store, ctx context.Context, requestID, winnerSig, rootSig string)
		wantStatus string
	}{
		{
			name: "same-token CAS loser",
			invalidate: func(t *testing.T, store *oauth2.OAuth2Store, ctx context.Context, requestID, winnerSig, _ string) {
				t.Helper()
				if err := store.RotateRefreshToken(ctx, requestID, winnerSig); !errors.Is(err, fosite.ErrInactiveToken) {
					t.Fatalf("CAS loser error=%v, want ErrInactiveToken", err)
				}
			},
			wantStatus: oauth2.RefreshStatusReused,
		},
		{
			name: "same-token lookup replay",
			invalidate: func(t *testing.T, store *oauth2.OAuth2Store, ctx context.Context, requestID, winnerSig, _ string) {
				t.Helper()
				if _, err := store.GetRefreshTokenSession(ctx, winnerSig, &oauth2.Session{}); !errors.Is(err, fosite.ErrInactiveToken) {
					t.Fatalf("same-token replay error=%v, want ErrInactiveToken", err)
				}
				if err := store.DeleteRefreshTokenSession(ctx, winnerSig); err != nil {
					t.Fatalf("delete reused signature: %v", err)
				}
				if err := store.RevokeRefreshToken(ctx, requestID); err != nil {
					t.Fatalf("revoke replayed family: %v", err)
				}
				if err := store.RevokeAccessToken(ctx, requestID); err != nil {
					t.Fatalf("revoke replayed access: %v", err)
				}
			},
			wantStatus: oauth2.RefreshStatusRevoked,
		},
		{
			name:      "older-token replay",
			seedChild: true,
			invalidate: func(t *testing.T, store *oauth2.OAuth2Store, ctx context.Context, requestID, _, rootSig string) {
				t.Helper()
				if _, err := store.GetRefreshTokenSession(ctx, rootSig, &oauth2.Session{}); !errors.Is(err, fosite.ErrInactiveToken) {
					t.Fatalf("older-token replay error=%v, want ErrInactiveToken", err)
				}
				// Mirror Fosite's handleRefreshTokenReuse cleanup. The reused
				// signature must remain as a terminal tombstone through these
				// separate calls so the paused winner cannot create a new root.
				if err := store.DeleteRefreshTokenSession(ctx, rootSig); err != nil {
					t.Fatalf("delete reused signature: %v", err)
				}
				if err := store.RevokeRefreshToken(ctx, requestID); err != nil {
					t.Fatalf("revoke replayed family: %v", err)
				}
				if err := store.RevokeAccessToken(ctx, requestID); err != nil {
					t.Fatalf("revoke replayed access: %v", err)
				}
			},
			wantStatus: oauth2.RefreshStatusRevoked,
		},
		{
			name: "explicit revoke",
			invalidate: func(t *testing.T, store *oauth2.OAuth2Store, ctx context.Context, requestID, _, _ string) {
				t.Helper()
				if err := store.RevokeRefreshToken(ctx, requestID); err != nil {
					t.Fatalf("revoke in Rotate/Create gap: %v", err)
				}
			},
			wantStatus: oauth2.RefreshStatusRevoked,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			app := setupTestApp(t)
			defer app.Cleanup()
			seedTestClient(t, app)
			store := oauth2.NewOAuth2Store(app)
			ctx := context.Background()
			session := makeRefreshSession("gap-" + tc.name)
			requestID := "gap-request-" + tc.name
			req := &fosite.Request{ID: requestID, Client: &fosite.DefaultClient{ID: testClientID}, Session: session}
			rootSig := "gap-root-" + tc.name
			winnerSig := rootSig
			if err := store.CreateAccessTokenSession(ctx, "gap-access-root-"+tc.name, req); err != nil {
				t.Fatal(err)
			}
			if err := store.CreateRefreshTokenSession(ctx, rootSig, "gap-access-root-"+tc.name, req); err != nil {
				t.Fatal(err)
			}
			if tc.seedChild {
				winnerSig = "gap-child-" + tc.name
				rotate(t, store, ctx, requestID, rootSig, winnerSig, "gap-access-child-"+tc.name, session)
			}

			rotated := make(chan error, 1)
			resume := make(chan struct{})
			winnerDone := make(chan error, 1)
			candidateAccess := "gap-access-candidate-" + tc.name
			candidateRefresh := "gap-refresh-candidate-" + tc.name
			go func() {
				if err := store.RotateRefreshToken(ctx, requestID, winnerSig); err != nil {
					rotated <- err
					return
				}
				rotated <- nil
				<-resume
				if err := store.CreateAccessTokenSession(ctx, candidateAccess, req); err != nil {
					winnerDone <- fmt.Errorf("candidate access: %w", err)
					return
				}
				winnerDone <- store.CreateRefreshTokenSession(ctx, candidateRefresh, candidateAccess, req)
			}()

			if err := <-rotated; err != nil {
				t.Fatalf("winning rotate: %v", err)
			}
			tc.invalidate(t, store, ctx, requestID, winnerSig, rootSig)
			close(resume)
			if err := <-winnerDone; !errors.Is(err, fosite.ErrInactiveToken) {
				t.Fatalf("winner replacement error=%v, want ErrInactiveToken", err)
			}

			rows, err := app.FindAllRecords(consts.RefreshCollectionName, dbx.HashExp{"request_id": requestID})
			if err != nil {
				t.Fatal(err)
			}
			for _, row := range rows {
				if got := row.GetString("status"); got != tc.wantStatus {
					t.Errorf("refresh %q status=%q, want %q", row.GetString("signature"), got, tc.wantStatus)
				}
				if row.GetString("signature") == candidateRefresh {
					t.Error("candidate refresh survived terminal authority")
				}
			}
			if _, err := store.GetAccessTokenSession(ctx, candidateAccess, &oauth2.Session{}); !errors.Is(err, fosite.ErrNotFound) {
				t.Fatalf("candidate access error=%v, want ErrNotFound", err)
			}
		})
	}
}

func TestRefreshFamily_PredecessorDeletedBetweenReadAndRotateFailsClosed(t *testing.T) {
	app := setupTestApp(t)
	defer app.Cleanup()
	seedTestClient(t, app)
	store := oauth2.NewOAuth2Store(app)
	ctx := context.Background()
	requestID := "deleted-predecessor-request"
	req := &fosite.Request{ID: requestID, Client: &fosite.DefaultClient{ID: testClientID}, Session: makeRefreshSession("deleted-predecessor")}
	if err := store.CreateAccessTokenSession(ctx, "deleted-predecessor-access", req); err != nil {
		t.Fatal(err)
	}
	if err := store.CreateRefreshTokenSession(ctx, "deleted-predecessor-refresh", "deleted-predecessor-access", req); err != nil {
		t.Fatal(err)
	}
	// First request has already read and validated the refresh session.
	if _, err := store.GetRefreshTokenSession(ctx, "deleted-predecessor-refresh", &oauth2.Session{}); err != nil {
		t.Fatal(err)
	}
	// Cleanup wins before that request reaches Rotate.
	if err := store.DeleteRefreshTokenSession(ctx, "deleted-predecessor-refresh"); err != nil {
		t.Fatal(err)
	}
	if err := store.RotateRefreshToken(ctx, requestID, "deleted-predecessor-refresh"); !errors.Is(err, fosite.ErrInactiveToken) {
		t.Fatalf("missing predecessor rotation error=%v, want ErrInactiveToken", err)
	}
	if _, err := store.GetAccessTokenSession(ctx, "deleted-predecessor-access", &oauth2.Session{}); !errors.Is(err, fosite.ErrNotFound) {
		t.Fatalf("predecessor access error=%v, want ErrNotFound", err)
	}

	// Even if a paused/misbehaving caller ignores Rotate's error, the durable
	// request tombstone refuses both the late access and a fallback root.
	if err := store.CreateAccessTokenSession(ctx, "deleted-predecessor-late-access", req); !errors.Is(err, fosite.ErrInactiveToken) {
		t.Fatalf("late access create error=%v, want ErrInactiveToken", err)
	}
	if err := store.CreateRefreshTokenSession(ctx, "deleted-predecessor-late-refresh", "deleted-predecessor-late-access", req); !errors.Is(err, fosite.ErrInactiveToken) {
		t.Fatalf("late root error=%v, want ErrInactiveToken", err)
	}
	if _, err := app.FindFirstRecordByFilter(
		consts.RefreshCollectionName,
		"signature = {:sig}",
		dbx.Params{"sig": "deleted-predecessor-late-refresh"},
	); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("late root exists or lookup failed: %v", err)
	}
	if _, err := store.GetAccessTokenSession(ctx, "deleted-predecessor-late-access", &oauth2.Session{}); !errors.Is(err, fosite.ErrNotFound) {
		t.Fatalf("late access error=%v, want ErrNotFound", err)
	}
}

func TestRefreshFamily_TerminalCreateCleanupFailurePropagatesAndAccessFailsClosed(t *testing.T) {
	app := setupTestApp(t)
	defer app.Cleanup()
	seedTestClient(t, app)
	store := oauth2.NewOAuth2Store(app)
	ctx := context.Background()
	session := makeRefreshSession("terminal-cleanup-fault")
	requestID := "terminal-cleanup-fault-request"
	req := &fosite.Request{ID: requestID, Client: &fosite.DefaultClient{ID: testClientID}, Session: session}
	if err := store.CreateRefreshTokenSession(ctx, "terminal-cleanup-root", "", req); err != nil {
		t.Fatal(err)
	}
	if err := store.CreateAccessTokenSession(ctx, "terminal-cleanup-access", req); err != nil {
		t.Fatal(err)
	}
	sentinel := errors.New("injected terminal access cleanup failure")
	app.OnRecordDelete(consts.AccessCollectionName).BindFunc(func(e *core.RecordEvent) error {
		if e.Record.GetString("signature") == "terminal-cleanup-access" {
			return sentinel
		}
		return e.Next()
	})
	if err := store.RevokeRefreshToken(ctx, requestID); !errors.Is(err, sentinel) {
		t.Fatalf("revoke error=%v, want wrapped cleanup failure", err)
	}
	if err := store.CreateRefreshTokenSession(ctx, "terminal-cleanup-child", "terminal-cleanup-access", req); !errors.Is(err, sentinel) {
		t.Fatalf("create error=%v, want wrapped cleanup failure", err)
	}
	if _, err := app.FindFirstRecordByFilter(
		consts.RefreshCollectionName,
		"signature = {:sig}",
		dbx.Params{"sig": "terminal-cleanup-child"},
	); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("terminal child exists or lookup failed: %v", err)
	}
	// The injected delete leaves the access row physically present, but
	// terminal family authority is checked on every read, so it cannot be used.
	if _, err := store.GetAccessTokenSession(ctx, "terminal-cleanup-access", &oauth2.Session{}); !errors.Is(err, fosite.ErrInactiveToken) {
		t.Fatalf("orphan access error=%v, want ErrInactiveToken", err)
	}
}

func TestRefreshFamily_TombstoneCoversLongAccessAndSurvivesCleanupFailure(t *testing.T) {
	app := setupTestApp(t)
	defer app.Cleanup()
	seedTestClient(t, app)
	store := oauth2.NewOAuth2Store(app)
	ctx := context.Background()
	now := time.Now()
	accessExpiry := now.Add(72 * time.Hour)
	refreshExpiry := now.Add(time.Hour)
	session := makeRefreshSession("long-access-short-refresh")
	session.SetExpiresAt(fosite.AccessToken, accessExpiry)
	session.SetExpiresAt(fosite.RefreshToken, refreshExpiry)
	requestID := "long-access-short-refresh-request"
	req := &fosite.Request{ID: requestID, Client: &fosite.DefaultClient{ID: testClientID}, RequestedAt: now, Session: session}
	if err := store.CreateAccessTokenSession(ctx, "long-access-token", req); err != nil {
		t.Fatal(err)
	}
	if err := store.CreateRefreshTokenSession(ctx, "short-refresh-token", "long-access-token", req); err != nil {
		t.Fatal(err)
	}
	sentinel := errors.New("injected long access cleanup failure")
	app.OnRecordDelete(consts.AccessCollectionName).BindFunc(func(e *core.RecordEvent) error {
		if e.Record.GetString("signature") == "long-access-token" {
			return sentinel
		}
		return e.Next()
	})
	if err := store.RevokeRefreshToken(ctx, requestID); !errors.Is(err, sentinel) {
		t.Fatalf("revoke error=%v, want wrapped %q", err, sentinel)
	}
	tombstone, err := app.FindFirstRecordByFilter(
		consts.RefreshTombstoneCollectionName,
		"provider_prefix = {:prefix} && request_id = {:request}",
		dbx.Params{"prefix": oauth2.DefaultPathPrefix, "request": requestID},
	)
	if err != nil {
		t.Fatal(err)
	}
	if got := int64(tombstone.GetInt("expires_at")); got < accessExpiry.Unix() {
		t.Fatalf("tombstone expiry=%d, want at least long access expiry=%d", got, accessExpiry.Unix())
	}

	// Simulate an under-budget marker left by an older build. Cleanup must
	// repair, not delete, it while the failed access cleanup leaves a row that
	// could otherwise authorize beyond the short refresh lifetime.
	tombstone.Set("expires_at", now.Add(-time.Hour).Unix())
	if err := app.Save(tombstone); err != nil {
		t.Fatal(err)
	}
	for _, job := range app.Cron().Jobs() {
		if job.Id() == consts.CleanupExpiredSessionsJobName {
			job.Run()
		}
	}
	tombstone, err = app.FindFirstRecordByFilter(
		consts.RefreshTombstoneCollectionName,
		"provider_prefix = {:prefix} && request_id = {:request}",
		dbx.Params{"prefix": oauth2.DefaultPathPrefix, "request": requestID},
	)
	if err != nil {
		t.Fatalf("cleanup removed live-artifact tombstone: %v", err)
	}
	if got := int64(tombstone.GetInt("expires_at")); got < accessExpiry.Unix() {
		t.Fatalf("cleanup repaired expiry=%d, want at least %d", got, accessExpiry.Unix())
	}
	if _, err := store.GetAccessTokenSession(ctx, "long-access-token", &oauth2.Session{}); !errors.Is(err, fosite.ErrInactiveToken) {
		t.Fatalf("surviving long access error=%v, want ErrInactiveToken", err)
	}
}

func TestRefreshFamily_ExistingRequestIDCannotCreateSecondRoot(t *testing.T) {
	app := setupTestApp(t)
	defer app.Cleanup()
	seedTestClient(t, app)
	store := oauth2.NewOAuth2Store(app)
	ctx := context.Background()
	req := &fosite.Request{ID: "duplicate-root-request", Client: &fosite.DefaultClient{ID: testClientID}, Session: makeRefreshSession("duplicate-root")}
	if err := store.CreateRefreshTokenSession(ctx, "duplicate-root-first", "", req); err != nil {
		t.Fatal(err)
	}
	if err := store.CreateAccessTokenSession(ctx, "duplicate-root-access", req); err != nil {
		t.Fatal(err)
	}
	if err := store.CreateRefreshTokenSession(ctx, "duplicate-root-second", "duplicate-root-access", req); !errors.Is(err, fosite.ErrSerializationFailure) {
		t.Fatalf("second root error=%v, want ErrSerializationFailure", err)
	}
	rows, err := app.FindAllRecords(consts.RefreshCollectionName, dbx.HashExp{"request_id": "duplicate-root-request"})
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 || rows[0].GetString("signature") != "duplicate-root-first" || rows[0].GetString("status") != oauth2.RefreshStatusActive {
		t.Fatalf("request-id authority changed: %#v", rows)
	}
	if _, err := store.GetAccessTokenSession(ctx, "duplicate-root-access", &oauth2.Session{}); !errors.Is(err, fosite.ErrNotFound) {
		t.Fatalf("rejected second-root access error=%v, want ErrNotFound", err)
	}
}

func TestRefreshFamily_CASLoserInvalidationFailuresRollbackAndPropagate(t *testing.T) {
	for _, tc := range []struct {
		name       string
		failDelete bool
	}{
		{name: "save"}, {name: "delete", failDelete: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			app := setupTestApp(t)
			defer app.Cleanup()
			seedTestClient(t, app)
			store := oauth2.NewOAuth2Store(app)
			ctx := context.Background()
			session := makeRefreshSession("cas-fault-" + tc.name)
			requestID := "cas-fault-request-" + tc.name
			req := &fosite.Request{ID: requestID, Client: &fosite.DefaultClient{ID: testClientID}, Session: session}
			rootAccess := "cas-fault-root-access-" + tc.name
			rootRefresh := "cas-fault-refresh-" + tc.name
			candidateAccess := "cas-fault-access-" + tc.name
			candidateRefresh := "cas-fault-child-" + tc.name
			if err := store.CreateAccessTokenSession(ctx, rootAccess, req); err != nil {
				t.Fatal(err)
			}
			if err := store.CreateRefreshTokenSession(ctx, rootRefresh, rootAccess, req); err != nil {
				t.Fatal(err)
			}

			// Pause the winning Fosite flow after Rotate + CreateAccess but before
			// CreateRefresh. The replay below loses Rotate's CAS while cleanup is
			// faulted, then the winner resumes against the durable tombstone.
			winnerReady := make(chan error, 1)
			resumeWinner := make(chan struct{})
			winnerDone := make(chan error, 1)
			go func() {
				if err := store.RotateRefreshToken(ctx, requestID, rootRefresh); err != nil {
					winnerReady <- err
					return
				}
				if err := store.CreateAccessTokenSession(ctx, candidateAccess, req); err != nil {
					winnerReady <- err
					return
				}
				winnerReady <- nil
				<-resumeWinner
				winnerDone <- store.CreateRefreshTokenSession(ctx, candidateRefresh, candidateAccess, req)
			}()
			if err := <-winnerReady; err != nil {
				t.Fatalf("winner did not reach Rotate/Create gap: %v", err)
			}

			sentinel := errors.New("injected CAS loser " + tc.name + " failure")
			if tc.failDelete {
				app.OnRecordDelete(consts.AccessCollectionName).BindFunc(func(e *core.RecordEvent) error {
					if e.Record.GetString("signature") == candidateAccess {
						return sentinel
					}
					return e.Next()
				})
			} else {
				app.OnRecordUpdate(consts.RefreshCollectionName).BindFunc(func(e *core.RecordEvent) error {
					if e.Record.GetString("status") == oauth2.RefreshStatusReused {
						return sentinel
					}
					return e.Next()
				})
			}
			loserErr := store.RotateRefreshToken(ctx, requestID, rootRefresh)
			close(resumeWinner)
			winnerErr := <-winnerDone
			if !errors.Is(loserErr, sentinel) {
				t.Fatalf("CAS loser error=%v, want wrapped %q", loserErr, sentinel)
			}
			if tc.failDelete {
				if !errors.Is(winnerErr, sentinel) {
					t.Fatalf("resumed winner error=%v, want wrapped %q", winnerErr, sentinel)
				}
			} else if !errors.Is(winnerErr, fosite.ErrInactiveToken) {
				t.Fatalf("resumed winner error=%v, want ErrInactiveToken", winnerErr)
			}

			row := loadRefreshRow(t, app, rootRefresh)
			if got := row.GetString("status"); got != oauth2.RefreshStatusRotated {
				t.Fatalf("failed invalidation partially changed status=%q", got)
			}
			if _, err := app.FindFirstRecordByFilter(consts.RefreshCollectionName, "signature = {:sig}", dbx.Params{"sig": candidateRefresh}); !errors.Is(err, sql.ErrNoRows) {
				t.Fatalf("resumed winner minted a refresh child or lookup failed: %v", err)
			}
			if _, err := store.GetAccessTokenSession(ctx, candidateAccess, &oauth2.Session{}); !errors.Is(err, fosite.ErrInactiveToken) && !errors.Is(err, fosite.ErrNotFound) {
				t.Fatalf("resumed winner access remains usable: %v", err)
			}
			if _, err := app.FindFirstRecordByFilter(
				consts.RefreshTombstoneCollectionName,
				"provider_prefix = {:prefix} && request_id = {:request}",
				dbx.Params{"prefix": oauth2.DefaultPathPrefix, "request": requestID},
			); err != nil {
				t.Fatalf("durable terminal authority missing after cleanup rollback: %v", err)
			}
		})
	}
}

// TestRefreshFamily_ConcurrentRotation_AtMostOneWinner verifies that one
// caller may drive active→rotated, while every CAS loser treats the already
// rotated token as reuse and tombstones the family. No loser may continue to
// mint a sibling and the winner's not-yet-created child is subsequently
// refused by CreateRefreshTokenSession.
func TestRefreshFamily_ConcurrentRotation_AtMostOneWinner(t *testing.T) {
	app := setupTestApp(t)
	defer app.Cleanup()

	seedTestClient(t, app)

	store := oauth2.NewOAuth2Store(app)
	ctx := context.Background()
	session := makeRefreshSession("race-user")

	req := &fosite.Request{
		ID:             "race-req-root",
		Client:         &fosite.DefaultClient{ID: testClientID},
		RequestedScope: fosite.Arguments{"openid"},
		GrantedScope:   fosite.Arguments{"openid"},
		Session:        session,
	}
	if err := store.CreateAccessTokenSession(ctx, "race-access-0", req); err != nil {
		t.Fatalf("create access failed: %v", err)
	}
	if err := store.CreateRefreshTokenSession(ctx, "race-refresh-0", "race-access-0", req); err != nil {
		t.Fatalf("create refresh failed: %v", err)
	}

	const workers = 8
	var (
		wg      sync.WaitGroup
		start   = make(chan struct{})
		results = make([]error, workers)
	)
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			<-start
			results[idx] = store.RotateRefreshToken(ctx, "race-req-root", "race-refresh-0")
		}(i)
	}
	close(start)
	wg.Wait()

	winners := 0
	reuseLosers := 0
	otherErrs := []error{}
	for _, err := range results {
		switch {
		case err == nil:
			winners++
		case errors.Is(err, fosite.ErrInactiveToken):
			reuseLosers++
		default:
			otherErrs = append(otherErrs, err)
		}
	}
	if winners != 1 {
		t.Errorf("expected exactly 1 winner, got %d (reuse losers=%d, other=%v)",
			winners, reuseLosers, otherErrs)
	}
	if reuseLosers != workers-1 {
		t.Errorf("expected %d losers with ErrInactiveToken, got %d (winners=%d, other=%v)",
			workers-1, reuseLosers, winners, otherErrs)
	}
	if len(otherErrs) > 0 {
		t.Errorf("unexpected error(s) from rotation: %v", otherErrs)
	}

	// Final state: one loser durably converted the family into a reuse
	// tombstone, so even the winner cannot later create an active child.
	row := loadRefreshRow(t, app, "race-refresh-0")
	if got := row.GetString("status"); got != oauth2.RefreshStatusReused {
		t.Errorf("final status = %q, want reused", got)
	}
	if row.GetInt("rotated_at") == 0 {
		t.Errorf("rotated_at must be stamped on winner")
	}
	replacement := &fosite.Request{ID: "race-req-root", Client: &fosite.DefaultClient{ID: testClientID}, Session: session}
	if err := store.CreateAccessTokenSession(ctx, "race-access-late", replacement); !errors.Is(err, fosite.ErrInactiveToken) {
		t.Fatalf("late winner access error=%v, want ErrInactiveToken", err)
	}
	if err := store.CreateRefreshTokenSession(ctx, "race-refresh-late", "race-access-late", replacement); !errors.Is(err, fosite.ErrInactiveToken) {
		t.Fatalf("late winner create error=%v, want ErrInactiveToken", err)
	}
	if _, err := app.FindFirstRecordByFilter(
		consts.RefreshCollectionName,
		"signature = {:sig}",
		dbx.Params{"sig": "race-refresh-late"},
	); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("late active child exists or lookup failed: %v", err)
	}
	if _, err := store.GetAccessTokenSession(ctx, "race-access-late", &oauth2.Session{}); !errors.Is(err, fosite.ErrNotFound) {
		t.Fatalf("late replacement access error=%v, want ErrNotFound", err)
	}
}
