package oauth2

import (
	"context"
	"errors"
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

// TestRefreshFamily_ConcurrentRotation_AtMostOneWinner verifies the race
// fix on RotateRefreshToken. N goroutines all try to rotate the same
// predecessor refresh signature simultaneously. Exactly ONE must succeed
// (drives the active→rotated transition) and every other caller must
// receive fosite.ErrSerializationFailure. Without the conditional UPDATE
// fix, multiple callers could all observe status=active in
// GetRefreshTokenSession, then all silently no-op in markRefreshRotated's
// pre-fix "already rotated → return nil" branch, allowing the upstream
// refresh-grant handler to mint sibling children from the same parent.
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
		wg        sync.WaitGroup
		start     = make(chan struct{})
		results   = make([]error, workers)
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
	losers := 0
	otherErrs := []error{}
	for _, err := range results {
		switch {
		case err == nil:
			winners++
		case errors.Is(err, fosite.ErrSerializationFailure):
			losers++
		default:
			otherErrs = append(otherErrs, err)
		}
	}
	if winners != 1 {
		t.Errorf("expected exactly 1 winner, got %d (losers=%d, other=%v)",
			winners, losers, otherErrs)
	}
	if losers != workers-1 {
		t.Errorf("expected %d losers with ErrSerializationFailure, got %d (winners=%d, other=%v)",
			workers-1, losers, winners, otherErrs)
	}
	if len(otherErrs) > 0 {
		t.Errorf("unexpected error(s) from rotation: %v", otherErrs)
	}

	// Final state: row is rotated exactly once.
	row := loadRefreshRow(t, app, "race-refresh-0")
	if got := row.GetString("status"); got != "rotated" {
		t.Errorf("final status = %q, want rotated", got)
	}
	if row.GetInt("rotated_at") == 0 {
		t.Errorf("rotated_at must be stamped on winner")
	}
}

