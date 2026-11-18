package db

import (
	"context"
	"path/filepath"
	"testing"
)

func canceledContext() context.Context {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	return ctx
}

// Writes outlive a cancelled request context, as the Rust calls (which always
// run to completion) do. Each case fails if the matching WithoutCancel is
// removed.
func TestWritesIgnoreCallerCancellation(t *testing.T) {
	ctx := context.Background()
	database, err := Open(ctx, filepath.Join(t.TempDir(), "w.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = database.Close(ctx) })

	if _, err := database.AddDohToken(canceledContext(), "phone"); err != nil {
		t.Fatalf("exec write: %v", err)
	}
	tokens, err := database.GetDohTokens(ctx)
	if err != nil || len(tokens) != 1 {
		t.Fatalf("token not stored: %v %v", tokens, err)
	}

	first, err := database.CreateUser(ctx, "a", "h", 1)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := database.CreateUser(ctx, "b", "h", 1); err != nil {
		t.Fatal(err)
	}
	if _, err := database.DeleteUser(canceledContext(), first); err != nil {
		t.Fatalf("transactional write: %v", err)
	}
	count, err := database.CountUsers(ctx)
	if err != nil || count != 1 {
		t.Fatalf("users after delete = %d, %v", count, err)
	}

	sessionID, err := database.InsertSession(ctx, NewSession{TokenHash: "t", UserID: 2, CreatedAt: 1, LastSeen: 1})
	if err != nil {
		t.Fatal(err)
	}
	if _, found, err := database.DeleteSessionByID(canceledContext(), sessionID); err != nil || !found {
		t.Fatalf("returning write: found=%v err=%v", found, err)
	}
}
