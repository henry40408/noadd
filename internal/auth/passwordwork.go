package auth

import (
	"context"
	"runtime"
	"sync"
)

// timingEqualisationPassword is hashed once, with the real parameters, so
// verifying against it costs what a real verification does.
const timingEqualisationPassword = "noadd::timing-equalisation::not-a-real-password"

// PasswordWork bounds concurrent Argon2 work. Each run holds about 19 MiB, so
// an unbounded burst of sign-ins could exhaust memory; the limit matches the
// core count. It does not by itself bound lockout bypass: requests queued here
// already passed IsLocked, so callers re-check the lock after the verify.
type PasswordWork struct {
	slots chan struct{}

	dummyOnce sync.Once
	dummyHash string
}

// NewPasswordWork allows limit concurrent operations; limit <= 0 means the
// CPU count.
func NewPasswordWork(limit int) *PasswordWork {
	if limit <= 0 {
		limit = runtime.NumCPU()
	}
	return &PasswordWork{slots: make(chan struct{}, limit)}
}

// Limit is the number of operations allowed at once.
func (w *PasswordWork) Limit() int { return cap(w.slots) }

// Available is the number of free slots; equals Limit when idle.
func (w *PasswordWork) Available() int { return cap(w.slots) - len(w.slots) }

// run executes work once a slot is free. The slot is held until the work
// finishes even if the caller gives up meanwhile, so a dropped request cannot
// start unbounded extra work.
func run[T any](ctx context.Context, w *PasswordWork, work func() T) (T, error) {
	var zero T
	select {
	case w.slots <- struct{}{}:
	case <-ctx.Done():
		return zero, ctx.Err()
	}
	done := make(chan T, 1)
	go func() {
		defer func() { <-w.slots }()
		done <- work()
	}()
	select {
	case result := <-done:
		return result, nil
	case <-ctx.Done():
		return zero, ctx.Err()
	}
}

// Hash is HashPassword under the concurrency limit.
func (w *PasswordWork) Hash(ctx context.Context, password string) (string, error) {
	type result struct {
		hash string
		err  error
	}
	got, err := run(ctx, w, func() result {
		hash, err := HashPassword(password)
		return result{hash, err}
	})
	if err != nil {
		return "", err
	}
	return got.hash, got.err
}

// Verify is VerifyPassword under the concurrency limit. A cancelled context is
// an error, never a verdict on the password.
func (w *PasswordWork) Verify(ctx context.Context, password, hash string) (bool, error) {
	type result struct {
		ok  bool
		err error
	}
	got, err := run(ctx, w, func() result {
		ok, err := VerifyPassword(password, hash)
		return result{ok, err}
	})
	if err != nil {
		return false, err
	}
	return got.ok, got.err
}

// SpendVerifyCost does the Argon2 work a real verification would and discards
// the answer, queued behind the same limit so padded and real paths wait
// alike. It closes the user-enumeration timing oracle: without it an unknown
// username answers before any hashing while a known one pays Argon2 first.
func (w *PasswordWork) SpendVerifyCost(ctx context.Context, password string) error {
	_, err := run(ctx, w, func() struct{} {
		w.dummyOnce.Do(func() {
			w.dummyHash, _ = HashPassword(timingEqualisationPassword)
		})
		// The verdict is meaningless by construction: the work is the product.
		_, _ = VerifyPassword(password, w.dummyHash)
		return struct{}{}
	})
	return err
}
