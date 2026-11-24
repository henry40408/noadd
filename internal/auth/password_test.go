package auth

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

// Rust: test_password_hash_and_verify
func TestHashAndVerify(t *testing.T) {
	hash, err := HashPassword("my_secure_password_123")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(hash, "$argon2id$v=19$m=19456,t=2,p=1$") {
		t.Fatalf("unexpected PHC prefix: %s", hash)
	}
	if ok, err := VerifyPassword("my_secure_password_123", hash); !ok || err != nil {
		t.Fatalf("right password: ok=%v err=%v", ok, err)
	}
	if ok, err := VerifyPassword("wrong_password", hash); ok || err != nil {
		t.Fatalf("wrong password: ok=%v err=%v", ok, err)
	}
}

func TestHashesUseFreshSalts(t *testing.T) {
	first, _ := HashPassword("same password")
	second, _ := HashPassword("same password")
	if first == second {
		t.Fatal("two hashes of one password must differ")
	}
}

// Rust: a_hash_written_by_the_previous_argon2_still_verifies
func TestHashWrittenByRustStillVerifies(t *testing.T) {
	stored := "$argon2id$v=19$m=19456,t=2,p=1$CFgBxAxypIe+BAv7VNQH0A$cMNXkJbVMEIFcFx0ets3cdrhZEbcp5IAIs5lkC2ppaQ"
	if ok, err := VerifyPassword("correct horse battery staple", stored); !ok || err != nil {
		t.Fatalf("ok=%v err=%v", ok, err)
	}
	if ok, _ := VerifyPassword("not the password", stored); ok {
		t.Fatal("wrong password verified")
	}
}

// rustPasswordVectors are argon2id hashes (m=19456,t=2,p=1) written by the Rust
// server 0.41.1. They are never regenerated from Go output.
var rustPasswordVectors = []struct{ username, password, phc string }{
	{"admin", "correct horse battery", "$argon2id$v=19$m=19456,t=2,p=1$a6HbvUBHXd81hVLaT7XBKA$IQ38bNVwFOCsLh0vem2N1oYI3GTv/qbAYs7Bg8qhWgQ"},
	{"second", "another long passphrase 42", "$argon2id$v=19$m=19456,t=2,p=1$hLp14PeCkaRxg/at+jJlsg$NPvrGiWQ5rZcFaozvkf2YbSNqULTWM3WuPWbw7jkUKk"},
	{"cjk-user", "這是一個很長的中文密碼測試用的密碼", "$argon2id$v=19$m=19456,t=2,p=1$X5Fj3nRFvDUl6f3Pxgu40g$neKymKhsfJZwYCeFzhNGzahJWp/JZB4cU7baBPWjpJA"},
}

// rustTokenVectors are unsalted BLAKE2b-512 digests (lower hex) of the token
// string, written by the Rust server 0.41.1.
var rustTokenVectors = []struct{ kind, token, digest string }{
	{"api_key", "noadd_CifGOW4zNCuriUmy9HIDnwGHfGpg3CzdcJ7oFz5D", "208bf4513fafc42e3de165f4b95c1aa035b4a212ef807f2dc4c2dc3c5a704976e6d53d14e7136c54e89300cc0e6934309ec1403756e47617671021b286865d48"},
	{"api_key", "noadd_O3lQsU5VJMRtSrkUoTBTDtcMEfQEGga4sjtjJryN", "12a998c60382c04f3f8dc68efbc590d67340c7cff74a954781532c307d02849b89d25d95ae57cf98a48e3270210ebf436efa8ebc9fe1f63feb3dd59879e3539d"},
	{"session", "AfvdpY9m8f1Y6vKx9NiAOEYzHs4ieyGRfoM6FVVJVgOQn4TtAi7hBNvD5VYVqrXb", "dbb68cc1180435602de30284d84182d2acf30ad6904a13a9789494932d1b3928725d00a1fc15b031663986c39b756109bb925e94f359038b922dc3c1525d7df8"},
}

func TestRustPasswordVectorsVerify(t *testing.T) {
	for _, v := range rustPasswordVectors {
		if ok, err := VerifyPassword(v.password, v.phc); !ok || err != nil {
			t.Errorf("%s: ok=%v err=%v", v.username, ok, err)
		}
		if ok, _ := VerifyPassword(v.password+"x", v.phc); ok {
			t.Errorf("%s: wrong password verified", v.username)
		}
	}
}

func TestRustTokenHashVectors(t *testing.T) {
	for _, v := range rustTokenVectors {
		if got := HashToken(v.token); got != v.digest {
			t.Errorf("%s: got %s, want %s", v.kind, got, v.digest)
		}
	}
}

// Rust: verify_password_rejects_the_sentinel_as_unparseable. Callers must
// check HasNoPassword first; this is an error, not (false, nil).
func TestSentinelIsAnError(t *testing.T) {
	if !HasNoPassword(NoPasswordSentinel) || HasNoPassword("") {
		t.Fatal("HasNoPassword must match only the sentinel")
	}
	hash, _ := HashPassword("whatever")
	if HasNoPassword(hash) {
		t.Fatal("a real hash is not the sentinel")
	}
	if _, err := VerifyPassword("anything", NoPasswordSentinel); !errors.Is(err, ErrInvalidHash) {
		t.Fatalf("err = %v, want ErrInvalidHash", err)
	}
}

func TestVerifyRejectsMalformedHashes(t *testing.T) {
	valid := "$argon2id$v=19$m=19456,t=2,p=1$CFgBxAxypIe+BAv7VNQH0A$cMNXkJbVMEIFcFx0ets3cdrhZEbcp5IAIs5lkC2ppaQ"
	bad := []string{
		"",
		"$argon2id$v=19$m=19456,t=2,p=1$CFgB",
		strings.Replace(valid, "argon2id", "argon2d", 1),
		strings.Replace(valid, "v=19", "v=16", 1),
		strings.Replace(valid, "t=2", "t=0", 1),
		strings.Replace(valid, "p=1", "p=0", 1),
		strings.Replace(valid, "m=19456", "m=4294967295", 1),
		strings.Replace(valid, "m=19456", "m=1", 1),
		strings.Replace(valid, "t=2", "t=x", 1),
		strings.Replace(valid, "CFgBxAxypIe+BAv7VNQH0A", "!!!", 1),
	}
	for _, hash := range bad {
		if _, err := VerifyPassword("x", hash); err == nil {
			t.Errorf("%q must be rejected", hash)
		}
	}
}

// Rust: spend_verify_cost_costs_what_a_real_verification_costs. Loose on
// purpose (3x, medians): the regression guarded against, a dropped call,
// turns ~50 ms into microseconds.
func TestSpendVerifyCostCostsWhatARealVerificationCosts(t *testing.T) {
	work := NewPasswordWork(2)
	ctx := context.Background()
	hash, _ := HashPassword("a genuine stored password")

	if err := work.SpendVerifyCost(ctx, "warm up"); err != nil {
		t.Fatal(err)
	}
	median := func(f func()) time.Duration {
		var samples [5]time.Duration
		for i := range samples {
			start := time.Now()
			f()
			samples[i] = time.Since(start)
		}
		for i := range samples {
			for j := i + 1; j < len(samples); j++ {
				if samples[j] < samples[i] {
					samples[i], samples[j] = samples[j], samples[i]
				}
			}
		}
		return samples[len(samples)/2]
	}
	real := median(func() {
		if ok, _ := VerifyPassword("the wrong password", hash); ok {
			t.Fatal("wrong password verified")
		}
	})
	dummy := median(func() { _ = work.SpendVerifyCost(ctx, "the wrong password") })
	if dummy*3 < real {
		t.Fatalf("padded path %v is meaningfully cheaper than a real verification %v", dummy, real)
	}
}

// Rust: blocking_hash_then_verify_round_trips
func TestWorkHashThenVerify(t *testing.T) {
	work := NewPasswordWork(0)
	ctx := context.Background()
	hash, err := work.Hash(ctx, "correct horse")
	if err != nil || !strings.HasPrefix(hash, "$argon2") {
		t.Fatalf("hash=%q err=%v", hash, err)
	}
	if ok, err := work.Verify(ctx, "correct horse", hash); !ok || err != nil {
		t.Fatalf("ok=%v err=%v", ok, err)
	}
	if ok, err := work.Verify(ctx, "wrong horse", hash); ok || err != nil {
		t.Fatalf("ok=%v err=%v", ok, err)
	}
}

// Rust: blocking_verify_reports_an_unparseable_hash_as_an_error
func TestWorkVerifyReportsUnparseableHashAsError(t *testing.T) {
	if _, err := NewPasswordWork(0).Verify(context.Background(), "anything", "!"); err == nil {
		t.Fatal("want an error, not a verdict")
	}
}

// Rust: password_work_limiter_is_sized_and_releases_permits
func TestWorkLimiterIsSizedAndReleasesSlots(t *testing.T) {
	work := NewPasswordWork(0)
	if work.Limit() < 1 || work.Available() != work.Limit() {
		t.Fatalf("limit=%d available=%d", work.Limit(), work.Available())
	}
	done := make(chan error, work.Limit()+2)
	for i := 0; i < work.Limit()+2; i++ {
		go func() { done <- work.SpendVerifyCost(context.Background(), "any password") }()
	}
	for i := 0; i < work.Limit()+2; i++ {
		if err := <-done; err != nil {
			t.Fatal(err)
		}
	}
	// The slot is released just after the result is delivered, so the count
	// settles a moment later rather than the instant the last caller returns.
	deadline := time.Now().Add(10 * time.Second)
	for work.Available() != work.Limit() {
		if time.Now().After(deadline) {
			t.Fatalf("available=%d, want %d", work.Available(), work.Limit())
		}
		time.Sleep(time.Millisecond)
	}
}

func TestWorkHoldsTheSlotWhenTheCallerGivesUp(t *testing.T) {
	work := NewPasswordWork(1)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	// A cancelled caller never starts work when no slot is contested? It may
	// still win the select; either way the slot must come back.
	_, _ = work.Hash(ctx, "abandoned")
	deadline := time.Now().Add(10 * time.Second)
	for work.Available() != 1 {
		if time.Now().After(deadline) {
			t.Fatal("slot never released")
		}
		time.Sleep(10 * time.Millisecond)
	}
	if _, err := work.Verify(ctx, "x", "!"); !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v, want context.Canceled, never a verdict", err)
	}
}
