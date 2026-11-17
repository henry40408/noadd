package auth

import (
	"context"
	"encoding/hex"
	"log/slog"
	"sync"
	"time"

	"github.com/henry40408/noadd/internal/db"
)

const (
	// SessionMaxAge is the absolute session lifetime (7 days).
	SessionMaxAge = 7 * 24 * 3600
	// SessionIdleTimeout (48 hours) is measured from the last request. It is
	// long because operators of a self-hosted appliance expect a long-lived tab;
	// the requirement is only that an idle layer exists beside the absolute one.
	// last_seen is flushed to disk every FlushInterval, so a restored value can
	// lag by that much: immaterial at 48h, but shorten the flush (or flush on
	// shutdown) before lowering this toward it.
	SessionIdleTimeout = 2 * 24 * 3600
	// ReauthWindow is how recently a session must have proved the password
	// before a sensitive action. Short on purpose: it bounds how long a stolen
	// session cookie can make a compromise permanent.
	ReauthWindow = 300

	// FlushInterval is how often last_seen is written back to the database.
	FlushInterval = 60 * time.Second
	// sweepEveryTicks makes every tenth flush also sweep expired sessions.
	sweepEveryTicks = 10
)

// SessionInfo is the in-memory metadata of one session.
type SessionInfo struct {
	SessionID int64
	UserID    int64
	CreatedAt int64
	LastSeen  int64
	// LastReauthAt is when the session last proved the account's password.
	// It is deliberately not persisted: it goes stale in minutes, and Load
	// falls back to CreatedAt, which is the safe direction.
	LastReauthAt int64
}

// ManagerConfig configures a Manager. DB is required.
type ManagerConfig struct {
	DB *db.DB
	// Now returns the current time; nil means time.Now.
	Now func() time.Time
	// Salt keys the log identifiers made by SidHash.
	Salt   [SessionLogSaltLen]byte
	Logger *slog.Logger
}

// Manager is the thread-safe session store: token hash to session metadata.
//
// It is keyed by the hash so the raw token never lives in noadd's own state,
// and the store and the sessions table share one identifier: a row deleted by
// id is evicted from memory by the hash the DELETE returned.
type Manager struct {
	db     *db.DB
	now    func() time.Time
	salt   [SessionLogSaltLen]byte
	logger *slog.Logger

	mu       sync.Mutex
	sessions map[string]SessionInfo
}

// NewManager returns an empty Manager; call Load to restore persisted sessions.
func NewManager(cfg ManagerConfig) *Manager {
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.New(slog.DiscardHandler)
	}
	return &Manager{
		db:       cfg.DB,
		now:      cfg.Now,
		salt:     cfg.Salt,
		logger:   cfg.Logger,
		sessions: make(map[string]SessionInfo),
	}
}

// Salt is the audit-log salt, for callers that log session events themselves.
func (m *Manager) Salt() [SessionLogSaltLen]byte { return m.salt }

func (m *Manager) nowUnix() int64 { return m.now().Unix() }

func expiryReason(info SessionInfo, now int64) string {
	// A backwards clock yields negative deltas, i.e. "not expired".
	if now-info.CreatedAt >= SessionMaxAge {
		return "expired_absolute"
	}
	if now-info.LastSeen >= SessionIdleTimeout {
		return "expired_idle"
	}
	return ""
}

// Store records a session in memory, keyed by its token hash.
func (m *Manager) Store(tokenHash string, info SessionInfo) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.sessions[tokenHash] = info
}

// Get returns a copy of the session without touching last_seen.
func (m *Manager) Get(tokenHash string) (SessionInfo, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	info, found := m.sessions[tokenHash]
	return info, found
}

// Len is the number of sessions in memory.
func (m *Manager) Len() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.sessions)
}

// Validate resolves a presented session by its token hash. It returns the
// owning user id and refreshes last_seen, or false if missing or expired
// (expired entries are dropped).
func (m *Manager) Validate(tokenHash string) (userID int64, ok bool) {
	now := m.nowUnix()
	info, expired, found := m.touch(tokenHash, now)
	if !found {
		return 0, false
	}
	if expired == "" {
		return info.UserID, true
	}
	// Logged after the lock is released.
	m.logger.Info("session expired",
		"event", "session.destroyed", "reason", expired,
		"session_id", info.SessionID, "sid_hash", SidHash(m.salt, tokenHash))
	return 0, false
}

// touch applies the expiry check and the last_seen refresh under one lock.
// The idle check reads last_seen before this request refreshes it.
func (m *Manager) touch(tokenHash string, now int64) (info SessionInfo, expired string, found bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	info, found = m.sessions[tokenHash]
	if !found {
		return SessionInfo{}, "", false
	}
	if reason := expiryReason(info, now); reason != "" {
		delete(m.sessions, tokenHash)
		return info, reason, true
	}
	info.LastSeen = now
	m.sessions[tokenHash] = info
	return info, "", true
}

// PruneExpired drops in-memory sessions past either timeout and returns how
// many. Validate only expires sessions on access, so this is the sweep.
func (m *Manager) PruneExpired() int {
	now := m.nowUnix()
	m.mu.Lock()
	defer m.mu.Unlock()
	removed := 0
	for hash, info := range m.sessions {
		if expiryReason(info, now) != "" {
			delete(m.sessions, hash)
			removed++
		}
	}
	return removed
}

// MarkReauthenticated records that the session just proved the account's
// password. It returns false if the token names no live session.
func (m *Manager) MarkReauthenticated(tokenHash string) bool {
	now := m.nowUnix()
	m.mu.Lock()
	defer m.mu.Unlock()
	info, found := m.sessions[tokenHash]
	if !found {
		return false
	}
	info.LastReauthAt = now
	m.sessions[tokenHash] = info
	return true
}

// HasFreshReauth reports whether the session proved the password within
// ReauthWindow. An unknown token is not fresh; a backwards clock reads as
// "not yet stale", the direction the expiry checks take.
func (m *Manager) HasFreshReauth(tokenHash string) bool {
	now := m.nowUnix()
	info, found := m.Get(tokenHash)
	return found && now-info.LastReauthAt < ReauthWindow
}

// Revoke removes one session from memory (log out this device only). The
// caller persists it. Callers logging session.destroyed must gate on the
// returned flag, so a fabricated cookie cannot inject a destruction event.
func (m *Manager) Revoke(tokenHash string) (SessionInfo, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	info, found := m.sessions[tokenHash]
	delete(m.sessions, tokenHash)
	return info, found
}

// Load restores persisted sessions; expired rows are purged by the database.
func (m *Manager) Load(ctx context.Context) error {
	loaded, err := m.db.LoadSessions(ctx, SessionMaxAge, SessionIdleTimeout, m.nowUnix())
	if err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, row := range loaded {
		m.sessions[row.TokenHash] = SessionInfo{
			SessionID: row.ID,
			UserID:    row.UserID,
			CreatedAt: row.CreatedAt,
			LastSeen:  row.LastSeen,
			// Not persisted; see SessionInfo.LastReauthAt.
			LastReauthAt: row.CreatedAt,
		}
	}
	return nil
}

// FlushLastSeen writes the in-memory last_seen values to the database.
func (m *Manager) FlushLastSeen(ctx context.Context) error {
	m.mu.Lock()
	entries := make([]db.SessionLastSeen, 0, len(m.sessions))
	for hash, info := range m.sessions {
		entries = append(entries, db.SessionLastSeen{TokenHash: hash, LastSeen: info.LastSeen})
	}
	m.mu.Unlock()
	return m.db.FlushSessionsLastSeen(ctx, entries)
}

// Sweep removes expired sessions from memory and from the sessions table and
// returns both counts. Flush first: the database predicate reads last_seen,
// which otherwise lags memory by up to one flush interval.
func (m *Manager) Sweep(ctx context.Context) (evicted int, deleted int64, err error) {
	evicted = m.PruneExpired()
	deleted, err = m.db.PurgeExpiredSessions(ctx, SessionMaxAge, SessionIdleTimeout, m.nowUnix())
	return evicted, deleted, err
}

// RevokeOthers revokes every session except keep (log out other devices). A
// nil keep (e.g. a forward-auth caller with no session cookie) revokes all.
// It returns the number of database rows removed, for the audit log.
func (m *Manager) RevokeOthers(ctx context.Context, keep *string) (int64, error) {
	m.mu.Lock()
	for hash := range m.sessions {
		if keep == nil || hash != *keep {
			delete(m.sessions, hash)
		}
	}
	m.mu.Unlock()
	if keep == nil {
		return m.db.DeleteAllSessions(ctx)
	}
	return m.db.DeleteSessionsExcept(ctx, *keep)
}

// RevokeUserSessionsExcept revokes userID's sessions except keep (nil revokes
// all of them). Other operators are unaffected, the semantics a password
// change needs. It returns the count evicted from memory, not the database
// row count: eviction is what ends authentication, and the two diverge (rows
// of lazily expired sessions linger until the sweep).
func (m *Manager) RevokeUserSessionsExcept(ctx context.Context, userID int64, keep *string) (int, error) {
	if _, err := m.db.DeleteUserSessionsExcept(ctx, userID, keep); err != nil {
		return 0, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	evicted := 0
	for hash, info := range m.sessions {
		if info.UserID == userID && (keep == nil || hash != *keep) {
			delete(m.sessions, hash)
			evicted++
		}
	}
	return evicted, nil
}

// Run flushes last_seen every FlushInterval and sweeps expired sessions every
// tenth tick, since otherwise only startup deletes them. It returns when ctx
// is done.
func (m *Manager) Run(ctx context.Context) {
	ticker := time.NewTicker(FlushInterval)
	defer ticker.Stop()
	ticks := 0
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
		_ = m.FlushLastSeen(ctx)
		ticks = (ticks + 1) % sweepEveryTicks
		if ticks == 0 {
			m.sweepAndLog(ctx)
		}
	}
}

func (m *Manager) sweepAndLog(ctx context.Context) {
	evicted, deleted, err := m.Sweep(ctx)
	if err != nil {
		m.logger.Warn("session sweep failed; will retry next cycle", "event", "session.sweep_failed", "error", err)
		return
	}
	if evicted > 0 || deleted > 0 {
		m.logger.Info("swept expired sessions", "event", "session.destroyed",
			"reason", "swept", "evicted", evicted, "deleted", deleted)
	}
}

// LoadOrCreateSessionLogSalt reads the persisted audit salt from settings,
// generating and storing one on first run. A malformed setting gets a fresh
// salt rather than an error.
func LoadOrCreateSessionLogSalt(ctx context.Context, database *db.DB) ([SessionLogSaltLen]byte, error) {
	var salt [SessionLogSaltLen]byte
	stored, found, err := database.GetSetting(ctx, SessionLogSaltKey)
	if err != nil {
		return salt, err
	}
	if found && decodeSalt(stored, &salt) {
		return salt, nil
	}
	randomBytes(salt[:])
	return salt, database.SetSetting(ctx, SessionLogSaltKey, hex.EncodeToString(salt[:]))
}

func decodeSalt(text string, out *[SessionLogSaltLen]byte) bool {
	if len(text) != 2*SessionLogSaltLen {
		return false
	}
	decoded, err := hex.DecodeString(text)
	if err != nil {
		return false
	}
	copy(out[:], decoded)
	return true
}
