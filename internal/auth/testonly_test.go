package auth

// Available is the number of free slots; equals Limit when idle.
func (w *PasswordWork) Available() int { return cap(w.slots) - len(w.slots) }

// TrackedAccounts is the number of accounts currently carrying failures.
func (l *Lockout) TrackedAccounts() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.failures)
}
