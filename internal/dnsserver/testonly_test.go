package dnsserver

// TrackedIPs returns the number of IPs with a bucket.
func (l *Limiter) TrackedIPs() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.buckets)
}
