package upstream

// ServerOrder is the try-order for the current strategy, as indexes into the
// configured servers.
func (f *Forwarder) ServerOrder() []int { return f.orderFor(f.set.Load()) }
