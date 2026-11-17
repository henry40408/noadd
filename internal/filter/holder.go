package filter

import "sync/atomic"

// Holder shares the current engine between the DNS path and the rebuild path.
// Readers never block; a rebuild publishes a new engine with Swap.
type Holder struct {
	current atomic.Pointer[Engine]
}

// NewHolder returns a holder that serves the given engine.
func NewHolder(engine *Engine) *Holder {
	holder := &Holder{}
	holder.current.Store(engine)
	return holder
}

// Load returns the engine in use now.
func (h *Holder) Load() *Engine { return h.current.Load() }

// Swap publishes a new engine and returns the previous one.
func (h *Holder) Swap(engine *Engine) *Engine { return h.current.Swap(engine) }
