package filter

import "context"

// BlockedDomainCount is the number of distinct block rules: exact entries plus
// trie terminals.
func (e *Engine) BlockedDomainCount() int {
	return e.exactBlock.len() + e.blockTrie.terminals
}

// HeapBytes estimates the heap the rule structures use.
func (e *Engine) HeapBytes() int {
	return e.blockTrie.heapBytes() + e.allowTrie.heapBytes() + e.exactBlock.heapBytes() + e.exactAllow.heapBytes()
}

// UpdateAllLists downloads every enabled list and rebuilds the engine.
func (m *Manager) UpdateAllLists(ctx context.Context) error {
	if _, err := m.UpdateAllListsNoRebuild(ctx); err != nil {
		return err
	}
	return m.Rebuild(ctx)
}
