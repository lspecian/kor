// Modified in this fork: new file.

package backend

import "context"

// Change notes that a document was written or deleted. It carries no document
// data: consumers re-read current state, so replaying a change converges and a
// consumer that falls behind skips straight to the latest value.
type Change struct {
	Name         string
	CollectionID string
	Delete       bool
}

// ChangeFeed is implemented by backends that can report committed changes.
// Live updates (the Listen RPC) and event handlers read from it.
type ChangeFeed interface {
	// WatchChanges calls fn with batches of changes in commit order until ctx
	// ends. It calls ready once its starting position is fixed: every commit
	// that completes after ready is delivered. It returns ctx.Err() when ctx
	// ends, or an error if the feed cannot be read; callers restart it.
	WatchChanges(ctx context.Context, ready func(), fn func([]Change)) error
}
