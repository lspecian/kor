// Modified in this fork: new file.

package backend

import (
	"context"
	"time"
)

// Event is one committed document change with its before and after state,
// for event handlers (the replacement for Cloud Functions document triggers).
type Event struct {
	// ID is unique and stable across reads, so consumers can de-duplicate.
	ID           string
	Name         string
	CollectionID string
	// Before and After are nil when the document did not exist before the
	// write, or does not exist after it.
	Before, After *Doc
	CommitTime    time.Time
}

// EventLog is implemented by backends that keep change events with images.
type EventLog interface {
	// ReadEvents returns events after cursor, oldest first, and the cursor to
	// continue from. An empty cursor starts at the current end of the log.
	// Delivery is at least once: a consumer de-duplicates by Event.ID.
	ReadEvents(ctx context.Context, cursor string, limit int) ([]Event, string, error)
}
