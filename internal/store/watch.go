// Modified in this fork: new file.

package store

import (
	"context"
	"fmt"
	"strconv"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/omelas-tech/kor/internal/backend"
)

var _ backend.ChangeFeed = (*Store)(nil)

// watchPollInterval is how often an idle feed checks the changelog.
const watchPollInterval = 100 * time.Millisecond

// WatchChanges tails the changelog from its current end and calls fn with
// each batch of new events. It reads through Changes, so it inherits the
// low-water-mark guarantee: no event is skipped when transactions commit out
// of order.
func (s *Store) WatchChanges(ctx context.Context, ready func(), fn func([]backend.Change)) error {
	cursor, err := s.changelogHead(ctx)
	if err != nil {
		return err
	}
	ready()
	const batch = 500
	for {
		events, err := s.Changes(ctx, cursor, "", batch)
		if err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			return err
		}
		if len(events) > 0 {
			out := make([]backend.Change, len(events))
			for i, e := range events {
				out[i] = backend.Change{Name: e.DocName, CollectionID: e.CollectionID, Delete: e.Kind == "delete"}
			}
			last := events[len(events)-1]
			cursor = Cursor{XID: last.XID, Seq: last.Seq}
			fn(out)
			if len(events) == batch {
				continue
			}
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(watchPollInterval):
		}
	}
}

// changelogHead returns the cursor of the newest event below the low-water
// mark, so a new watcher starts at "now" instead of replaying history.
func (s *Store) changelogHead(ctx context.Context) (Cursor, error) {
	var (
		xid string
		seq int64
	)
	err := s.Pool.QueryRow(ctx, `
		SELECT xid::text, seq FROM changelog
		WHERE xid < pg_snapshot_xmin(pg_current_snapshot())
		ORDER BY xid DESC, seq DESC LIMIT 1`).Scan(&xid, &seq)
	if err == pgx.ErrNoRows {
		return Cursor{}, nil
	}
	if err != nil {
		return Cursor{}, fmt.Errorf("store: changelog head: %w", err)
	}
	x, err := strconv.ParseUint(xid, 10, 64)
	if err != nil {
		return Cursor{}, fmt.Errorf("store: changelog head xid %q: %w", xid, err)
	}
	return Cursor{XID: x, Seq: seq}, nil
}
