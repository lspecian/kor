// Modified in this fork: Changes orders by the xid8 column, not its text
// rendering (which sorted "999" after "1000" and could skip events).

package store

import (
	"context"
	"fmt"
	"strconv"
	"time"

	"github.com/jackc/pgx/v5"
)

// Change is one document event.
//
// It deliberately carries no document data. Consumers re-read current state by
// name, which makes the feed idempotent and self-healing: replaying an event
// twice converges, and a consumer that falls behind skips straight to the
// latest value instead of replaying a history it no longer cares about. Storing
// snapshots would double the write cost and hand consumers stale data to act on.
type Change struct {
	Seq          int64
	XID          uint64
	DocName      string
	CollectionID string
	Kind         string // write | delete
	At           time.Time
}

// Cursor is a resume position. The zero value starts from the beginning.
type Cursor struct {
	XID uint64
	Seq int64
}

// appendChange records one event inside the caller's transaction.
//
// Sharing the transaction is what makes the feed trustworthy: an event that
// committed without its document, or a document without its event, would leave
// consumers permanently out of step with no way to detect it.
func appendChange(ctx context.Context, tx pgx.Tx, name, collectionID, kind string) error {
	if _, err := tx.Exec(ctx, `
		INSERT INTO changelog (xid, doc_name, collection_id, kind)
		VALUES (pg_current_xact_id(), $1, $2, $3)`,
		name, collectionID, kind); err != nil {
		return fmt.Errorf("store: append changelog for %s: %w", name, err)
	}
	return nil
}

// Changes returns events after the cursor, in commit order, up to limit.
//
// Only rows below the low-water mark are returned — see the migration comment.
// The cost is latency, not correctness: an event stays invisible while any
// older transaction is still open, so a long-running transaction holds the feed
// back. That is the right trade for a change feed, where a late event is
// recoverable and a lost one is not.
//
// collectionID filters to one collection when non-empty.
func (s *Store) Changes(ctx context.Context, after Cursor, collectionID string, limit int) ([]Change, error) {
	if limit <= 0 {
		limit = 500
	}
	// The cursor xid crosses the wire as text: pgx has no encoder for xid8, and
	// uint64 does not fit int8 across the whole range.
	args := []any{strconv.FormatUint(after.XID, 10), after.Seq, limit}
	where := `WHERE xid < pg_snapshot_xmin(pg_current_snapshot())
	            AND (xid > $1::text::xid8 OR (xid = $1::text::xid8 AND seq > $2))`
	if collectionID != "" {
		args = append(args, collectionID)
		where += fmt.Sprintf(" AND collection_id = $%d", len(args))
	}
	rows, err := s.Pool.Query(ctx, `
		SELECT seq, xid::text, doc_name, collection_id, kind, at
		FROM changelog `+where+`
		ORDER BY changelog.xid, changelog.seq LIMIT $3`, args...)
	if err != nil {
		return nil, fmt.Errorf("store: read changelog: %w", err)
	}
	defer rows.Close()
	var out []Change
	for rows.Next() {
		var c Change
		var xid string
		if err := rows.Scan(&c.Seq, &xid, &c.DocName, &c.CollectionID, &c.Kind, &c.At); err != nil {
			return nil, err
		}
		if c.XID, err = strconv.ParseUint(xid, 10, 64); err != nil {
			return nil, fmt.Errorf("store: changelog xid %q: %w", xid, err)
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// PruneChanges deletes events older than the given age.
//
// Retention is the operator's call and there is no safe universal default: the
// feed must outlive the slowest consumer's downtime, and only the operator
// knows what that is. Pruning below a consumer's cursor does not error — it
// silently makes that consumer's resume position meaningless, which is why this
// is explicit rather than automatic.
func (s *Store) PruneChanges(ctx context.Context, olderThan time.Duration) (int64, error) {
	tag, err := s.Pool.Exec(ctx,
		`DELETE FROM changelog WHERE at < now() - $1::interval`,
		fmt.Sprintf("%d seconds", int(olderThan.Seconds())))
	if err != nil {
		return 0, fmt.Errorf("store: prune changelog: %w", err)
	}
	return tag.RowsAffected(), nil
}
