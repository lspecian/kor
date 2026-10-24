// Modified in this fork: new file.

package store

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/omelas-tech/kor/internal/backend"
	"github.com/omelas-tech/kor/internal/value"
)

var _ backend.EventLog = (*Store)(nil)

// appendChangeImages records one event with the document's before and after
// state, inside the caller's transaction.
func appendChangeImages(ctx context.Context, tx pgx.Tx, name, collectionID, kind string, before, after *Doc) error {
	bData, bCreate, bUpdate, err := image(before)
	if err != nil {
		return err
	}
	aData, aCreate, aUpdate, err := image(after)
	if err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO changelog (xid, doc_name, collection_id, kind,
		                       before_data, before_create, before_update,
		                       after_data, after_create, after_update)
		VALUES (pg_current_xact_id(), $1, $2, $3, $4, $5, $6, $7, $8, $9)`,
		name, collectionID, kind, bData, bCreate, bUpdate, aData, aCreate, aUpdate); err != nil {
		return fmt.Errorf("store: append changelog for %s: %w", name, err)
	}
	return nil
}

func image(d *Doc) ([]byte, *time.Time, *time.Time, error) {
	if d == nil {
		return nil, nil, nil, nil
	}
	data, err := value.MarshalFields(d.Fields)
	if err != nil {
		return nil, nil, nil, err
	}
	c, u := d.CreateTime, d.UpdateTime
	return data, &c, &u, nil
}

// ReadEvents returns events after the cursor ("xid:seq"), below the
// low-water mark, so none is skipped when transactions commit out of order.
func (s *Store) ReadEvents(ctx context.Context, cursor string, limit int) ([]backend.Event, string, error) {
	if limit <= 0 {
		limit = 200
	}
	var after Cursor
	if cursor == "" {
		head, err := s.changelogHead(ctx)
		if err != nil {
			return nil, "", err
		}
		return nil, formatCursor(head), nil
	}
	xs, seqs, ok := strings.Cut(cursor, ":")
	x, err1 := strconv.ParseUint(xs, 10, 64)
	q, err2 := strconv.ParseInt(seqs, 10, 64)
	if !ok || err1 != nil || err2 != nil {
		return nil, "", fmt.Errorf("store: bad event cursor %q", cursor)
	}
	after = Cursor{XID: x, Seq: q}
	rows, err := s.Pool.Query(ctx, `
		SELECT seq, xid::text, doc_name, collection_id, at,
		       before_data, before_create, before_update,
		       after_data, after_create, after_update
		FROM changelog
		WHERE xid < pg_snapshot_xmin(pg_current_snapshot())
		  AND (xid > $1::text::xid8 OR (xid = $1::text::xid8 AND seq > $2))
		ORDER BY changelog.xid, changelog.seq LIMIT $3`, strconv.FormatUint(after.XID, 10), after.Seq, limit)
	if err != nil {
		return nil, "", fmt.Errorf("store: read events: %w", err)
	}
	defer rows.Close()
	var out []backend.Event
	next := after
	for rows.Next() {
		var (
			seq             int64
			xid, name, coll string
			at              time.Time
			bData, aData    []byte
			bC, bU, aC, aU  *time.Time
		)
		if err := rows.Scan(&seq, &xid, &name, &coll, &at, &bData, &bC, &bU, &aData, &aC, &aU); err != nil {
			return nil, "", err
		}
		x, err := strconv.ParseUint(xid, 10, 64)
		if err != nil {
			return nil, "", err
		}
		next = Cursor{XID: x, Seq: seq}
		before, err := docImage(name, bData, bC, bU)
		if err != nil {
			return nil, "", err
		}
		afterDoc, err := docImage(name, aData, aC, aU)
		if err != nil {
			return nil, "", err
		}
		commit := at.UTC()
		if afterDoc != nil {
			commit = afterDoc.UpdateTime
		}
		out = append(out, backend.Event{ID: "pg:" + strconv.FormatInt(seq, 10), Name: name, CollectionID: coll,
			Before: before, After: afterDoc, CommitTime: commit})
	}
	if err := rows.Err(); err != nil {
		return nil, "", err
	}
	return out, formatCursor(next), nil
}

func docImage(name string, data []byte, created, updated *time.Time) (*Doc, error) {
	if data == nil {
		return nil, nil
	}
	fields, err := value.UnmarshalFields(data)
	if err != nil {
		return nil, fmt.Errorf("store: event image of %s: %w", name, err)
	}
	d := &Doc{Name: name, Fields: fields}
	if created != nil {
		d.CreateTime = created.UTC()
	}
	if updated != nil {
		d.UpdateTime = updated.UTC()
	}
	return d, nil
}

func formatCursor(c Cursor) string {
	return strconv.FormatUint(c.XID, 10) + ":" + strconv.FormatInt(c.Seq, 10)
}
