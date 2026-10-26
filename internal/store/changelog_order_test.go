// Modified in this fork: new file.

package store

import (
	"context"
	"testing"
)

// Transaction ids must be compared as numbers. Ordering by their text form
// put "10" before "5", and a reader paging one event at a time then advanced
// its cursor past xid 10 and never saw xid 5.
func TestChangesOrderTransactionIDsNumerically(t *testing.T) {
	s := openStore(t)
	ctx := context.Background()
	for _, xid := range []string{"10", "5"} {
		if _, err := s.Pool.Exec(ctx,
			`INSERT INTO changelog (xid, doc_name, collection_id, kind) VALUES ($1::xid8, $2, 'c', 'write')`,
			xid, "projects/p/databases/(default)/documents/c/x"+xid); err != nil {
			t.Fatal(err)
		}
	}
	var seen []uint64
	cursor := Cursor{}
	for i := 0; i < 5; i++ {
		events, err := s.Changes(ctx, cursor, "", 1)
		if err != nil {
			t.Fatal(err)
		}
		if len(events) == 0 {
			break
		}
		seen = append(seen, events[0].XID)
		cursor = Cursor{XID: events[0].XID, Seq: events[0].Seq}
	}
	if len(seen) != 2 || seen[0] != 5 || seen[1] != 10 {
		t.Fatalf("paged xids %v, want [5 10]", seen)
	}
	head, err := s.changelogHead(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if head.XID != 10 {
		t.Fatalf("head xid %d, want 10", head.XID)
	}
}
