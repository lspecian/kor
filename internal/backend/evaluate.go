// Modified in this fork: new file.

package backend

import (
	"errors"
	"sort"

	pb "cloud.google.com/go/firestore/apiv1/firestorepb"

	"github.com/omelas-tech/kor/internal/query"
)

// ErrStop ends a RunQuery early without an error; yield returns it once it
// has seen enough documents.
var ErrStop = errors.New("kor: stop iteration")

// Evaluate applies a query's full Firestore semantics (filters, ordering,
// cursors, offset and limit) to a candidate set and yields the results in
// query order. Backends that cannot push a query down use it as their
// reference path, so every backend answers a query the same way.
func Evaluate(q *query.Query, candidates []*Doc, yield func(*Doc) error) error {
	type entry struct {
		doc *Doc
		key []*pb.Value
	}
	entries := make([]entry, 0, len(candidates))
	for _, doc := range candidates {
		if !q.Matches(doc.Name, doc.Fields) {
			continue
		}
		key := q.OrderKey(doc.Name, doc.Fields)
		if !q.InCursorRange(key) {
			continue
		}
		entries = append(entries, entry{doc, key})
	}
	sort.SliceStable(entries, func(i, j int) bool {
		return q.CompareKeys(entries[i].key, entries[j].key) < 0
	})

	start := int(q.Offset)
	if start > len(entries) {
		start = len(entries)
	}
	end := len(entries)
	if q.Limit >= 0 && start+int(q.Limit) < end {
		end = start + int(q.Limit)
	}
	for _, e := range entries[start:end] {
		if err := yield(e.doc); err != nil {
			if errors.Is(err, ErrStop) {
				return nil
			}
			return err
		}
	}
	return nil
}
