// Modified in this fork: new file.

package cosmos

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"strconv"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/data/azcosmos"

	"github.com/omelas-tech/kor/internal/backend"
)

var _ backend.ChangeFeed = (*Store)(nil)

const (
	// watchPollInterval is how often an idle feed checks for change records.
	watchPollInterval = 150 * time.Millisecond
	// watchLookback is how far behind the newest record each poll re-reads.
	// Commit times are taken before the batch lands, so a slow commit can
	// appear after a faster, later one; re-reading a window and skipping ids
	// already seen catches it. It also absorbs clock skew between servers.
	watchLookback = 5 * time.Second
)

// WatchChanges polls the change records this backend writes with every
// commit, and calls fn with the changes not delivered before.
func (s *Store) WatchChanges(ctx context.Context, ready func(), fn func([]backend.Change)) error {
	// Starting a lookback window in the past means every commit that finishes
	// from now on has a later commit time than the window start.
	since := time.Now().Add(-watchLookback).UnixMicro()
	ready()
	newest := since
	seen := map[string]int64{} // change record id -> at_us
	const sql = `SELECT * FROM c WHERE c.kind = "change" AND c.at_us > @since`
	for {
		var fresh []changeItem
		pager := s.container.NewQueryItemsPager(sql, s.pk, &azcosmos.QueryOptions{
			QueryParameters: []azcosmos.QueryParameter{{Name: "@since", Value: since}},
		})
		for pager.More() {
			page, err := pager.NextPage(ctx)
			if err != nil {
				if ctx.Err() != nil {
					return ctx.Err()
				}
				return fmt.Errorf("cosmos: read change records: %w", err)
			}
			for _, raw := range page.Items {
				var it changeItem
				if err := json.Unmarshal(raw, &it); err != nil {
					return fmt.Errorf("cosmos: bad change record: %w", err)
				}
				if _, ok := seen[it.ID]; ok {
					continue
				}
				seen[it.ID] = it.AtUS
				fresh = append(fresh, it)
			}
		}
		if len(fresh) > 0 {
			sort.Slice(fresh, func(i, j int) bool { return fresh[i].AtUS < fresh[j].AtUS })
			var out []backend.Change
			for _, it := range fresh {
				if it.AtUS > newest {
					newest = it.AtUS
				}
				for _, c := range it.Changes {
					out = append(out, backend.Change{Name: c.Name, CollectionID: c.CollectionID, Delete: c.Delete})
				}
			}
			fn(out)
		}
		since = newest - watchLookback.Microseconds()
		for id, at := range seen {
			if at <= since {
				delete(seen, id)
			}
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(watchPollInterval):
		}
	}
}

var _ backend.Clearer = (*Store)(nil)

// ClearDatabase deletes every document of a database in this partition
// (development only) and records the deletes for open listeners.
func (s *Store) ClearDatabase(ctx context.Context, database string) error {
	prefix := database + "/documents/"
	pager := s.container.NewQueryItemsPager(
		`SELECT c.id, c.name, c.collection_id FROM c WHERE c.kind = "doc" AND STARTSWITH(c.name, @prefix)`, s.pk,
		&azcosmos.QueryOptions{QueryParameters: []azcosmos.QueryParameter{{Name: "@prefix", Value: prefix}}})
	var gone []changeEntry
	var ids []string
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return fmt.Errorf("cosmos: clear: %w", err)
		}
		for _, raw := range page.Items {
			var row struct {
				ID           string `json:"id"`
				Name         string `json:"name"`
				CollectionID string `json:"collection_id"`
			}
			if err := json.Unmarshal(raw, &row); err != nil {
				return fmt.Errorf("cosmos: clear: %w", err)
			}
			ids = append(ids, row.ID)
			gone = append(gone, changeEntry{Name: row.Name, CollectionID: row.CollectionID, Delete: true})
		}
	}
	for _, id := range ids {
		if _, err := s.container.DeleteItem(ctx, s.pk, id, nil); err != nil && !isStatus(err, http.StatusNotFound) {
			return fmt.Errorf("cosmos: clear %s: %w", id, err)
		}
	}
	if len(gone) == 0 {
		return nil
	}
	body, err := s.encodeChange(time.Now().UTC(), gone)
	if err != nil {
		return err
	}
	if _, err := s.container.CreateItem(ctx, s.pk, body, nil); err != nil {
		return fmt.Errorf("cosmos: clear: record deletes: %w", err)
	}
	return nil
}

var _ backend.EventLog = (*Store)(nil)

// ReadEvents returns the events in change records after the cursor (a commit
// time in microseconds). Each read re-covers the lookback window, so a
// commit that landed late is not missed; consumers de-duplicate by ID.
func (s *Store) ReadEvents(ctx context.Context, cursor string, limit int) ([]backend.Event, string, error) {
	if cursor == "" {
		return nil, strconv.FormatInt(time.Now().UnixMicro(), 10), nil
	}
	at, err := strconv.ParseInt(cursor, 10, 64)
	if err != nil {
		return nil, "", fmt.Errorf("cosmos: bad event cursor %q", cursor)
	}
	since := at - watchLookback.Microseconds()
	pager := s.container.NewQueryItemsPager(`SELECT * FROM c WHERE c.kind = "change" AND c.at_us > @since`, s.pk,
		&azcosmos.QueryOptions{QueryParameters: []azcosmos.QueryParameter{{Name: "@since", Value: since}}})
	var records []changeItem
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, "", fmt.Errorf("cosmos: read events: %w", err)
		}
		for _, raw := range page.Items {
			var it changeItem
			if err := json.Unmarshal(raw, &it); err != nil {
				return nil, "", fmt.Errorf("cosmos: bad change record: %w", err)
			}
			records = append(records, it)
		}
	}
	sort.Slice(records, func(i, j int) bool { return records[i].AtUS < records[j].AtUS })
	next := at
	var out []backend.Event
	for _, rec := range records {
		if limit > 0 && len(out) >= limit && rec.AtUS > next {
			break
		}
		if rec.AtUS > next {
			next = rec.AtUS
		}
		for i, c := range rec.Changes {
			before, err := c.Before.doc(c.Name)
			if err != nil {
				return nil, "", err
			}
			after, err := c.After.doc(c.Name)
			if err != nil {
				return nil, "", err
			}
			out = append(out, backend.Event{
				ID: fmt.Sprintf("cosmos:%s:%d", rec.ID, i), Name: c.Name, CollectionID: c.CollectionID,
				Before: before, After: after, CommitTime: toTime(rec.AtUS),
			})
		}
	}
	return out, strconv.FormatInt(next, 10), nil
}
