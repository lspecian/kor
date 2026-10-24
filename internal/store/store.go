// Package store is Kor's PostgreSQL persistence layer.
//
// Modified in this fork: Doc, DocPath and the transaction registry moved to
// package backend; Store implements backend.Backend; ListCollectionIDs moved
// here from the RPC layer.
package store

import (
	"context"
	"embed"
	"fmt"
	"sort"
	"sync/atomic"
	"time"

	pb "cloud.google.com/go/firestore/apiv1/firestorepb"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/omelas-tech/kor/internal/backend"
	"github.com/omelas-tech/kor/internal/value"
	"github.com/omelas-tech/kor/internal/writes"
)

var _ backend.Backend = (*Store)(nil)

//go:embed migrations/*.sql
var migrationsFS embed.FS

// Store wraps a Postgres pool holding Kor's document data.
type Store struct {
	Pool    *pgxpool.Pool
	txns    backend.TxnRegistry
	indexes indexRegistry
	// indexedQueries counts queries served from index_entries. See
	// IndexedQueries: registered and actually-used are different claims.
	indexedQueries atomic.Int64
	// indexedMerged counts index-served queries that had to merge several
	// ranges (an `in` filter). Separate because "an index was used" and "the
	// merge path was exercised" are different claims.
	indexedMerged atomic.Int64
	// indexedContains counts index-served queries whose definition fans a
	// document out per array element.
	indexedContains atomic.Int64
}

// Doc is a stored document.
type Doc = backend.Doc

// Open connects, applies migrations, and returns the store.
func Open(ctx context.Context, dsn string) (*Store, error) {
	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		return nil, fmt.Errorf("store: parse dsn: %w", err)
	}
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("store: connect: %w", err)
	}
	s := &Store{Pool: pool}
	if err := s.migrate(ctx); err != nil {
		pool.Close()
		return nil, err
	}
	return s, nil
}

func (s *Store) Close() { s.Pool.Close() }

// ListCollectionIDs lists the collection ids directly under parent, from the
// registry maintained on write.
func (s *Store) ListCollectionIDs(ctx context.Context, parent string) ([]string, error) {
	rows, err := s.Pool.Query(ctx,
		`SELECT collection_id FROM collections WHERE parent_path = $1 ORDER BY collection_id`, parent)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var ids []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		ids = append(ids, id)
	}
	return ids, rows.Err()
}

func (s *Store) migrate(ctx context.Context) error {
	_, err := s.Pool.Exec(ctx, `CREATE TABLE IF NOT EXISTS schema_migrations (
		version int PRIMARY KEY, applied_at timestamptz NOT NULL DEFAULT now())`)
	if err != nil {
		return fmt.Errorf("store: init migrations table: %w", err)
	}
	entries, err := migrationsFS.ReadDir("migrations")
	if err != nil {
		return err
	}
	names := make([]string, 0, len(entries))
	for _, e := range entries {
		names = append(names, e.Name())
	}
	sort.Strings(names)
	for i, name := range names {
		version := i + 1
		var exists bool
		if err := s.Pool.QueryRow(ctx,
			`SELECT EXISTS(SELECT 1 FROM schema_migrations WHERE version=$1)`, version).Scan(&exists); err != nil {
			return err
		}
		if exists {
			continue
		}
		sql, err := migrationsFS.ReadFile("migrations/" + name)
		if err != nil {
			return err
		}
		tx, err := s.Pool.Begin(ctx)
		if err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, string(sql)); err != nil {
			_ = tx.Rollback(ctx)
			return fmt.Errorf("store: migration %s: %w", name, err)
		}
		if _, err := tx.Exec(ctx, `INSERT INTO schema_migrations (version) VALUES ($1)`, version); err != nil {
			_ = tx.Rollback(ctx)
			return err
		}
		if err := tx.Commit(ctx); err != nil {
			return err
		}
	}
	return nil
}

// DocPath is a parsed document resource name.
type DocPath = backend.DocPath

// ParseDocumentName validates and splits a document resource name.
func ParseDocumentName(name string) (DocPath, error) { return backend.ParseDocumentName(name) }

// GetDocuments fetches the named documents. Missing names are simply absent
// from the result map.
func (s *Store) GetDocuments(ctx context.Context, names []string) (map[string]*Doc, error) {
	if len(names) == 0 {
		return map[string]*Doc{}, nil
	}
	rows, err := s.Pool.Query(ctx,
		`SELECT name, data, create_time, update_time FROM documents WHERE name = ANY($1)`, names)
	if err != nil {
		return nil, fmt.Errorf("store: get documents: %w", err)
	}
	defer rows.Close()
	return scanDocs(rows)
}

func scanDocs(rows pgx.Rows) (map[string]*Doc, error) {
	out := map[string]*Doc{}
	for rows.Next() {
		var (
			name       string
			data       []byte
			createTime time.Time
			updateTime time.Time
		)
		if err := rows.Scan(&name, &data, &createTime, &updateTime); err != nil {
			return nil, err
		}
		fields, err := value.UnmarshalFields(data)
		if err != nil {
			return nil, fmt.Errorf("store: document %s: %w", name, err)
		}
		out[name] = &Doc{Name: name, Fields: fields, CreateTime: createTime.UTC(), UpdateTime: updateTime.UTC()}
	}
	return out, rows.Err()
}

// Commit applies a list of writes atomically and returns their results plus
// the commit time. Writes apply in order; later writes in the same commit
// observe the effects of earlier ones (required by SDKs that pair an update
// with a separate transform write for the same document).
func (s *Store) Commit(ctx context.Context, ws []*pb.Write) ([]*pb.WriteResult, time.Time, error) {
	return s.applyCommit(ctx, ws, nil, nil)
}

// applyCommit is the shared core of Commit and CommitTxn: lock the union of
// write targets and extraLocks in canonical order, verify recorded read
// versions (ABORTED on drift), apply writes, persist.
func (s *Store) applyCommit(ctx context.Context, ws []*pb.Write, extraLocks []string, verify map[string]time.Time) ([]*pb.WriteResult, time.Time, error) {
	commitTime := time.Now().UTC().Truncate(time.Microsecond)

	// Collect and lock target documents in canonical order (deadlock safety).
	targets := make([]string, 0, len(ws))
	paths := map[string]DocPath{}
	for _, w := range ws {
		name, err := writes.TargetName(w)
		if err != nil {
			return nil, time.Time{}, err
		}
		if _, seen := paths[name]; !seen {
			p, err := ParseDocumentName(name)
			if err != nil {
				return nil, time.Time{}, err
			}
			paths[name] = p
			targets = append(targets, name)
		}
	}
	lockSet := append([]string(nil), targets...)
	for _, name := range extraLocks {
		if _, isTarget := paths[name]; !isTarget {
			lockSet = append(lockSet, name)
		}
	}
	sort.Strings(targets)
	sort.Strings(lockSet)

	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return nil, time.Time{}, fmt.Errorf("store: begin: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	// Row locks (FOR UPDATE) cannot cover documents that do not exist yet, so
	// concurrent creates of the same name would race past version checks and
	// preconditions. Transaction-scoped advisory locks on the (sorted) name
	// set serialize commits touching the same documents, present or not.
	if len(lockSet) > 0 {
		if _, err := tx.Exec(ctx,
			`SELECT pg_advisory_xact_lock(hashtext(n)) FROM unnest($1::text[]) AS n`, lockSet); err != nil {
			return nil, time.Time{}, fmt.Errorf("store: advisory locks: %w", err)
		}
	}

	states := map[string]*writes.DocState{}
	rows, err := tx.Query(ctx,
		`SELECT name, data, create_time, update_time FROM documents WHERE name = ANY($1) FOR UPDATE`, lockSet)
	if err != nil {
		return nil, time.Time{}, fmt.Errorf("store: lock documents: %w", err)
	}
	existing, err := scanDocs(rows)
	if err != nil {
		return nil, time.Time{}, err
	}

	// Optimistic-transaction validation: every read version must be unchanged
	// between the transactional read and this commit.
	for name, want := range verify {
		var current time.Time
		if doc, ok := existing[name]; ok {
			current = doc.UpdateTime
		}
		if !current.Equal(want) {
			return nil, time.Time{}, status.Errorf(codes.Aborted,
				"transaction contention on %s: read version %v, current %v", name, want, current)
		}
	}
	for _, name := range targets {
		if doc, ok := existing[name]; ok {
			states[name] = &writes.DocState{
				Name: name, Exists: true, Fields: backend.CloneFields(doc.Fields),
				CreateTime: doc.CreateTime, UpdateTime: doc.UpdateTime,
			}
		} else {
			states[name] = &writes.DocState{Name: name}
		}
	}

	results := make([]*pb.WriteResult, 0, len(ws))
	for _, w := range ws {
		name, _ := writes.TargetName(w)
		res, err := writes.Apply(states[name], w, commitTime)
		if err != nil {
			return nil, time.Time{}, err
		}
		results = append(results, res)
	}

	for _, name := range targets {
		st := states[name]
		if !st.Dirty {
			continue
		}
		if err := backend.RunCommitCheck(ctx, name, existing[name], afterDoc(st)); err != nil {
			return nil, time.Time{}, err
		}
	}

	for _, name := range targets {
		st := states[name]
		if !st.Dirty {
			continue
		}
		if st.Exists {
			data, err := value.MarshalFields(st.Fields)
			if err != nil {
				return nil, time.Time{}, status.Errorf(codes.InvalidArgument, "document %s: %v", name, err)
			}
			p := paths[name]
			if _, err := tx.Exec(ctx, `
				INSERT INTO documents (name, parent_path, collection_id, doc_id, data, create_time, update_time)
				VALUES ($1, $2, $3, $4, $5, $6, $7)
				ON CONFLICT (name) DO UPDATE SET data = $5, update_time = $7`,
				name, p.ParentPath, p.CollectionID, p.DocID, data, st.CreateTime, st.UpdateTime); err != nil {
				return nil, time.Time{}, fmt.Errorf("store: upsert %s: %w", name, err)
			}
			if _, err := tx.Exec(ctx, `
				INSERT INTO collections (parent_path, collection_id) VALUES ($1, $2)
				ON CONFLICT DO NOTHING`, p.ParentPath, p.CollectionID); err != nil {
				return nil, time.Time{}, fmt.Errorf("store: register collection: %w", err)
			}
			if err := s.refreshIndexEntries(ctx, tx, name, p.CollectionID, st.Fields, false); err != nil {
				return nil, time.Time{}, err
			}
			if err := appendChange(ctx, tx, name, p.CollectionID, "write"); err != nil {
				return nil, time.Time{}, err
			}
		} else {
			if _, err := tx.Exec(ctx, `DELETE FROM documents WHERE name = $1`, name); err != nil {
				return nil, time.Time{}, fmt.Errorf("store: delete %s: %w", name, err)
			}
			if err := s.refreshIndexEntries(ctx, tx, name, paths[name].CollectionID, nil, true); err != nil {
				return nil, time.Time{}, err
			}
			if err := appendChange(ctx, tx, name, paths[name].CollectionID, "delete"); err != nil {
				return nil, time.Time{}, err
			}
		}
	}

	if err := tx.Commit(ctx); err != nil {
		return nil, time.Time{}, fmt.Errorf("store: commit: %w", err)
	}
	return results, commitTime, nil
}

// afterDoc is the document a commit will store for st, or nil for a delete.
func afterDoc(st *writes.DocState) *Doc {
	if !st.Exists {
		return nil
	}
	return &Doc{Name: st.Name, Fields: st.Fields, CreateTime: st.CreateTime, UpdateTime: st.UpdateTime}
}
