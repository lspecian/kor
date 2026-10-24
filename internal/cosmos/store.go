// Package cosmos is a Kor storage backend on Azure Cosmos DB for NoSQL.
//
// Every document of one customer lives in a single container partition
// (/customer_id), so any commit within the Cosmos batch limit is one atomic
// transactional batch. Concurrency is optimistic: a commit reads its targets
// with their etags, applies the writes with the shared writes package, and
// sends replace/delete operations conditioned on those etags. A conflicting
// change fails the whole batch; plain commits retry, transaction commits
// return ABORTED so the SDK retries. Query semantics come from the shared
// query package via backend.Evaluate.
//
// Modified in this fork: this package is new.
package cosmos

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"sort"
	"time"

	pb "cloud.google.com/go/firestore/apiv1/firestorepb"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/data/azcosmos"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/omelas-tech/kor/internal/backend"
	"github.com/omelas-tech/kor/internal/query"
	"github.com/omelas-tech/kor/internal/value"
	"github.com/omelas-tech/kor/internal/writes"
)

var _ backend.Backend = (*Store)(nil)

// maxBatchOps is the Cosmos transactional batch limit.
const maxBatchOps = 100

// commitAttempts bounds retries of a non-transactional commit that lost an
// optimistic race.
const commitAttempts = 8

const (
	kindDoc   = "doc"
	kindGuard = "guard"
)

// Config selects the Cosmos account, database, container and partition.
type Config struct {
	Endpoint   string
	Key        string
	Database   string
	Container  string
	CustomerID string
	// CreateIfMissing creates the database and container on Open. Production
	// containers come from infrastructure code; this is for local use.
	CreateIfMissing bool
}

// Store implements backend.Backend on one Cosmos container partition.
type Store struct {
	container *azcosmos.ContainerClient
	customer  string
	pk        azcosmos.PartitionKey
	txns      backend.TxnRegistry
}

// item is the stored shape of one document.
type item struct {
	ID           string          `json:"id"`
	CustomerID   string          `json:"customer_id"`
	Kind         string          `json:"kind"`
	Name         string          `json:"name,omitempty"`
	ParentPath   string          `json:"parent_path,omitempty"`
	CollectionID string          `json:"collection_id,omitempty"`
	DocID        string          `json:"doc_id,omitempty"`
	Data         json.RawMessage `json:"data,omitempty"`
	CreateUS     int64           `json:"create_us,omitempty"`
	UpdateUS     int64           `json:"update_us,omitempty"`
}

// Open connects to Cosmos and, when asked, creates the database and container.
func Open(ctx context.Context, cfg Config) (*Store, error) {
	if cfg.Endpoint == "" || cfg.Key == "" || cfg.Database == "" || cfg.Container == "" || cfg.CustomerID == "" {
		return nil, errors.New("cosmos: endpoint, key, database, container and customer id are required")
	}
	cred, err := azcosmos.NewKeyCredential(cfg.Key)
	if err != nil {
		return nil, fmt.Errorf("cosmos: key: %w", err)
	}
	client, err := azcosmos.NewClientWithKey(cfg.Endpoint, cred, nil)
	if err != nil {
		return nil, fmt.Errorf("cosmos: client: %w", err)
	}
	if cfg.CreateIfMissing {
		if _, err := client.CreateDatabase(ctx, azcosmos.DatabaseProperties{ID: cfg.Database}, nil); err != nil && !isStatus(err, http.StatusConflict) {
			return nil, fmt.Errorf("cosmos: create database: %w", err)
		}
		db, err := client.NewDatabase(cfg.Database)
		if err != nil {
			return nil, fmt.Errorf("cosmos: database: %w", err)
		}
		props := azcosmos.ContainerProperties{
			ID:                     cfg.Container,
			PartitionKeyDefinition: azcosmos.PartitionKeyDefinition{Paths: []string{"/customer_id"}},
		}
		if _, err := db.CreateContainer(ctx, props, nil); err != nil && !isStatus(err, http.StatusConflict) {
			return nil, fmt.Errorf("cosmos: create container: %w", err)
		}
	}
	container, err := client.NewContainer(cfg.Database, cfg.Container)
	if err != nil {
		return nil, fmt.Errorf("cosmos: container: %w", err)
	}
	return &Store{
		container: container,
		customer:  cfg.CustomerID,
		pk:        azcosmos.NewPartitionKeyString(cfg.CustomerID),
	}, nil
}

// Close releases nothing; the SDK client holds no resources that need it.
func (s *Store) Close() {}

// itemID maps a document name to a Cosmos id. Ids are limited to 255
// characters and may not contain '/', so the id is a hash of the name; the
// name itself is stored on the item.
func itemID(name string) string {
	sum := sha256.Sum256([]byte(name))
	return "d" + hex.EncodeToString(sum[:])
}

func toTime(us int64) time.Time { return time.UnixMicro(us).UTC() }

func decodeItem(raw []byte) (*item, *backend.Doc, error) {
	var it item
	if err := json.Unmarshal(raw, &it); err != nil {
		return nil, nil, fmt.Errorf("cosmos: bad item: %w", err)
	}
	fields, err := value.UnmarshalFields(it.Data)
	if err != nil {
		return nil, nil, fmt.Errorf("cosmos: document %s: %w", it.Name, err)
	}
	return &it, &backend.Doc{
		Name:       it.Name,
		Fields:     fields,
		CreateTime: toTime(it.CreateUS),
		UpdateTime: toTime(it.UpdateUS),
	}, nil
}

// current is a document as read for a commit, with the etag that guards it.
type current struct {
	doc  *backend.Doc
	raw  []byte
	etag azcore.ETag
}

func (s *Store) read(ctx context.Context, name string) (*current, error) {
	resp, err := s.container.ReadItem(ctx, s.pk, itemID(name), nil)
	if err != nil {
		if isStatus(err, http.StatusNotFound) {
			return nil, nil
		}
		return nil, fmt.Errorf("cosmos: read %s: %w", name, err)
	}
	_, doc, err := decodeItem(resp.Value)
	if err != nil {
		return nil, err
	}
	return &current{doc: doc, raw: resp.Value, etag: resp.ETag}, nil
}

// GetDocuments fetches the named documents; missing names are absent.
func (s *Store) GetDocuments(ctx context.Context, names []string) (map[string]*backend.Doc, error) {
	out := make(map[string]*backend.Doc, len(names))
	for _, name := range names {
		if _, seen := out[name]; seen {
			continue
		}
		cur, err := s.read(ctx, name)
		if err != nil {
			return nil, err
		}
		if cur != nil {
			out[name] = cur.doc
		}
	}
	return out, nil
}

// Commit applies writes atomically, retrying when it loses an optimistic race.
func (s *Store) Commit(ctx context.Context, ws []*pb.Write) ([]*pb.WriteResult, time.Time, error) {
	for attempt := 1; ; attempt++ {
		results, at, err := s.tryCommit(ctx, ws, nil)
		if !errors.Is(err, errConflict) {
			return results, at, err
		}
		if attempt == commitAttempts {
			return nil, time.Time{}, status.Error(codes.Aborted, "commit contention: too many concurrent writers")
		}
	}
}

// BeginTxn starts an optimistic transaction.
func (s *Store) BeginTxn() []byte { return s.txns.Begin() }

// RecordTxnReads notes the versions observed by transactional reads.
func (s *Store) RecordTxnReads(id []byte, reads map[string]time.Time) error {
	return s.txns.Record(id, reads)
}

// RollbackTxn discards a transaction.
func (s *Store) RollbackTxn(id []byte) { s.txns.Drop(id) }

// CommitTxn verifies the transaction's reads and applies its writes in one
// batch. Any change since the reads returns ABORTED so the SDK retries.
func (s *Store) CommitTxn(ctx context.Context, id []byte, ws []*pb.Write) ([]*pb.WriteResult, time.Time, error) {
	reads, err := s.txns.Take(id)
	if err != nil {
		return nil, time.Time{}, err
	}
	results, at, err := s.tryCommit(ctx, ws, reads)
	if errors.Is(err, errConflict) {
		return nil, time.Time{}, status.Error(codes.Aborted, "transaction contention")
	}
	return results, at, err
}

var errConflict = errors.New("cosmos: optimistic conflict")

func (s *Store) tryCommit(ctx context.Context, ws []*pb.Write, verify map[string]time.Time) ([]*pb.WriteResult, time.Time, error) {
	commitTime := time.Now().UTC().Truncate(time.Microsecond)

	var targets []string
	paths := map[string]backend.DocPath{}
	for _, w := range ws {
		name, err := writes.TargetName(w)
		if err != nil {
			return nil, time.Time{}, err
		}
		if _, seen := paths[name]; !seen {
			p, err := backend.ParseDocumentName(name)
			if err != nil {
				return nil, time.Time{}, err
			}
			paths[name] = p
			targets = append(targets, name)
		}
	}

	// Read every target and every transactionally read document once.
	seen := map[string]*current{}
	readNames := append([]string(nil), targets...)
	for name := range verify {
		if _, isTarget := paths[name]; !isTarget {
			readNames = append(readNames, name)
		}
	}
	sort.Strings(readNames)
	for _, name := range readNames {
		cur, err := s.read(ctx, name)
		if err != nil {
			return nil, time.Time{}, err
		}
		seen[name] = cur
	}

	for name, want := range verify {
		var got time.Time
		if cur := seen[name]; cur != nil {
			got = cur.doc.UpdateTime
		}
		if !got.Equal(want) {
			return nil, time.Time{}, errConflict
		}
	}

	states := map[string]*writes.DocState{}
	for _, name := range targets {
		if cur := seen[name]; cur != nil {
			states[name] = &writes.DocState{
				Name: name, Exists: true, Fields: cur.doc.Fields,
				CreateTime: cur.doc.CreateTime, UpdateTime: cur.doc.UpdateTime,
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

	batch := s.container.NewTransactionalBatch(s.pk)
	ops := 0
	for _, name := range targets {
		st := states[name]
		if !st.Dirty {
			continue
		}
		cur := seen[name]
		if st.Exists {
			body, err := s.encode(paths[name], st)
			if err != nil {
				return nil, time.Time{}, err
			}
			if cur != nil {
				etag := cur.etag
				batch.ReplaceItem(itemID(name), body, &azcosmos.TransactionalBatchItemOptions{IfMatchETag: &etag})
			} else {
				batch.CreateItem(body, nil)
			}
			ops++
			continue
		}
		if cur != nil {
			etag := cur.etag
			batch.DeleteItem(itemID(name), &azcosmos.TransactionalBatchItemOptions{IfMatchETag: &etag})
			ops++
		} else {
			// Deleting a document we saw as absent: assert it is still absent.
			ops += s.guardAbsent(&batch, name)
		}
	}
	// Documents the transaction read but does not write must be unchanged at
	// commit: rewrite them as-is under their etag, or assert they are still
	// absent. Either fails the batch if something changed meanwhile.
	for name := range verify {
		if _, isTarget := paths[name]; isTarget {
			continue
		}
		if cur := seen[name]; cur != nil {
			etag := cur.etag
			batch.ReplaceItem(itemID(name), stripSystem(cur.raw), &azcosmos.TransactionalBatchItemOptions{IfMatchETag: &etag})
			ops++
		} else {
			ops += s.guardAbsent(&batch, name)
		}
	}

	if ops == 0 {
		return results, commitTime, nil
	}
	if ops > maxBatchOps {
		return nil, time.Time{}, status.Errorf(codes.InvalidArgument,
			"commit needs %d Cosmos operations; the limit is %d", ops, maxBatchOps)
	}
	resp, err := s.container.ExecuteTransactionalBatch(ctx, batch, nil)
	if err != nil {
		return nil, time.Time{}, fmt.Errorf("cosmos: batch: %w", err)
	}
	if !resp.Success {
		for _, r := range resp.OperationResults {
			switch r.StatusCode {
			case http.StatusFailedDependency, http.StatusOK, http.StatusCreated, http.StatusNoContent:
				continue
			case http.StatusPreconditionFailed, http.StatusConflict, http.StatusNotFound:
				return nil, time.Time{}, errConflict
			default:
				return nil, time.Time{}, fmt.Errorf("cosmos: batch operation failed with status %d", r.StatusCode)
			}
		}
		return nil, time.Time{}, errConflict
	}
	return results, commitTime, nil
}

// guardAbsent adds operations that fail the batch if name exists: create a
// placeholder (409 if the document appeared) and delete it again.
func (s *Store) guardAbsent(batch *azcosmos.TransactionalBatch, name string) int {
	body, _ := json.Marshal(item{ID: itemID(name), CustomerID: s.customer, Kind: kindGuard})
	batch.CreateItem(body, nil)
	batch.DeleteItem(itemID(name), nil)
	return 2
}

func (s *Store) encode(p backend.DocPath, st *writes.DocState) ([]byte, error) {
	data, err := value.MarshalFields(st.Fields)
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "document %s: %v", p.Name, err)
	}
	return json.Marshal(item{
		ID:           itemID(p.Name),
		CustomerID:   s.customer,
		Kind:         kindDoc,
		Name:         p.Name,
		ParentPath:   p.ParentPath,
		CollectionID: p.CollectionID,
		DocID:        p.DocID,
		Data:         data,
		CreateUS:     st.CreateTime.UnixMicro(),
		UpdateUS:     st.UpdateTime.UnixMicro(),
	})
}

// stripSystem removes Cosmos system properties from a read item so it can be
// written back unchanged.
func stripSystem(raw []byte) []byte {
	var m map[string]json.RawMessage
	if err := json.Unmarshal(raw, &m); err != nil {
		return raw
	}
	for _, k := range []string{"_rid", "_self", "_etag", "_attachments", "_ts"} {
		delete(m, k)
	}
	out, err := json.Marshal(m)
	if err != nil {
		return raw
	}
	return out
}

// RunQuery fetches the candidate documents of the query's collection (or
// collection group) in this partition and applies Firestore semantics in Go.
func (s *Store) RunQuery(ctx context.Context, q *query.Query, yield func(*backend.Doc) error) error {
	sql := `SELECT * FROM c WHERE c.kind = "doc" AND c.parent_path = @parent AND c.collection_id = @coll`
	params := []azcosmos.QueryParameter{{Name: "@parent", Value: q.Parent}, {Name: "@coll", Value: q.CollectionID}}
	if q.AllDescendants {
		sql = `SELECT * FROM c WHERE c.kind = "doc" AND c.collection_id = @coll AND STARTSWITH(c.name, @prefix)`
		params = []azcosmos.QueryParameter{{Name: "@coll", Value: q.CollectionID}, {Name: "@prefix", Value: q.Parent + "/"}}
	}
	var docs []*backend.Doc
	pager := s.container.NewQueryItemsPager(sql, s.pk, &azcosmos.QueryOptions{QueryParameters: params})
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return fmt.Errorf("cosmos: query: %w", err)
		}
		for _, raw := range page.Items {
			_, doc, err := decodeItem(raw)
			if err != nil {
				return err
			}
			docs = append(docs, doc)
		}
	}
	return backend.Evaluate(q, docs, yield)
}

// RunCount counts the query's matches, honoring limit and upTo.
func (s *Store) RunCount(ctx context.Context, q *query.Query, upTo int64) (int64, error) {
	bounded := *q
	if upTo > 0 && (bounded.Limit < 0 || upTo < int64(bounded.Limit)) {
		bounded.Limit = int32(upTo)
	}
	var n int64
	err := s.RunQuery(ctx, &bounded, func(*backend.Doc) error {
		n++
		return nil
	})
	return n, err
}

// ListCollectionIDs lists the collections that hold documents directly under
// parent, sorted.
func (s *Store) ListCollectionIDs(ctx context.Context, parent string) ([]string, error) {
	sql := `SELECT c.collection_id FROM c WHERE c.kind = "doc" AND c.parent_path = @parent`
	pager := s.container.NewQueryItemsPager(sql, s.pk, &azcosmos.QueryOptions{
		QueryParameters: []azcosmos.QueryParameter{{Name: "@parent", Value: parent}},
	})
	set := map[string]bool{}
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("cosmos: list collections: %w", err)
		}
		for _, raw := range page.Items {
			var row struct {
				CollectionID string `json:"collection_id"`
			}
			if err := json.Unmarshal(raw, &row); err != nil {
				return nil, fmt.Errorf("cosmos: list collections: %w", err)
			}
			set[row.CollectionID] = true
		}
	}
	ids := make([]string, 0, len(set))
	for id := range set {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	return ids, nil
}

func isStatus(err error, code int) bool {
	var re *azcore.ResponseError
	return errors.As(err, &re) && re.StatusCode == code
}
