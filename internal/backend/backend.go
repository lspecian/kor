// Package backend defines the storage contract the Firestore RPC layer serves
// from. Each storage engine (PostgreSQL today; Cosmos DB and others next)
// implements Backend; the wire protocol, value encoding and query semantics
// stay in the engine-independent packages.
//
// Modified in this fork: this package is new.
package backend

import (
	"context"
	"time"

	pb "cloud.google.com/go/firestore/apiv1/firestorepb"

	"github.com/omelas-tech/kor/internal/query"
)

// Doc is one stored document, addressed by its full Firestore resource name.
type Doc struct {
	Name       string
	Fields     map[string]*pb.Value
	CreateTime time.Time
	UpdateTime time.Time
}

// Backend is everything the RPC layer needs from a storage engine.
type Backend interface {
	// GetDocuments returns the documents that exist, keyed by name. Missing
	// names are absent from the map.
	GetDocuments(ctx context.Context, names []string) (map[string]*Doc, error)

	// Commit applies writes atomically and returns one result per write plus
	// the commit time.
	Commit(ctx context.Context, ws []*pb.Write) ([]*pb.WriteResult, time.Time, error)

	// BeginTxn starts a transaction and returns its id.
	BeginTxn() []byte
	// LockTxnReads takes the read locks of documents a transaction is about
	// to read, waiting while other transactions hold them (codes.Aborted
	// after a bounded wait).
	LockTxnReads(ctx context.Context, id []byte, names []string) error
	// RecordTxnReads remembers the update times a transaction observed, so
	// CommitTxn can reject the commit if any of them changed.
	RecordTxnReads(id []byte, reads map[string]time.Time) error
	// RollbackTxn forgets a transaction.
	RollbackTxn(id []byte)
	// CommitTxn verifies the transaction's reads and applies its writes
	// atomically; a changed read fails with codes.Aborted so SDKs retry.
	CommitTxn(ctx context.Context, id []byte, ws []*pb.Write) ([]*pb.WriteResult, time.Time, error)

	// RunQuery streams the documents matching q, in query order.
	RunQuery(ctx context.Context, q *query.Query, yield func(*Doc) error) error
	// RunCount counts the documents matching q, stopping at upTo when upTo > 0.
	RunCount(ctx context.Context, q *query.Query, upTo int64) (int64, error)

	// ListCollectionIDs lists the collection ids directly under parent, sorted.
	ListCollectionIDs(ctx context.Context, parent string) ([]string, error)
}
