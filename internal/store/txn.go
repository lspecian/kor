// Modified in this fork: the transaction registry moved to package backend.

package store

import (
	"context"
	"time"

	pb "cloud.google.com/go/firestore/apiv1/firestorepb"
)

// Transactions follow the design's "no held Postgres snapshots" model:
// BeginTransaction allocates a server-side read-set; transactional reads are
// served at latest-committed state while recording (doc, update_time); Commit
// re-locks every read and written document with SELECT ... FOR UPDATE,
// verifies the recorded versions are unchanged, and applies the writes — or
// returns ABORTED so the SDK's RunTransaction retries. This is serializable
// for point-read transactions; queries inside transactions are rejected
// upstream until predicate validation exists.

// BeginTxn starts a transaction and returns its opaque id.
func (s *Store) BeginTxn() []byte { return s.txns.Begin() }

// RecordTxnReads notes the versions observed by transactional reads.
func (s *Store) RecordTxnReads(id []byte, reads map[string]time.Time) error {
	return s.txns.Record(id, reads)
}

// RollbackTxn discards a transaction.
func (s *Store) RollbackTxn(id []byte) { s.txns.Drop(id) }

// CommitTxn atomically verifies the transaction's reads and applies writes.
// Version drift returns ABORTED, which Firestore SDKs retry automatically.
func (s *Store) CommitTxn(ctx context.Context, id []byte, ws []*pb.Write) ([]*pb.WriteResult, time.Time, error) {
	reads, err := s.txns.Take(id)
	if err != nil {
		return nil, time.Time{}, err
	}
	extraLocks := make([]string, 0, len(reads))
	for name := range reads {
		extraLocks = append(extraLocks, name)
	}
	return s.applyCommit(ctx, ws, extraLocks, reads)
}
