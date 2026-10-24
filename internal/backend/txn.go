// Modified in this fork: moved here from package store so every backend shares it.

package backend

import (
	"crypto/rand"
	"sync"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// txnTTL bounds how long an abandoned transaction's read-set is kept.
const txnTTL = 5 * time.Minute

type txnEntry struct {
	reads   map[string]time.Time // doc name -> update_time at read (zero = missing)
	created time.Time
}

// TxnRegistry holds the read-sets of in-flight optimistic transactions.
// BeginTransaction allocates one; transactional reads record the update time
// they observed; the commit takes the read-set and verifies none changed.
// The zero value is ready to use.
type TxnRegistry struct {
	mu sync.Mutex
	m  map[string]*txnEntry
}

// Begin allocates a transaction and returns its opaque id.
func (r *TxnRegistry) Begin() []byte {
	id := make([]byte, 16)
	_, _ = rand.Read(id)
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.m == nil {
		r.m = map[string]*txnEntry{}
	}
	// Lazy expiry sweep; transaction counts are small (one per in-flight
	// RunTransaction), so a full walk is fine.
	now := time.Now()
	for k, e := range r.m {
		if now.Sub(e.created) > txnTTL {
			delete(r.m, k)
		}
	}
	r.m[string(id)] = &txnEntry{reads: map[string]time.Time{}, created: now}
	return id
}

// Record notes the versions a transaction's reads observed. The first read of
// a document wins: it is the version the transaction logic actually saw.
func (r *TxnRegistry) Record(id []byte, reads map[string]time.Time) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	e, ok := r.m[string(id)]
	if !ok {
		return status.Error(codes.InvalidArgument, "unknown or expired transaction")
	}
	for name, t := range reads {
		if _, seen := e.reads[name]; !seen {
			e.reads[name] = t
		}
	}
	return nil
}

// Take removes a transaction and returns its read-set for commit.
func (r *TxnRegistry) Take(id []byte) (map[string]time.Time, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	e, ok := r.m[string(id)]
	if !ok {
		return nil, status.Error(codes.InvalidArgument, "unknown or expired transaction")
	}
	delete(r.m, string(id))
	return e.reads, nil
}

// Drop discards a transaction.
func (r *TxnRegistry) Drop(id []byte) {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.m, string(id))
}
