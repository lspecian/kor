// Modified in this fork: moved here from package store so every backend shares it.

package backend

import (
	"context"
	"crypto/rand"
	"sort"
	"sync"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// txnTTL bounds how long an abandoned transaction's read-set is kept.
const txnTTL = 5 * time.Minute

// Read locks, as Firestore's server-SDK transactions take them: lockWait
// bounds how long a transaction waits for another's lock (a deadlock ends
// there, ABORTED, and the SDK retries); lockTTL frees the locks of a
// transaction that never committed or rolled back.
var (
	lockWait = 20 * time.Second
	lockTTL  = 30 * time.Second
)

type txnEntry struct {
	reads   map[string]time.Time // doc name -> update_time at read (zero = missing)
	locks   []string
	created time.Time
}

type lockHold struct {
	txn   string
	since time.Time
}

// TxnRegistry holds the read-sets of in-flight transactions. BeginTransaction
// allocates one; transactional reads lock their documents (Lock) and record
// the update time they observed; the commit takes the read-set, verifies none
// changed, and releases the locks once its writes are applied.
//
// Locks are per process: they make contended transactions on one server wait
// their turn instead of aborting each other, as Firestore's do. Across
// servers the version check still keeps commits exact. The zero value is
// ready to use.
type TxnRegistry struct {
	mu       sync.Mutex
	m        map[string]*txnEntry
	owners   map[string]lockHold      // doc name -> holder
	released map[string]chan struct{} // doc name -> closed when its lock frees
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
			r.unlock(k, e)
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

// Lock takes the read locks of documents a transaction is about to read,
// waiting while other transactions hold them. Call it before the read, so
// the version the transaction sees is the one it commits against.
func (r *TxnRegistry) Lock(ctx context.Context, id []byte, names []string) error {
	sorted := append([]string(nil), names...)
	sort.Strings(sorted) // one order for every transaction makes deadlocks rarer
	deadline := time.Now().Add(lockWait)
	for _, name := range sorted {
		for {
			r.mu.Lock()
			e, ok := r.m[string(id)]
			if !ok {
				r.mu.Unlock()
				return status.Error(codes.InvalidArgument, "unknown or expired transaction")
			}
			if r.owners == nil {
				r.owners = map[string]lockHold{}
				r.released = map[string]chan struct{}{}
			}
			hold, held := r.owners[name]
			if !held || hold.txn == string(id) || time.Since(hold.since) > lockTTL {
				if !held || hold.txn != string(id) {
					r.owners[name] = lockHold{txn: string(id), since: time.Now()}
					e.locks = append(e.locks, name)
				}
				r.mu.Unlock()
				break
			}
			ch := r.released[name]
			if ch == nil {
				ch = make(chan struct{})
				r.released[name] = ch
			}
			r.mu.Unlock()
			// Wake when the lock frees, when an abandoned holder's lock
			// expires, or at the deadline.
			wake := deadline
			if expiry := hold.since.Add(lockTTL); expiry.Before(wake) {
				wake = expiry
			}
			wait := time.NewTimer(time.Until(wake))
			select {
			case <-ch:
				wait.Stop()
			case <-ctx.Done():
				wait.Stop()
				return ctx.Err()
			case <-wait.C:
				if !time.Now().Before(deadline) {
					return status.Error(codes.Aborted, "transaction contention: lock wait timed out")
				}
			}
		}
	}
	return nil
}

// unlock frees the locks e still holds. r.mu must be held.
func (r *TxnRegistry) unlock(id string, e *txnEntry) {
	for _, name := range e.locks {
		if hold, ok := r.owners[name]; ok && hold.txn == id {
			delete(r.owners, name)
			if ch := r.released[name]; ch != nil {
				close(ch)
				delete(r.released, name)
			}
		}
	}
	e.locks = nil
}

// Take removes a transaction and returns its read-set for commit, and a
// release that frees its locks: call it once the commit is applied or failed.
func (r *TxnRegistry) Take(id []byte) (map[string]time.Time, func(), error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	e, ok := r.m[string(id)]
	if !ok {
		return nil, func() {}, status.Error(codes.InvalidArgument, "unknown or expired transaction")
	}
	delete(r.m, string(id))
	release := func() {
		r.mu.Lock()
		defer r.mu.Unlock()
		r.unlock(string(id), e)
	}
	return e.reads, release, nil
}

// Drop discards a transaction and frees its locks.
func (r *TxnRegistry) Drop(id []byte) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if e, ok := r.m[string(id)]; ok {
		r.unlock(string(id), e)
	}
	delete(r.m, string(id))
}
