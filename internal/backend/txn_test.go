// Modified in this fork: new file.

package backend

import (
	"context"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func lockAsync(r *TxnRegistry, id []byte, names ...string) <-chan error {
	done := make(chan error, 1)
	go func() { done <- r.Lock(context.Background(), id, names) }()
	return done
}

func waiting(t *testing.T, done <-chan error) {
	t.Helper()
	select {
	case err := <-done:
		t.Fatalf("lock taken while another transaction holds it (err %v)", err)
	case <-time.After(100 * time.Millisecond):
	}
}

func granted(t *testing.T, done <-chan error) {
	t.Helper()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("lock: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("lock not granted after release")
	}
}

func TestTxnLocksWaitForCommit(t *testing.T) {
	var r TxnRegistry
	a, b := r.Begin(), r.Begin()
	if err := r.Lock(context.Background(), a, []string{"d1"}); err != nil {
		t.Fatal(err)
	}
	// Re-reading a document it holds does not block a transaction.
	if err := r.Lock(context.Background(), a, []string{"d1", "d2"}); err != nil {
		t.Fatal(err)
	}
	done := lockAsync(&r, b, "d1")
	waiting(t, done)
	_, release, err := r.Take(a)
	if err != nil {
		t.Fatal(err)
	}
	waiting(t, done) // held until the commit is applied
	release()
	granted(t, done)
}

func TestTxnLocksFreedByRollback(t *testing.T) {
	var r TxnRegistry
	a, b := r.Begin(), r.Begin()
	_ = r.Lock(context.Background(), a, []string{"d1"})
	done := lockAsync(&r, b, "d1")
	waiting(t, done)
	r.Drop(a)
	granted(t, done)
}

func TestTxnLockWaitTimesOut(t *testing.T) {
	defer func(w time.Duration) { lockWait = w }(lockWait)
	lockWait = 150 * time.Millisecond
	var r TxnRegistry
	a, b := r.Begin(), r.Begin()
	_ = r.Lock(context.Background(), a, []string{"d1"})
	err := r.Lock(context.Background(), b, []string{"d1"})
	if status.Code(err) != codes.Aborted {
		t.Fatalf("want ABORTED (the SDK retries), got %v", err)
	}
}

func TestTxnAbandonedLockExpires(t *testing.T) {
	defer func(ttl time.Duration) { lockTTL = ttl }(lockTTL)
	lockTTL = 300 * time.Millisecond
	var r TxnRegistry
	a, b := r.Begin(), r.Begin()
	_ = r.Lock(context.Background(), a, []string{"d1"}) // a never finishes
	// b, already waiting, takes the lock once a's expires.
	done := lockAsync(&r, b, "d1")
	waiting(t, done)
	granted(t, done)
	// a's late release must not free b's lock.
	_, release, _ := r.Take(a)
	release()
	c := r.Begin()
	next := lockAsync(&r, c, "d1")
	waiting(t, next)
	r.Drop(b)
	granted(t, next)
}

func TestTxnLockUnknownTransaction(t *testing.T) {
	var r TxnRegistry
	if err := r.Lock(context.Background(), []byte("nope"), []string{"d1"}); status.Code(err) != codes.InvalidArgument {
		t.Fatalf("got %v", err)
	}
}
