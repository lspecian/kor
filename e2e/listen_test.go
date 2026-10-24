// Modified in this fork: new file.

package e2e

import (
	"context"
	"testing"
	"time"

	"cloud.google.com/go/firestore"
)

// listenTimeout bounds each wait for a snapshot, so a missing update fails the
// test instead of hanging it.
const listenTimeout = 20 * time.Second

func nextIDs(t *testing.T, it *firestore.QuerySnapshotIterator) []string {
	t.Helper()
	snap, err := it.Next()
	if err != nil {
		t.Fatalf("query snapshot: %v", err)
	}
	docs, err := snap.Documents.GetAll()
	if err != nil {
		t.Fatalf("snapshot documents: %v", err)
	}
	ids := make([]string, len(docs))
	for i, d := range docs {
		ids[i] = d.Ref.ID
	}
	return ids
}

func wantIDs(t *testing.T, step string, got []string, want ...string) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("%s: got %v, want %v", step, got, want)
	}
	for i := range got {
		if got[i] != want[i] {
			t.Fatalf("%s: got %v, want %v", step, got, want)
		}
	}
}

func TestSDKListenQuery(t *testing.T) {
	startKord(t)
	client := newClient(t)
	ctx, cancel := context.WithTimeout(context.Background(), listenTimeout)
	defer cancel()
	rooms := client.Collection("rooms")
	mustSet(t, ctx, rooms.Doc("a"), map[string]any{"n": 1})
	mustSet(t, ctx, rooms.Doc("b"), map[string]any{"n": 2})

	it := rooms.Where("n", ">", 0).OrderBy("n", firestore.Asc).Snapshots(ctx)
	defer it.Stop()
	wantIDs(t, "initial", nextIDs(t, it), "a", "b")

	mustSet(t, ctx, rooms.Doc("c"), map[string]any{"n": 3})
	wantIDs(t, "added", nextIDs(t, it), "a", "b", "c")

	mustSet(t, ctx, rooms.Doc("a"), map[string]any{"n": 5})
	wantIDs(t, "reordered", nextIDs(t, it), "b", "c", "a")

	mustSet(t, ctx, rooms.Doc("b"), map[string]any{"n": -1})
	wantIDs(t, "left the query", nextIDs(t, it), "c", "a")

	if _, err := rooms.Doc("c").Delete(ctx); err != nil {
		t.Fatal(err)
	}
	wantIDs(t, "deleted", nextIDs(t, it), "a")
}

func TestSDKListenLimitWindow(t *testing.T) {
	startKord(t)
	client := newClient(t)
	ctx, cancel := context.WithTimeout(context.Background(), listenTimeout)
	defer cancel()
	tasks := client.Collection("tasks")
	for id, n := range map[string]int{"t1": 1, "t2": 2, "t3": 3} {
		mustSet(t, ctx, tasks.Doc(id), map[string]any{"n": n})
	}

	it := tasks.OrderBy("n", firestore.Asc).Limit(2).Snapshots(ctx)
	defer it.Stop()
	wantIDs(t, "initial window", nextIDs(t, it), "t1", "t2")

	if _, err := tasks.Doc("t1").Delete(ctx); err != nil {
		t.Fatal(err)
	}
	wantIDs(t, "t3 enters the window", nextIDs(t, it), "t2", "t3")
}

func TestSDKListenDocument(t *testing.T) {
	startKord(t)
	client := newClient(t)
	ctx, cancel := context.WithTimeout(context.Background(), listenTimeout)
	defer cancel()
	ref := client.Collection("profiles").Doc("p1")

	it := ref.Snapshots(ctx)
	defer it.Stop()
	next := func(step string) *firestore.DocumentSnapshot {
		t.Helper()
		snap, err := it.Next()
		if err != nil && snap == nil {
			t.Fatalf("%s: %v", step, err)
		}
		return snap
	}

	if next("initial").Exists() {
		t.Fatal("initial: document should not exist yet")
	}
	mustSet(t, ctx, ref, map[string]any{"name": "Ada"})
	if snap := next("created"); !snap.Exists() || snap.Data()["name"] != "Ada" {
		t.Fatalf("created: got exists=%v data=%v", snap.Exists(), snap.Data())
	}
	mustSet(t, ctx, ref, map[string]any{"name": "Grace"})
	if snap := next("updated"); snap.Data()["name"] != "Grace" {
		t.Fatalf("updated: got %v", snap.Data())
	}
	if _, err := ref.Delete(ctx); err != nil {
		t.Fatal(err)
	}
	if next("deleted").Exists() {
		t.Fatal("deleted: document should be gone")
	}
}

func TestSDKListenIsolatesCollections(t *testing.T) {
	startKord(t)
	client := newClient(t)
	ctx, cancel := context.WithTimeout(context.Background(), listenTimeout)
	defer cancel()

	red := client.Collection("red").Snapshots(ctx)
	defer red.Stop()
	blue := client.Collection("blue").Snapshots(ctx)
	defer blue.Stop()
	wantIDs(t, "red initial", nextIDs(t, red))
	wantIDs(t, "blue initial", nextIDs(t, blue))

	mustSet(t, ctx, client.Collection("blue").Doc("b1"), map[string]any{"v": 1})
	wantIDs(t, "blue sees its write", nextIDs(t, blue), "b1")
	mustSet(t, ctx, client.Collection("red").Doc("r1"), map[string]any{"v": 1})
	wantIDs(t, "red sees only red", nextIDs(t, red), "r1")
}

func mustSet(t *testing.T, ctx context.Context, ref *firestore.DocumentRef, data map[string]any) {
	t.Helper()
	if _, err := ref.Set(ctx, data); err != nil {
		t.Fatalf("set %s: %v", ref.Path, err)
	}
}
