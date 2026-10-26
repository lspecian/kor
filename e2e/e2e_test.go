// Package e2e proves the wire swap: the unmodified official Go Firestore SDK
// (cloud.google.com/go/firestore) talking to kord via FIRESTORE_EMULATOR_HOST.
//
// Modified in this fork: the server under test comes from openBackend.
package e2e

import (
	"context"
	"net"
	"testing"
	"time"

	"cloud.google.com/go/firestore"
	"google.golang.org/genproto/googleapis/type/latlng"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/omelas-tech/kor/internal/pgtest"
	"github.com/omelas-tech/kor/internal/rpc"
)

func TestMain(m *testing.M) { pgtest.Main(m) }

// startKord runs the full server on a random port and points the Firestore
// SDK at it.
func startKord(t *testing.T) {
	t.Helper()
	st := openBackend(t)

	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	g := grpc.NewServer()
	rpc.New(st).Register(g)
	go func() { _ = g.Serve(lis) }()
	t.Cleanup(g.Stop)

	t.Setenv("FIRESTORE_EMULATOR_HOST", lis.Addr().String())
}

func newClient(t *testing.T) *firestore.Client {
	t.Helper()
	client, err := firestore.NewClient(context.Background(), "kor-e2e")
	if err != nil {
		t.Fatalf("firestore.NewClient: %v", err)
	}
	t.Cleanup(func() { client.Close() })
	return client
}

func TestSDKRoundTrip(t *testing.T) {
	startKord(t)
	client := newClient(t)
	ctx := context.Background()

	doc := client.Collection("users").Doc("alice")
	when := time.Date(2026, 8, 9, 12, 30, 45, 123456000, time.UTC)
	payload := map[string]any{
		"string": "hello",
		"int":    int64(9007199254740993), // 2^53+1: JSON-unsafe, must survive
		"double": 2.5,
		"negZeroDouble": func() float64 {
			z := 0.0
			return -z
		}(),
		"bool":  true,
		"null":  nil,
		"time":  when,
		"bytes": []byte{0x00, 0x01, 0xFF},
		"geo":   &latlng.LatLng{Latitude: 52.37, Longitude: 4.89},
		"ref":   client.Collection("artworks").Doc("mona-lisa"),
		"array": []any{"a", int64(1), false},
		"nested": map[string]any{
			"deep": map[string]any{"x": "y"},
		},
	}
	if _, err := doc.Set(ctx, payload); err != nil {
		t.Fatalf("Set: %v", err)
	}

	snap, err := doc.Get(ctx)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	data := snap.Data()

	if data["string"] != "hello" {
		t.Errorf("string = %v", data["string"])
	}
	if data["int"] != int64(9007199254740993) {
		t.Errorf("int64 fidelity lost: %v", data["int"])
	}
	if data["double"] != 2.5 {
		t.Errorf("double = %v", data["double"])
	}
	if data["bool"] != true || data["null"] != nil {
		t.Errorf("bool/null = %v / %v", data["bool"], data["null"])
	}
	if got := data["time"].(time.Time); !got.Equal(when) {
		t.Errorf("time = %v, want %v", got, when)
	}
	if got := data["bytes"].([]byte); len(got) != 3 || got[0] != 0 || got[2] != 0xFF {
		t.Errorf("bytes = %v", got)
	}
	if got := data["geo"].(*latlng.LatLng); got.Latitude != 52.37 || got.Longitude != 4.89 {
		t.Errorf("geo = %v", got)
	}
	if got := data["ref"].(*firestore.DocumentRef); got.Path != client.Collection("artworks").Doc("mona-lisa").Path {
		t.Errorf("ref = %v", got.Path)
	}
	arr := data["array"].([]any)
	if len(arr) != 3 || arr[0] != "a" || arr[1] != int64(1) || arr[2] != false {
		t.Errorf("array = %v", arr)
	}
	nested := data["nested"].(map[string]any)["deep"].(map[string]any)
	if nested["x"] != "y" {
		t.Errorf("nested = %v", data["nested"])
	}
	if !snap.CreateTime.Equal(snap.UpdateTime) {
		t.Errorf("fresh doc create/update mismatch: %v vs %v", snap.CreateTime, snap.UpdateTime)
	}
}

func TestSDKServerTimestampAndIncrement(t *testing.T) {
	startKord(t)
	client := newClient(t)
	ctx := context.Background()

	doc := client.Collection("counters").Doc("c1")
	before := time.Now().Add(-2 * time.Second)
	if _, err := doc.Set(ctx, map[string]any{
		"count":     int64(10),
		"updatedAt": firestore.ServerTimestamp,
	}); err != nil {
		t.Fatalf("Set with ServerTimestamp: %v", err)
	}
	snap, err := doc.Get(ctx)
	if err != nil {
		t.Fatal(err)
	}
	ts, ok := snap.Data()["updatedAt"].(time.Time)
	if !ok || ts.Before(before) || ts.After(time.Now().Add(2*time.Second)) {
		t.Errorf("serverTimestamp = %v (ok=%v)", ts, ok)
	}

	if _, err := doc.Update(ctx, []firestore.Update{
		{Path: "count", Value: firestore.Increment(5)},
	}); err != nil {
		t.Fatalf("Update+Increment: %v", err)
	}
	snap, _ = doc.Get(ctx)
	if got := snap.Data()["count"]; got != int64(15) {
		t.Errorf("count after increment = %v, want 15", got)
	}

	// Update on a missing document must surface NotFound (the SDK sends an
	// exists precondition).
	missing := client.Collection("counters").Doc("nope")
	_, err = missing.Update(ctx, []firestore.Update{{Path: "x", Value: 1}})
	if status.Code(err) != codes.NotFound {
		t.Errorf("Update on missing doc: want NotFound, got %v", err)
	}
}

func TestSDKArrayOpsAndMerge(t *testing.T) {
	startKord(t)
	client := newClient(t)
	ctx := context.Background()

	doc := client.Collection("lists").Doc("l1")
	if _, err := doc.Set(ctx, map[string]any{"tags": []any{"a"}, "keep": "me"}); err != nil {
		t.Fatal(err)
	}
	if _, err := doc.Set(ctx, map[string]any{
		"tags": firestore.ArrayUnion("b", "a", "c"),
	}, firestore.MergeAll); err != nil {
		t.Fatalf("MergeAll+ArrayUnion: %v", err)
	}
	snap, _ := doc.Get(ctx)
	tags := snap.Data()["tags"].([]any)
	if len(tags) != 3 || tags[0] != "a" || tags[1] != "b" || tags[2] != "c" {
		t.Errorf("tags = %v", tags)
	}
	if snap.Data()["keep"] != "me" {
		t.Errorf("MergeAll clobbered sibling field: %v", snap.Data())
	}

	if _, err := doc.Update(ctx, []firestore.Update{
		{Path: "tags", Value: firestore.ArrayRemove("a", "c")},
	}); err != nil {
		t.Fatal(err)
	}
	snap, _ = doc.Get(ctx)
	tags = snap.Data()["tags"].([]any)
	if len(tags) != 1 || tags[0] != "b" {
		t.Errorf("tags after remove = %v", tags)
	}
}

func TestSDKBatchAndGetAll(t *testing.T) {
	startKord(t)
	client := newClient(t)
	ctx := context.Background()

	batch := client.Batch()
	refs := make([]*firestore.DocumentRef, 3)
	for i, id := range []string{"a", "b", "c"} {
		refs[i] = client.Collection("batch").Doc(id)
		batch.Set(refs[i], map[string]any{"n": int64(i)})
	}
	if _, err := batch.Commit(ctx); err != nil {
		t.Fatalf("batch commit: %v", err)
	}

	// Interleave a missing doc; GetAll must report it as non-existent.
	all := append(refs[:2:2], client.Collection("batch").Doc("missing"), refs[2])
	snaps, err := client.GetAll(ctx, all)
	if err != nil {
		t.Fatalf("GetAll: %v", err)
	}
	if len(snaps) != 4 {
		t.Fatalf("GetAll returned %d snaps", len(snaps))
	}
	if !snaps[0].Exists() || !snaps[1].Exists() || snaps[2].Exists() || !snaps[3].Exists() {
		t.Errorf("existence pattern wrong: %v %v %v %v",
			snaps[0].Exists(), snaps[1].Exists(), snaps[2].Exists(), snaps[3].Exists())
	}
	if got := snaps[3].Data()["n"]; got != int64(2) {
		t.Errorf("snaps[3].n = %v", got)
	}

	// Delete + verify.
	if _, err := refs[0].Delete(ctx); err != nil {
		t.Fatal(err)
	}
	snap, err := refs[0].Get(ctx)
	if status.Code(err) != codes.NotFound {
		t.Errorf("Get after delete: want NotFound, got err=%v exists=%v", err, snap.Exists())
	}
}
