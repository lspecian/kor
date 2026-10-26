// Modified in this fork: the server under test comes from openBackend.

package e2e

import (
	"context"
	"net"
	"testing"

	"cloud.google.com/go/firestore"
	"google.golang.org/api/option"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	"github.com/omelas-tech/kor/internal/rpc"
)

// TestSDKDialWithoutEmulatorEnv proves the pattern a host application uses to
// run a Kor-backed client NEXT TO its real Firestore client in one process:
// an explicit insecure gRPC connection via option.WithGRPCConn, with
// FIRESTORE_EMULATOR_HOST deliberately unset.
func TestSDKDialWithoutEmulatorEnv(t *testing.T) {
	ctx := context.Background()
	st := openBackend(t)

	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	g := grpc.NewServer()
	rpc.New(st).Register(g)
	go func() { _ = g.Serve(lis) }()
	t.Cleanup(g.Stop)

	// Explicitly NOT setting FIRESTORE_EMULATOR_HOST.
	t.Setenv("FIRESTORE_EMULATOR_HOST", "")

	conn, err := grpc.NewClient(lis.Addr().String(), grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatal(err)
	}
	client, err := firestore.NewClient(ctx, "demo-kor", option.WithGRPCConn(conn))
	if err != nil {
		t.Fatalf("NewClient(WithGRPCConn): %v", err)
	}
	t.Cleanup(func() { client.Close() })

	doc := client.Collection("ai_content").Doc("description_artwork_test_en")
	if _, err := doc.Set(ctx, map[string]any{"content": "hello from kor", "model": "test-1"}); err != nil {
		t.Fatalf("Set over custom conn: %v", err)
	}
	snap, err := doc.Get(ctx)
	if err != nil {
		t.Fatalf("Get over custom conn: %v", err)
	}
	if snap.Data()["content"] != "hello from kor" {
		t.Errorf("content = %v", snap.Data()["content"])
	}
}
