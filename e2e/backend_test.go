// Modified in this fork: new file.

package e2e

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"os"
	"testing"

	"github.com/omelas-tech/kor/internal/backend"
	"github.com/omelas-tech/kor/internal/cosmos"
	"github.com/omelas-tech/kor/internal/pgtest"
	"github.com/omelas-tech/kor/internal/store"
)

// openBackend returns the storage backend the e2e suite runs against:
// PostgreSQL by default, or Cosmos DB when KOR_E2E_BACKEND=cosmos (with
// KOR_E2E_COSMOS_ENDPOINT and KOR_E2E_COSMOS_KEY). Each Cosmos test gets its
// own customer partition, so tests never see each other's documents.
func openBackend(t *testing.T) backend.Backend {
	t.Helper()
	ctx := context.Background()
	if os.Getenv("KOR_E2E_BACKEND") == "cosmos" {
		suffix := make([]byte, 6)
		_, _ = rand.Read(suffix)
		cs, err := cosmos.Open(ctx, cosmos.Config{
			Endpoint:        os.Getenv("KOR_E2E_COSMOS_ENDPOINT"),
			Key:             os.Getenv("KOR_E2E_COSMOS_KEY"),
			Database:        "kor-e2e",
			Container:       "documents",
			CustomerID:      "e2e-" + hex.EncodeToString(suffix),
			CreateIfMissing: true,
		})
		if err != nil {
			t.Fatalf("open cosmos backend: %v", err)
		}
		t.Cleanup(cs.Close)
		return cs
	}
	st, err := store.Open(ctx, pgtest.DSN(t))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(st.Close)
	return st
}
